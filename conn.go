package gostls

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bigbes/gostls/internal/handshake"
	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// Sentinel errors for conn.go operations.
var (
	// errConnClosed is returned by Read/Write on a closed connection.
	errConnClosed = errors.New("tls: connection closed")
	// errNoSuites is returned when no cipher suites are available for negotiation.
	errNoSuites = errors.New("tls: no cipher suites available for negotiation")
	// errAlertTruncated is returned when an alert record is too short.
	errAlertTruncated = errors.New("tls: truncated alert record")
	// errAlertReceived is wrapped with level/desc when a non-close_notify alert arrives.
	errAlertReceived = errors.New("tls: received alert")
	// errUnexpectedRecord is wrapped with the content type when an unexpected record type arrives.
	errUnexpectedRecord = errors.New("tls: unexpected record type in application data phase")
	// errNoServerName is returned when verification is enabled but no ServerName
	// is set and none could be derived from the dial address.
	errNoServerName = errors.New("tls: no ServerName and InsecureSkipVerify is false; cannot verify server identity")
)

// alertMinLen is the minimum length of a TLS alert record (level + description).
const alertMinLen = 2

// Compile-time interface check.
var _ net.Conn = (*Conn)(nil)

// Conn is a TLS 1.2 client connection implementing net.Conn.
//
// The zero value is not usable; create one with NewConn or Dialer.DialContext.
type Conn struct {
	conn   net.Conn
	config *Config
	layer  *record.Layer

	// handshakeOnce ensures the handshake runs exactly once.
	// handshakeErr holds the result after Once fires.
	handshakeOnce sync.Once
	handshakeErr  error

	// closed is set to true by Close via CAS; prevents double-close.
	closed atomic.Bool

	// inMu serialises concurrent Read callers.
	// outMu serialises concurrent Write callers.
	// They are intentionally separate so Read and Write can proceed concurrently.
	inMu  sync.Mutex
	outMu sync.Mutex

	// readBuf holds decrypted application data not yet consumed by Read.
	readBuf []byte

	// readErr is the sticky error that terminated the read side. Once set (by a
	// transport error, fatal alert, or unexpected record type) every Read
	// returns it instead of parsing the desynchronized stream. Guarded by inMu.
	readErr error

	// handshakeOK is set true once the handshake completes successfully. Close
	// consults it to decide whether to send close_notify without blocking on
	// handshakeOnce (a still-running handshake is interrupted by closing conn).
	handshakeOK atomic.Bool

	// serverNameFromDial is the host the Dialer parsed from the dial address,
	// used as the effective ServerName when Config.ServerName is empty (matching
	// crypto/tls.Dialer). Empty for connections created via NewConn.
	serverNameFromDial string
}

// NewConn creates a Conn wrapping the given net.Conn with the provided Config.
// This is the primary way to create a *Conn directly — Dialer.DialContext also
// creates one internally.
func NewConn(c net.Conn, config *Config) *Conn {
	return newConn(c, config)
}

// newConn creates a Conn wrapping the given net.Conn with the provided Config.
func newConn(c net.Conn, config *Config) *Conn {
	if config == nil {
		config = &Config{}
	}

	return &Conn{
		conn:   c,
		config: config,
		layer:  record.NewLayer(c),
	}
}

// Handshake runs the TLS 1.2 client handshake if it has not been run yet.
// It is called automatically by Read and Write if needed.
func (c *Conn) Handshake() error {
	c.handshakeOnce.Do(func() {
		if c.closed.Load() {
			c.handshakeErr = errConnClosed

			return
		}

		c.handshakeErr = c.doHandshake()
		if c.handshakeErr == nil {
			c.handshakeOK.Store(true)
		}
	})

	return c.handshakeErr
}

// Read reads decrypted application data from the connection.
// It triggers the handshake if needed.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.inMu.Lock()
	defer c.inMu.Unlock()

	if c.closed.Load() {
		return 0, errConnClosed
	}

	// Drain any buffered data first.
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)

		c.readBuf = c.readBuf[n:]

		return n, nil
	}

	// Once the record stream is desynchronized (a transport error, a fatal alert,
	// or an unexpected record type), every subsequent Read must fail with the
	// same error instead of attempting to parse the corrupted stream.
	if c.readErr != nil {
		return 0, c.readErr
	}

	// Read records until we get application data.
	for {
		ct, payload, err := c.layer.ReadRecord()
		if err != nil {
			c.readErr = err

			return 0, err
		}

		switch ct {
		case record.ContentTypeApplicationData:
			if len(payload) == 0 {
				continue
			}

			n := copy(b, payload)
			if n < len(payload) {
				// Buffer the remainder.
				c.readBuf = append(c.readBuf, payload[n:]...)
			}

			return n, nil

		case record.ContentTypeAlert:
			if len(payload) < alertMinLen {
				c.readErr = errAlertTruncated

				return 0, errAlertTruncated
			}

			level, desc := record.DecodeAlert(payload)
			if desc == record.AlertCloseNotify {
				c.readErr = io.EOF

				return 0, io.EOF
			}

			c.readErr = fmt.Errorf("tls: received alert level=%d desc=%d: %w", level, desc, errAlertReceived)

			return 0, c.readErr

		default:
			c.readErr = fmt.Errorf(
				"tls: unexpected record type %d in application data phase: %w", ct, errUnexpectedRecord,
			)

			return 0, c.readErr
		}
	}
}

// Write encrypts and sends b over the connection.
// It triggers the handshake if needed.
// Records are split into chunks of at most 16384 bytes each.
func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.outMu.Lock()
	defer c.outMu.Unlock()

	if c.closed.Load() {
		return 0, errConnClosed
	}

	const maxChunk = 1 << 14 // 16384 bytes.

	written := 0

	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}

		if err := c.layer.WriteRecord(record.ContentTypeApplicationData, chunk); err != nil {
			return written, err
		}

		written += len(chunk)

		b = b[len(chunk):]
	}

	return written, nil
}

// Close sends a close_notify alert (when the handshake completed) and closes the
// underlying connection. It never waits on an in-flight handshake: closing the
// transport unblocks a handshake currently blocked on I/O, which then returns an
// error. This is why the decision below uses the handshakeOK flag rather than
// driving handshakeOnce (which would block).
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Send close_notify only when the handshake already completed successfully:
	// the transport is then still open and a send protector is installed.
	// handshakeOK is false while a handshake is in flight — exactly when we must
	// not block trying to write an alert.
	if c.handshakeOK.Load() {
		c.outMu.Lock()

		alertBody := record.EncodeAlert(record.AlertLevelWarning, record.AlertCloseNotify)
		// Best effort: ignore write error since we're closing anyway.
		_ = c.layer.WriteRecord(record.ContentTypeAlert, alertBody)
		c.outMu.Unlock()
	}

	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// doHandshake performs the TLS 1.2 client handshake.
// It is called at most once, protected by handshakeOnce.
func (c *Conn) doHandshake() error {
	offeredSuites := c.config.CipherSuites
	if offeredSuites == nil {
		offeredSuites = handshake.AvailableSuites()
	}

	if len(offeredSuites) == 0 {
		return errNoSuites
	}

	rootCAs, err := c.config.rootCAPool()
	if err != nil {
		return err
	}

	clientCerts, err := c.config.clientCerts()
	if err != nil {
		return err
	}

	// Resolve the effective server name: Config.ServerName, else the host the
	// Dialer parsed from the dial address (crypto/tls.Dialer does the same).
	// With verification enabled an empty name would silently skip hostname
	// checking (fail open), so fail closed instead.
	serverName := c.config.ServerName
	if serverName == "" {
		serverName = c.serverNameFromDial
	}

	if serverName == "" && !c.config.InsecureSkipVerify {
		return errNoServerName
	}

	params := handshake.ClientParams{
		Rand:                  c.config.rand(),
		ServerName:            serverName,
		OfferedSuites:         offeredSuites,
		RootCAs:               rootCAs,
		GOSTRoots:             gostCertsParam(c.config.GOSTRoots),
		GOSTIntermediates:     gostCertsParam(c.config.GOSTIntermediates),
		InsecureSkipVerify:    c.config.InsecureSkipVerify,
		VerifyPeerCertificate: c.config.VerifyPeerCertificate,
		Certificates:          clientCerts,
	}

	state := handshake.NewClientState(c.layer, params)

	return state.Handshake()
}

// ConnectionState holds information about a TLS connection.
type ConnectionState struct {
	// Version is the TLS version used; always 0x0303 (TLS 1.2).
	Version uint16
	// CipherSuite is the IANA cipher suite ID negotiated.
	CipherSuite uint16
	// Suite is the full suite descriptor, or nil before handshake.
	Suite *suites.Suite
}
