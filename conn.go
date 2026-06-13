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
)

// alertMinLen is the minimum length of a TLS alert record (level + description).
const alertMinLen = 2

// Compile-time interface check.
var _ net.Conn = (*Conn)(nil)

// Conn is a TLS 1.2 client connection implementing net.Conn.
//
// The zero value is not usable; create with newConn.
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
		c.handshakeErr = c.doHandshake()
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

	// Read records until we get application data.
	for {
		ct, payload, err := c.layer.ReadRecord()
		if err != nil {
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
				return 0, errAlertTruncated
			}

			level, desc := record.DecodeAlert(payload)
			if desc == record.AlertCloseNotify {
				return 0, io.EOF
			}

			return 0, fmt.Errorf("tls: received alert level=%d desc=%d: %w", level, desc, errAlertReceived)

		default:
			return 0, fmt.Errorf(
				"tls: unexpected record type %d in application data phase: %w", ct, errUnexpectedRecord,
			)
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

// Close sends a close_notify alert and closes the underlying connection.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Consume the Once: either (a) no-op if handshake already ran and result is
	// preserved, (b) blocks waiting if a handshake is in flight, or (c) records
	// errConnClosed if no handshake ever started.
	c.handshakeOnce.Do(func() { c.handshakeErr = errConnClosed })

	// Send close_notify if handshake succeeded.
	if c.handshakeErr == nil {
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

	params := handshake.ClientParams{
		Rand:                  c.config.rand(),
		ServerName:            c.config.ServerName,
		OfferedSuites:         offeredSuites,
		RootCAs:               rootCAs,
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
