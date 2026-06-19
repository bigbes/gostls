package gostls

import (
	"context"
	"net"
	"time"
)

// backendTag identifies which backend was compiled in.
// Used by tests to assert the correct code path is linked.
const backendTag = "default"

// BackendTag returns a string identifying the TLS backend compiled into this
// binary: "default" for the pure-Go backend, "openssl" for the CGO backend.
func BackendTag() string { return backendTag }

// dialBackend implements the pure-Go TLS backend.
// It dials a raw TCP connection using netDialer (or a zero-value net.Dialer
// if nil), then performs the TLS 1.2 handshake implemented in this package.
func dialBackend(ctx context.Context, network, addr string, netDialer *net.Dialer, cfg *Config) (net.Conn, error) {
	nd := netDialer
	if nd == nil {
		nd = &net.Dialer{}
	}

	rawConn, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := newConn(rawConn, cfg)

	// Mirror crypto/tls.Dialer: when no ServerName is configured, use the host
	// from the dial address for SNI and certificate verification.
	if cfg == nil || cfg.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			tlsConn.serverNameFromDial = host
		}
	}

	if err := tlsConn.handshakeContext(ctx); err != nil {
		_ = rawConn.Close()

		return nil, err
	}

	return tlsConn, nil
}

// handshakeContext runs the TLS handshake bounded by ctx: it applies ctx's
// deadline to the underlying connection and interrupts a blocked handshake if
// ctx is cancelled, so a stalled peer cannot block past ctx. Without this the
// handshake would read with no deadline at all.
func (c *Conn) handshakeContext(ctx context.Context) error {
	if ctx.Done() == nil {
		return c.Handshake()
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}

	done := make(chan struct{})
	interrupt := make(chan error, 1)

	go func() {
		select {
		case <-ctx.Done():
			// Unblock the in-flight handshake's blocked read/write.
			_ = c.conn.SetDeadline(time.Now())

			interrupt <- ctx.Err()
		case <-done:
			interrupt <- nil
		}
	}()

	err := c.Handshake()

	close(done)

	if ctxErr := <-interrupt; ctxErr != nil {
		return ctxErr
	}

	return err
}
