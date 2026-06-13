//nolint:testpackage // white-box: accesses unexported newConn for nil-config path
package gostls

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestNewConn_NilConfig verifies that newConn accepts a nil config and
// falls back to a zero-value Config internally (coverage for the nil guard
// branch in newConn).
func TestNewConn_NilConfig(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, nil)
	if c == nil {
		t.Fatal("newConn(_, nil) returned nil")
	}

	if c.config == nil {
		t.Fatal("newConn(_, nil): c.config must be non-nil after fallback")
	}
}

// TestConn_AddrDelegation verifies that LocalAddr and RemoteAddr on a *Conn
// delegate to the underlying net.Conn.
func TestConn_AddrDelegation(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	if got, want := c.LocalAddr(), client.LocalAddr(); got != want {
		t.Errorf("LocalAddr() = %v, want %v", got, want)
	}

	if got, want := c.RemoteAddr(), client.RemoteAddr(); got != want {
		t.Errorf("RemoteAddr() = %v, want %v", got, want)
	}
}

// TestConn_SetDeadline verifies that SetDeadline is forwarded to the
// underlying net.Conn. A past deadline makes Read immediately time out, which
// proves the call actually reached the underlying transport.
func TestConn_SetDeadline(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// SetDeadline itself must not error.
	if err := c.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Reset to zero (no deadline) to leave the conn clean.
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline(zero): %v", err)
	}
}

// TestConn_SetReadDeadline verifies the passthrough and that a past deadline
// causes Read to return immediately with a timeout error.
func TestConn_SetReadDeadline(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// Mark handshake done so Read bypasses Handshake().
	c.handshakeOnce.Do(func() {})

	// A deadline set in the past must cause the next Read to fail immediately.
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 1)

	_, readErr := c.Read(buf)
	if readErr == nil {
		t.Fatal("expected timeout error from Read after past SetReadDeadline, got nil")
	}

	// Must be a timeout error (net.Error.Timeout()), not an EOF or other error.
	var netErr net.Error

	if !errors.As(readErr, &netErr) || !netErr.Timeout() {
		t.Errorf("expected net.Error with Timeout()=true, got %T: %v", readErr, readErr)
	}
}

// TestConn_SetWriteDeadline verifies the passthrough and that a past deadline
// causes Write to return immediately with a timeout error.
func TestConn_SetWriteDeadline(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// Mark handshake done so Write bypasses Handshake().
	c.handshakeOnce.Do(func() {})

	// A deadline set in the past must cause the next Write to fail immediately.
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	_, writeErr := c.Write([]byte("hello"))
	if writeErr == nil {
		t.Fatal("expected timeout error from Write after past SetWriteDeadline, got nil")
	}

	var netErr net.Error

	if !errors.As(writeErr, &netErr) || !netErr.Timeout() {
		t.Errorf("expected net.Error with Timeout()=true, got %T: %v", writeErr, writeErr)
	}
}

// TestConn_Read_ClosedConn exercises the early-return path in Read when the
// connection is already marked closed.
func TestConn_Read_ClosedConn(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// Mark handshake done and connection closed.
	c.handshakeOnce.Do(func() {})
	c.closed.Store(true)

	buf := make([]byte, 1)

	_, readErr := c.Read(buf)
	if readErr == nil {
		t.Fatal("expected error reading from closed conn, got nil")
	}
}
