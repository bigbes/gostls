package gostls_test

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bigbes/gostls"
	"github.com/bigbes/gostls/internal/suites"
)

// handshakedPipeConn completes a real TLS 1.2 handshake over net.Pipe against
// the scripted test server and returns the post-handshake client *Conn. It lets
// the Conn transport behaviour (deadlines, close, concurrent Read/Write) be
// exercised through the public API instead of reaching into unexported fields.
//
// If drain is true the server keeps reading after the handshake, so the client
// can Write without blocking; otherwise the server sits idle, so a client Write
// blocks until its write deadline fires (the synchronous net.Pipe semantics the
// deadline tests rely on).
func handshakedPipeConn(t *testing.T, drain bool) (*gostls.Conn, func()) {
	t.Helper()
	initTestFixtures(t)

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("test suite ECDHE-RSA-AES128-GCM-SHA256 not registered")
	}

	clientConn, serverConn := net.Pipe()

	var serverRandom [32]byte

	serverRandom[0] = 0xDE
	serverRandom[1] = 0xAD

	stop := make(chan struct{})
	srvDone := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				srvDone <- fmt.Errorf("server panic: %v", r)
			}
		}()

		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)
		runner.runFullHandshake(serverRandom)

		srvDone <- nil

		// Keep the peer open after the handshake so the client Conn stays
		// usable: drain to let Write succeed, or sit idle so Write blocks.
		if drain {
			buf := make([]byte, 4096)
			for {
				if _, err := serverConn.Read(buf); err != nil {
					return
				}
			}
		}

		<-stop
	}()

	conn := gostls.NewConn(clientConn, &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
	})

	if err := conn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	if err := <-srvDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	cleanup := func() {
		close(stop)

		_ = clientConn.Close()
		_ = serverConn.Close()
	}

	return conn, cleanup
}

// TestNewConn_NilConfig verifies that NewConn accepts a nil config and returns
// a usable connection (the nil-config fallback to a zero-value Config). The
// fallback is observed through the public API: a method that delegates to the
// underlying transport works without panicking.
func TestNewConn_NilConfig(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, nil)
	if conn == nil {
		t.Fatal("NewConn(_, nil) returned nil")
	}

	if got, want := conn.LocalAddr(), client.LocalAddr(); got != want {
		t.Errorf("NewConn(_, nil): LocalAddr() = %v, want %v", got, want)
	}
}

// TestConn_AddrDelegation verifies that LocalAddr and RemoteAddr on a *Conn
// delegate to the underlying net.Conn (no handshake required).
func TestConn_AddrDelegation(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, &gostls.Config{})

	if got, want := conn.LocalAddr(), client.LocalAddr(); got != want {
		t.Errorf("LocalAddr() = %v, want %v", got, want)
	}

	if got, want := conn.RemoteAddr(), client.RemoteAddr(); got != want {
		t.Errorf("RemoteAddr() = %v, want %v", got, want)
	}
}

// TestConn_SetDeadline verifies that SetDeadline is forwarded to the underlying
// net.Conn without error (it does not trigger the handshake).
func TestConn_SetDeadline(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, &gostls.Config{})

	if err := conn.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline(zero): %v", err)
	}
}

// TestConn_SetReadDeadline verifies the passthrough reaches the transport: a
// past read deadline makes the next Read return a timeout error.
func TestConn_SetReadDeadline(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, false)
	defer cleanup()

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 1)

	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected timeout error from Read after past SetReadDeadline, got nil")
	}

	var netErr net.Error

	if !errors.As(readErr, &netErr) || !netErr.Timeout() {
		t.Errorf("expected net.Error with Timeout()=true, got %T: %v", readErr, readErr)
	}
}

// TestConn_SetWriteDeadline verifies the passthrough reaches the transport: a
// past write deadline makes the next Write return a timeout error (the idle
// server never reads, so the synchronous net.Pipe Write blocks until the
// deadline fires).
func TestConn_SetWriteDeadline(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, false)
	defer cleanup()

	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	_, writeErr := conn.Write([]byte("hello"))
	if writeErr == nil {
		t.Fatal("expected timeout error from Write after past SetWriteDeadline, got nil")
	}

	var netErr net.Error

	if !errors.As(writeErr, &netErr) || !netErr.Timeout() {
		t.Errorf("expected net.Error with Timeout()=true, got %T: %v", writeErr, writeErr)
	}
}

// TestConn_Read_ClosedConn exercises the early-return path in Read when the
// connection has been closed via the public Close method. The server drains so
// Close's close_notify write completes.
func TestConn_Read_ClosedConn(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, true)
	defer cleanup()

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	buf := make([]byte, 1)

	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected error reading from closed conn, got nil")
	}
}
