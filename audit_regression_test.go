//nolint:testpackage // white-box: exercises unexported newConn, sentinels and conn fields
package gostls

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bigbes/gostls/internal/record"
)

// stallingListener starts a TCP listener whose connections accept (and discard)
// data but never reply, simulating a peer that stalls during the TLS handshake.
func stallingListener(t *testing.T) net.Listener {
	t.Helper()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	return ln
}

// TestConn_Handshake_FailsClosedWithoutServerName covers H1: with verification
// enabled and no ServerName (and none derived from a dial address), the
// handshake must fail closed rather than silently skip hostname verification.
func TestConn_Handshake_FailsClosedWithoutServerName(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	c := newConn(client, &Config{})

	if err := c.Handshake(); !errors.Is(err, errNoServerName) {
		t.Fatalf("expected errNoServerName, got %v", err)
	}
}

// TestDialContext_DerivesServerNameFromAddr covers H1: DialContext derives the
// ServerName from the dial address when Config.ServerName is empty (like
// crypto/tls.Dialer), so verification is not skipped and the fail-closed guard
// does not trigger. The dial then fails on the stalling handshake — not with
// errNoServerName.
func TestDialContext_DerivesServerNameFromAddr(t *testing.T) {
	t.Parallel()

	ln := stallingListener(t)
	t.Cleanup(func() { _ = ln.Close() })

	d := &Dialer{Config: &Config{}}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("expected the dial to fail against a stalling peer")
	}

	if errors.Is(err, errNoServerName) {
		t.Fatal("DialContext did not derive ServerName from the dial address")
	}
}

// TestConn_Close_InterruptsInFlightHandshake covers H3: Close must not block on a
// handshake that is in flight. Closing the transport unblocks the handshake; both
// Close and Handshake return promptly.
func TestConn_Close_InterruptsInFlightHandshake(t *testing.T) {
	t.Parallel()

	ln := stallingListener(t)
	t.Cleanup(func() { _ = ln.Close() })

	var nd net.Dialer

	raw, err := nd.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	c := newConn(raw, &Config{InsecureSkipVerify: true}) //nolint:gosec // stalling-peer test.

	hsDone := make(chan error, 1)

	go func() { hsDone <- c.Handshake() }()

	// Give the handshake time to send ClientHello and block reading ServerHello.
	time.Sleep(50 * time.Millisecond)

	closeDone := make(chan error, 1)

	go func() { closeDone <- c.Close() }()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on the in-flight handshake")
	}

	select {
	case <-hsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not unblock after Close")
	}
}

// TestConn_Read_StickyErrorAfterFatalAlert covers L2: after a fatal record-layer
// error, every subsequent Read returns the same error instead of parsing the
// now-desynchronized stream (a second Read here would otherwise block on the
// drained pipe).
func TestConn_Read_StickyErrorAfterFatalAlert(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	t.Cleanup(func() { _ = c.conn.Close() })
	t.Cleanup(func() { _ = server.Close() })

	// Server sends a fatal alert: level=2 (fatal), desc=40 (handshake_failure).
	go func() {
		writeRawRecord(t, server, record.ContentTypeAlert, []byte{2, 40})
	}()

	buf := make([]byte, 16)

	_, err1 := c.Read(buf)
	if !errors.Is(err1, errAlertReceived) {
		t.Fatalf("first Read after fatal alert: expected errAlertReceived, got %v", err1)
	}

	// The error must be sticky: the second Read returns it without reading the
	// drained pipe again (otherwise this Read would block indefinitely).
	_, err2 := c.Read(buf)
	if !errors.Is(err2, errAlertReceived) {
		t.Fatalf("second Read: expected sticky errAlertReceived, got %v", err2)
	}
}
