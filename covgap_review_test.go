// Package gostls — coverage-gap tests for the security-critical defaults and
// lifecycle guarantees of conn.go / dialer.go / dialer_default.go:
//
//  1. the insecure-default regression: a zero-value Config verifies (does not
//     skip verification), and an empty effective ServerName fails closed with
//     errNoServerName on both the NewConn and the DialContext code paths;
//  2. DialContext honours context cancellation (already-cancelled and
//     cancelled-mid-handshake) without leaking the raw net.Conn;
//  3. the current default AvailableSuites() composition is pinned so any change
//     is a deliberate test update, not an accident.
//
// These are structural / negative / lifecycle tests — no external KAT. The
// harness mirrors conn_error_paths_test.go (newConn, net.Pipe, atomic flags).
//
//nolint:testpackage // white-box: references unexported newConn, errNoServerName, handshakeContext
package gostls

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bigbes/gostls/internal/handshake"
)

// 1. Insecure-default regression.

// TestConfig_ZeroValue_VerifiesByDefault asserts that a zero-value Config does
// NOT skip verification. This is the single most security-load-bearing default
// in the package: were InsecureSkipVerify to default to true (e.g. via a struct
// change or a stray field reorder), every connection would silently accept any
// certificate. Lock it.
func TestConfig_ZeroValue_VerifiesByDefault(t *testing.T) {
	t.Parallel()

	var cfg Config // zero value.

	if cfg.InsecureSkipVerify {
		t.Fatal("zero-value Config{}.InsecureSkipVerify is true; " +
			"the secure default MUST be false (verification enabled)")
	}
}

// TestDoHandshake_EmptyServerName_FailsClosed_NewConn verifies that a Conn
// created via NewConn with verification enabled (InsecureSkipVerify false) and
// no ServerName — and, because it did not come from a Dialer, no
// serverNameFromDial — fails closed with errNoServerName rather than silently
// skipping hostname verification (fail-open).
//
// The error is returned before any ClientHello is written, so no server side is
// needed: the net.Pipe peer is never read from.
func TestDoHandshake_EmptyServerName_FailsClosed_NewConn(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	// Zero-value Config: verification on, ServerName empty. NewConn leaves
	// serverNameFromDial empty, so the effective server name is "".
	c := NewConn(client, &Config{})

	err := c.Handshake()
	if err == nil {
		t.Fatal("expected errNoServerName from Handshake with empty ServerName and verification on, got nil")
	}

	if !errors.Is(err, errNoServerName) {
		t.Errorf("expected errNoServerName, got %T: %v", err, err)
	}
}

// TestDoHandshake_EmptyServerName_FailsClosed_DialContext verifies the same
// fail-closed guarantee on the Dialer path: when the dial address carries no
// host (":port"), serverNameFromDial is left empty, and with verification
// enabled DialContext must abort with errNoServerName instead of connecting
// unverified.
//
// The listener accepts the TCP connection so the dial reaches the handshake;
// doHandshake returns errNoServerName before writing the ClientHello.
func TestDoHandshake_EmptyServerName_FailsClosed_DialContext(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = ln.Close() }()

	// Accept and hold; the client aborts before exchanging bytes.
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			go func(cc net.Conn) {
				defer func() { _ = cc.Close() }()

				_, _ = io.Copy(io.Discard, cc)
			}(conn)
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}

	// Address with an empty host: net.SplitHostPort returns host="" (no error),
	// so dialBackend leaves serverNameFromDial empty, yet the dial still reaches
	// the loopback listener.
	addr := net.JoinHostPort("", port)

	d := &Dialer{Config: &Config{}} // verification on, ServerName empty.

	_, derr := d.DialContext(context.Background(), "tcp", addr)
	if derr == nil {
		t.Fatal("expected errNoServerName from DialContext with empty host and verification on, got nil")
	}

	if !errors.Is(derr, errNoServerName) {
		t.Errorf("expected errNoServerName, got %T: %v", derr, derr)
	}
}

// 2. DialContext cancellation.

// TestDialContext_AlreadyCancelledContext_AbortsPromptly verifies that a dial
// started with an already-cancelled context returns quickly with a
// cancellation error, without waiting on the network.
func TestDialContext_AlreadyCancelledContext_AbortsPromptly(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before dialing.

	d := &Dialer{Config: &Config{InsecureSkipVerify: true}} //nolint:gosec // cancellation test.

	start := time.Now()
	_, derr := d.DialContext(ctx, "tcp", ln.Addr().String())
	elapsed := time.Since(start)

	if derr == nil {
		t.Fatal("expected error dialing with an already-cancelled context, got nil")
	}

	if !errors.Is(derr, context.Canceled) {
		t.Errorf("expected context.Canceled, got %T: %v", derr, derr)
	}

	if elapsed > time.Second {
		t.Errorf("dial took %v with an already-cancelled context; expected a prompt abort", elapsed)
	}
}

// TestDialContext_CancelMidHandshake_ClosesRawConn verifies that when the
// context is cancelled while the TLS handshake is stalled, DialContext aborts
// AND closes the raw net.Conn (no fd/goroutine leak). The stalling peer reads
// the ClientHello and never replies; once the client aborts and closes the raw
// connection, the server's io.Copy observes EOF — proving the raw conn was
// closed, not leaked.
func TestDialContext_CancelMidHandshake_ClosesRawConn(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = ln.Close() }()

	// serverClosed is signalled when the accepted connection observes EOF, i.e.
	// when the client side is closed. A leaked (never-closed) raw conn would
	// leave io.Copy blocked forever and this channel unsignalled.
	serverClosed := make(chan struct{}, 1)

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}

		go func() {
			defer func() { _ = conn.Close() }()

			_, _ = io.Copy(io.Discard, conn) // stall: read ClientHello, never reply.

			select {
			case serverClosed <- struct{}{}:
			default:
			}
		}()
	}()

	// Bounded context so the stalled handshake is interrupted deterministically.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	d := &Dialer{Config: &Config{InsecureSkipVerify: true}} //nolint:gosec // cancellation test.

	start := time.Now()
	_, derr := d.DialContext(ctx, "tcp", ln.Addr().String())
	elapsed := time.Since(start)

	if derr == nil {
		t.Fatal("expected error when context is cancelled mid-handshake, got nil")
	}

	if elapsed > 2*time.Second {
		t.Fatalf("DialContext blocked %v despite a 150ms ctx deadline (cancellation ignored)", elapsed)
	}

	// The raw conn must be closed by dialBackend's error path.
	select {
	case <-serverClosed:
		// Good: the peer observed the client closing the transport.
	case <-time.After(2 * time.Second):
		t.Fatal("raw net.Conn was not closed after handshake abort (connection leak)")
	}
}

// 3. Default cipher-suite composition.

// TestAvailableSuites_DefaultComposition pins the CURRENT default suite set
// offered when Config.CipherSuites is nil. This is a change-detector, not a
// policy gate: it deliberately does NOT assert a "no static-RSA / no SHA1"
// policy (0x002F, static-RSA AES-128-CBC-SHA, is intentionally present today).
// Its job is to make any future change to the default negotiation set a
// conscious, reviewed test update rather than a silent drift.
func TestAvailableSuites_DefaultComposition(t *testing.T) {
	t.Parallel()

	// Snapshot of handshake.AvailableSuites() as of this commit. Order is
	// documented as "stable but unspecified", so compare as a set.
	want := []uint16{
		0xC02C, 0xC02C, // ECDHE-ECDSA-AES256-GCM-SHA384.
		0xCCA9, 0xCCA9, // ECDHE-ECDSA-CHACHA20-POLY1305.
		0xC02B, 0xC02B, // ECDHE-ECDSA-AES128-GCM-SHA256.
		0xC030, 0xC030, // ECDHE-RSA-AES256-GCM-SHA384.
		0xCCA8, 0xCCA8, // ECDHE-RSA-CHACHA20-POLY1305.
		0xC02F, 0xC02F, // ECDHE-RSA-AES128-GCM-SHA256.
		0xC024, 0xC024, // ECDHE-ECDSA-AES256-SHA384.
		0xC023, 0xC023, // ECDHE-ECDSA-AES128-SHA256.
		0xC028, 0xC028, // ECDHE-RSA-AES256-SHA384.
		0xC027, 0xC027, // ECDHE-RSA-AES128-SHA256.
		0xC00A, 0xC00A, // ECDHE-ECDSA-AES256-SHA.
		0xC009, 0xC009, // ECDHE-ECDSA-AES128-SHA.
		0xC014, 0xC014, // ECDHE-RSA-AES256-SHA.
		0xC013, 0xC013, // ECDHE-RSA-AES128-SHA.
		0x009F, 0x009F, // DHE-RSA-AES256-GCM-SHA384.
		0xCCAA, 0xCCAA, // DHE-RSA-CHACHA20-POLY1305.
		0x009E, 0x009E, // DHE-RSA-AES128-GCM-SHA256.
		0x006B, 0x006B, // DHE-RSA-AES256-SHA256.
		0x0067, 0x0067, // DHE-RSA-AES128-SHA256.
		0x0039, 0x0039, // DHE-RSA-AES256-SHA.
		0x0033, 0x0033, // DHE-RSA-AES128-SHA.
		0x009D, 0x009D, // RSA-AES256-GCM-SHA384.
		0x009C, 0x009C, // RSA-AES128-GCM-SHA256.
		0x003D, 0x003D, // RSA-AES256-SHA256.
		0x003C, 0x003C, // RSA-AES128-SHA256.
		0x0035, 0x0035, // RSA-AES256-SHA.
		0x002F, 0x002F, // RSA-AES128-SHA (static-RSA, SHA1 — kept intentionally, see doc).
	}

	got := handshake.AvailableSuites()

	// Build sets, checking for duplicates in the actual output along the way.
	gotSet := make(map[uint16]struct{}, len(got))
	for _, id := range got {
		if _, dup := gotSet[id]; dup {
			t.Errorf("AvailableSuites() contains duplicate suite 0x%04X", id)
		}

		gotSet[id] = struct{}{}
	}

	wantSet := make(map[uint16]struct{}, len(want))
	for _, id := range want {
		wantSet[id] = struct{}{}
	}

	if len(gotSet) != len(wantSet) {
		t.Errorf("default suite count = %d, want %d", len(gotSet), len(wantSet))
	}

	for id := range wantSet {
		if _, ok := gotSet[id]; !ok {
			t.Errorf("expected default suite 0x%04X is missing", id)
		}
	}

	for id := range gotSet {
		if _, ok := wantSet[id]; !ok {
			t.Errorf("unexpected new default suite 0x%04X; if intentional, update this pinned set", id)
		}
	}
}
