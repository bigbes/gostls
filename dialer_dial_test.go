package gostls_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/bigbes/gostls"
)

// ============================================================================
// Suite registry tests (AllSuites, LookupSuiteByName)
// ============================================================================.

// TestAllSuites_NonEmpty verifies that AllSuites returns at least one suite
// and that each entry has a non-zero ID and a non-empty name.
func TestAllSuites_NonEmpty(t *testing.T) {
	t.Parallel()

	all := gostls.AllSuites()

	if len(all) == 0 {
		t.Fatal("AllSuites() returned empty slice")
	}

	for _, s := range all {
		if s.ID == 0 {
			t.Errorf("suite %q has zero ID", s.Name)
		}

		if s.Name == "" {
			t.Errorf("suite with ID 0x%04x has empty Name", s.ID)
		}
	}

	t.Logf("AllSuites() returned %d suites", len(all))
}

// TestAllSuites_ContainsKnownSuite checks that a well-known suite is present.
func TestAllSuites_ContainsKnownSuite(t *testing.T) {
	t.Parallel()

	const wantName = "ECDHE-RSA-AES128-GCM-SHA256"

	const wantID = uint16(0xC02F)

	all := gostls.AllSuites()

	found := false

	for _, s := range all {
		if s.Name == wantName {
			if s.ID != wantID {
				t.Errorf("suite %q has ID 0x%04x, want 0x%04x", wantName, s.ID, wantID)
			}

			found = true

			break
		}
	}

	if !found {
		t.Errorf("AllSuites() does not contain %q", wantName)
	}
}

// TestLookupSuiteByName_Known verifies that a registered suite name resolves
// to the correct IANA ID.
func TestLookupSuiteByName_Known(t *testing.T) {
	t.Parallel()

	id, ok := gostls.LookupSuiteByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("LookupSuiteByName(\"ECDHE-RSA-AES128-GCM-SHA256\") returned not-found")
	}

	if id != 0xC02F {
		t.Errorf("LookupSuiteByName returned ID 0x%04x, want 0xC02F", id)
	}
}

// TestLookupSuiteByName_Unknown verifies that an unregistered name returns
// (0, false) — the not-found result.
func TestLookupSuiteByName_Unknown(t *testing.T) {
	t.Parallel()

	id, ok := gostls.LookupSuiteByName("NOT-A-REAL-SUITE")
	if ok {
		t.Fatalf("LookupSuiteByName(unknown) returned ok=true, id=0x%04x", id)
	}

	if id != 0 {
		t.Errorf("LookupSuiteByName(unknown) returned id=0x%04x, want 0", id)
	}
}

// ============================================================================
// Dialer.DialContext tests
// ============================================================================.

// startStdlibTLSServer starts a crypto/tls TLS 1.2 server using the shared
// test fixtures (testCACert, testServerKey, testServerCertDER). The server
// echoes every ApplicationData record it receives. The caller must call
// l.Close() when done.
func startStdlibTLSServer(t *testing.T) net.Listener {
	t.Helper()
	initTestFixtures(t)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{testServerCertDER},
		PrivateKey:  testServerKey,
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12, //nolint:gosec // pinned to TLS 1.2 intentionally for interop test.
		MaxVersion:   tls.VersionTLS12, //nolint:gosec // same.
	}

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	tlsLn := tls.NewListener(ln, cfg)

	go func() {
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return // listener closed.
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				buf := make([]byte, 4096)
				for {
					n, readErr := c.Read(buf)
					if readErr != nil {
						return
					}

					if _, writeErr := c.Write(buf[:n]); writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return tlsLn
}

// TestDialer_DialContext_Success dials a real stdlib TLS 1.2 server using
// Dialer.DialContext and performs a round-trip to confirm the connection works.
func TestDialer_DialContext_Success(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	ln := startStdlibTLSServer(t)
	defer func() { _ = ln.Close() }()

	pool := rootCAsForTest(t)

	d := &gostls.Dialer{
		Config: &gostls.Config{
			RootCAs:    pool,
			ServerName: "test.example.com",
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	defer func() { _ = conn.Close() }()

	// Round-trip a small payload.
	want := []byte("ping")

	if _, err := conn.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := make([]byte, len(want))

	if _, err := conn.Read(got); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("round-trip: got %q, want %q", got, want)
	}
}

// TestDialer_DialContext_InsecureSkipVerify verifies that a Dialer with
// InsecureSkipVerify reaches the server and completes the handshake even
// without a configured RootCAs pool.
func TestDialer_DialContext_InsecureSkipVerify(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	ln := startStdlibTLSServer(t)
	defer func() { _ = ln.Close() }()

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional for this negative-path test.
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext with InsecureSkipVerify: %v", err)
	}

	_ = conn.Close()
}

// TestDialer_DialContext_NilNetDialer exercises the branch where
// Dialer.NetDialer is nil, which causes dialBackend to create a default
// net.Dialer internally.
func TestDialer_DialContext_NilNetDialer(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	ln := startStdlibTLSServer(t)
	defer func() { _ = ln.Close() }()

	pool := rootCAsForTest(t)

	d := &gostls.Dialer{
		NetDialer: nil, // exercises the nil-NetDialer branch in dialBackend.
		Config: &gostls.Config{
			RootCAs:    pool,
			ServerName: "test.example.com",
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext with nil NetDialer: %v", err)
	}

	_ = conn.Close()
}

// TestDialer_DialContext_ClosedPort verifies that DialContext returns an error
// (not a panic) when the target port is closed.
func TestDialer_DialContext_ClosedPort(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := ln.Addr().String()

	_ = ln.Close() // port is now closed.

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true, //nolint:gosec // error-path test, no real data.
		},
	}

	_, dialErr := d.DialContext(context.Background(), "tcp", addr)
	if dialErr == nil {
		t.Fatal("expected error dialing closed port, got nil")
	}

	t.Logf("correctly received error for closed port: %v", dialErr)
}

// TestDialer_DialContext_ContextCancelled verifies that a cancelled context
// causes DialContext to return promptly with an error.
func TestDialer_DialContext_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately.

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true, //nolint:gosec // error-path test.
		},
	}

	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — always unreachable on a normal
	// network, so the dial attempt blocks until the context fires.
	_, dialErr := d.DialContext(ctx, "tcp", "192.0.2.1:443")
	if dialErr == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}

	t.Logf("correctly received error for cancelled context: %v", dialErr)
}
