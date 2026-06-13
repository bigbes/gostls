package gostls_test

// Malformed-server-flight handshake tests.
//
// These tests drive the client state machine through its error branches by
// scripting a server that sends bad or out-of-order handshake messages.
// They reuse the helpers declared in handshake_test.go
// (newScriptedServer, buildServerHello, buildCertificate, buildServerHelloDone,
// rootCAsForTest, initTestFixtures, etc.).

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bigbes/gostls"
	"github.com/bigbes/gostls/internal/suites"
)

// handshakeError calls tlsConn.Handshake() and asserts it returns a non-nil
// error. Returns the error.
func handshakeError(t *testing.T, tlsConn *gostls.Conn) error {
	t.Helper()

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected handshake to fail, got nil")
	}

	return err
}

// drainAndClose reads up to 512 bytes from conn (discarding them) then closes.
// Used by server goroutines to consume the client's fatal alert so the pipe
// does not block.
func drainAndClose(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 512)

	conn.Read(buf) //nolint:errcheck

	_ = conn.Close()
}

// ecdheSuiteOrSkip returns the ECDHE-RSA-AES128-GCM-SHA256 suite or skips.
func ecdheSuiteOrSkip(t *testing.T) *suites.Suite {
	t.Helper()

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Skip("ECDHE-RSA-AES128-GCM-SHA256 not registered")
	}

	return suite
}

// 1. ServerHello with an un-offered cipher suite.

// TestHandshake_ServerHello_UnofferedSuite verifies that the client rejects a
// ServerHello that selects a cipher suite not in the ClientHello offer list.
func TestHandshake_ServerHello_UnofferedSuite(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		// 0x00FF is not a valid IANA suite and is never offered.
		sh := buildServerHello(serverRandom, 0x00FF)
		srv.writeHandshake(sh)
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("un-offered suite: %v", err)
}

// 2. ServerHello with wrong TLS version.

// TestHandshake_ServerHello_WrongVersion verifies that the client rejects a
// ServerHello that advertises TLS 1.0 instead of TLS 1.2.
func TestHandshake_ServerHello_WrongVersion(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	suite := ecdheSuiteOrSkip(t)

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		// Build a ServerHello and then patch version to 0x0301 (TLS 1.0).
		// wrapHS result: [type(1)|len(3)|version(2)|random(32)|...]
		// version is at offsets 4 and 5.
		sh := buildServerHello(serverRandom, suite.ID)
		if len(sh) >= 6 {
			sh[4] = 0x03
			sh[5] = 0x01 // TLS 1.0.
		}

		srv.writeHandshake(sh)
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("wrong version: %v", err)
}

// 3. Out-of-order message: ServerHelloDone before Certificate.

// TestHandshake_ServerFlight_SHDBeforeCertificate verifies that the client
// rejects a server flight that sends ServerHelloDone immediately after
// ServerHello, before the Certificate message.
func TestHandshake_ServerFlight_SHDBeforeCertificate(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteOrSkip(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		// Skip Certificate and send ServerHelloDone immediately.
		// The client expects Certificate (type 11) but gets ServerHelloDone (type 14).
		shd := buildServerHelloDone()
		srv.writeHandshake(shd)
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("SHD before Certificate: %v", err)
}

// 4. Certificate with an empty cert list.

// TestHandshake_Certificate_EmptyList verifies that the client rejects a
// Certificate message with an empty certificate list (no cert at all).
func TestHandshake_Certificate_EmptyList(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteOrSkip(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		// Empty cert list.
		cert := buildCertificate(nil)
		srv.writeHandshake(cert)
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("empty cert list: %v", err)
}

// 5. Truncated handshake message (truncated body).

// TestHandshake_TruncatedServerHello verifies that a handshake record whose
// declared body length exceeds the actual payload causes the client to return
// a hard error.
func TestHandshake_TruncatedServerHello(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		// Build a minimal ServerHello envelope that claims 32 bytes of body
		// but provides none. Connection closes immediately after so the client
		// sees EOF while waiting for the declared bytes.
		truncated := []byte{
			2,          // ServerHello type.
			0, 0, 0x20, // body length = 32 (claimed).
			// No body bytes at all — EOF follows.
		}
		srv.writeHandshake(truncated)

		// Close immediately so client sees EOF while waiting for body.
		_ = serverConn.Close()
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("truncated ServerHello: %v", err)
}

// 6. Untrusted server certificate.

// TestHandshake_UntrustedServerCert verifies that the client rejects a
// self-signed server certificate that is not in the RootCAs trust store when
// InsecureSkipVerify is false.
func TestHandshake_UntrustedServerCert(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteOrSkip(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		// Send our test cert, which is signed by our test CA but the client
		// below trusts only the system pool (which won't contain that CA).
		cert := buildCertificate([][]byte{testServerCertDER})
		srv.writeHandshake(cert)
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		ServerName:         "test.example.com",
		RootCAs:            nil,   // system pool (won't contain our test CA).
		InsecureSkipVerify: false, //nolint:gosec // intentionally verifying certs.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("untrusted server cert: %v", err)
}

// 7. ServerKeyExchange required but missing (SKE for ECDHE suite).

// TestHandshake_ServerFlight_MissingServerKeyExchange verifies that the client
// rejects a server flight for an ECDHE suite that omits the ServerKeyExchange
// message (sends ServerHelloDone immediately after Certificate).
func TestHandshake_ServerFlight_MissingServerKeyExchange(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteOrSkip(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		cert := buildCertificate([][]byte{testServerCertDER})
		srv.writeHandshake(cert)

		// Skip ServerKeyExchange → send ServerHelloDone directly.
		// For ECDHE, a missing SKE is a hard error → client must reject.
		shd := buildServerHelloDone()
		srv.writeHandshake(shd)
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test; cert error is irrelevant.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("missing SKE for ECDHE suite: %v", err)
}

// 8. Connection closed mid-handshake (during ServerHello read).

// TestHandshake_ConnectionClosedMidHandshake verifies that an EOF during the
// ServerHello read (before any flight is exchanged) is surfaced as an error.
func TestHandshake_ConnectionClosedMidHandshake(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	go func() {
		// Accept ClientHello then close the connection immediately.
		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		_ = serverConn.Close()
	}()

	tlsConn := gostls.NewConn(clientConn, &gostls.Config{
		InsecureSkipVerify: true, //nolint:gosec // negative test.
	})

	err := handshakeError(t, tlsConn)
	t.Logf("connection closed mid-handshake: %v", err)
}

// 9. Read/Write after a failed handshake.

// TestConn_ReadAfterFailedHandshake verifies that Read called on a conn whose
// handshake failed returns the same error as Handshake() (cached result).
func TestConn_ReadAfterFailedHandshake(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	go func() {
		defer func() { _ = serverConn.Close() }()

		buf := make([]byte, 256)

		serverConn.Read(buf) //nolint:errcheck
	}()

	// Config with empty suite list → Handshake() returns errNoSuites immediately.
	c := gostls.NewConn(clientConn, &gostls.Config{
		CipherSuites:       []uint16{}, //nolint:gosec // error path: forces errNoSuites.
		InsecureSkipVerify: true,
	})

	hsErr := c.Handshake()
	if hsErr == nil {
		t.Fatal("expected handshake error, got nil")
	}

	// Read must return the same error.
	buf := make([]byte, 16)

	_, readErr := c.Read(buf)
	if readErr == nil {
		t.Fatal("expected Read to fail after failed handshake, got nil")
	}

	if readErr.Error() != hsErr.Error() {
		t.Errorf("Read err %q != Handshake err %q", readErr, hsErr)
	}
}

// TestConn_WriteAfterFailedHandshake verifies that Write on a conn whose
// handshake failed returns the cached handshake error.
func TestConn_WriteAfterFailedHandshake(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	go func() {
		defer func() { _ = serverConn.Close() }()

		buf := make([]byte, 256)

		serverConn.Read(buf) //nolint:errcheck
	}()

	c := gostls.NewConn(clientConn, &gostls.Config{
		CipherSuites:       []uint16{}, //nolint:gosec // error path: forces errNoSuites.
		InsecureSkipVerify: true,
	})

	hsErr := c.Handshake()
	if hsErr == nil {
		t.Fatal("expected handshake error, got nil")
	}

	_, writeErr := c.Write([]byte("hello"))
	if writeErr == nil {
		t.Fatal("expected Write to fail after failed handshake, got nil")
	}

	if writeErr.Error() != hsErr.Error() {
		t.Errorf("Write err %q != Handshake err %q", writeErr, hsErr)
	}
}

// 10. Dial context already cancelled at call time.

// TestDialer_DialContext_AlreadyCancelledContext checks that DialContext returns
// promptly when the context is cancelled before the call.
func TestDialer_DialContext_AlreadyCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before dialing.

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true, //nolint:gosec // error-path test.
		},
	}

	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — unreachable; the pre-cancelled
	// context should cause an immediate error without blocking.
	_, err := d.DialContext(ctx, "tcp", "192.0.2.1:443")
	if err == nil {
		t.Fatal("expected error for pre-cancelled context, got nil")
	}

	t.Logf("correctly received error for pre-cancelled context: %v", err)
}
