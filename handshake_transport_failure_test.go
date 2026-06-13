package gostls_test

// Transport-failure handshake tests.
//
// These tests verify that the client state machine surfaces a non-nil error
// (rather than hanging) when the server closes the connection at each stage
// of the TLS 1.2 handshake.  All tests use net.Pipe and the scripted-server
// helpers declared in handshake_test.go.
//
// Each test sets a deadline on the client side so the test cannot block
// forever if the state machine were to hang on a read.

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/bigbes/gostls"
	"github.com/bigbes/gostls/internal/suites"
)

// withDeadline wraps a net.Conn with a 5-second deadline so blocked reads fail fast.
func withDeadline(conn net.Conn) net.Conn {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// ecdheSuiteForTransport returns the ECDHE-RSA-AES128-GCM-SHA256 suite or skips.
func ecdheSuiteForTransport(t *testing.T) *suites.Suite {
	t.Helper()

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Skip("ECDHE-RSA-AES128-GCM-SHA256 not registered")
	}

	return suite
}

// drainConn reads all available bytes from conn until EOF or deadline, discarding them.
func drainConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.SetReadDeadline(time.Time{})
}

// TestTransportFailure_CloseAfterClientHello verifies that an EOF during the
// client's recvServerHello() read (server closes after reading ClientHello)
// is returned as a non-nil error from Handshake().
func TestTransportFailure_CloseAfterClientHello(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	go func() {
		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()
		// Close without sending anything.
		_ = serverConn.Close()
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{InsecureSkipVerify: true}, //nolint:gosec // negative test.
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error after server close mid-ServerHello read, got nil")
	}

	t.Logf("CloseAfterClientHello: %v", err)
}

// TestTransportFailure_CloseAfterServerHello verifies that an EOF during the
// client's recvCertificate() read (server closes after sending ServerHello)
// is returned as a non-nil error from Handshake().
func TestTransportFailure_CloseAfterServerHello(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteForTransport(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		// Close without sending Certificate.
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{InsecureSkipVerify: true}, //nolint:gosec // negative test.
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error after server close mid-Certificate read, got nil")
	}

	t.Logf("CloseAfterServerHello: %v", err)
}

// TestTransportFailure_CloseAfterCertificate verifies that an EOF during the
// client's recvServerFlight() read (server closes after sending Certificate)
// is returned as a non-nil error from Handshake().
func TestTransportFailure_CloseAfterCertificate(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteForTransport(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		cert := buildCertificate([][]byte{testServerCertDER})
		srv.writeHandshake(cert)

		// Close without sending ServerKeyExchange or ServerHelloDone.
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{InsecureSkipVerify: true}, //nolint:gosec // negative test.
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error after server close mid-ServerFlight read, got nil")
	}

	t.Logf("CloseAfterCertificate: %v", err)
}

// TestTransportFailure_BadServerKeyExchange verifies that a garbage
// ServerKeyExchange (unverifiable body) during the server flight causes
// Handshake() to return a non-nil error from recvServerFlight.
// The server goroutine drains the client's fatal alert before closing so
// net.Pipe does not stall.
func TestTransportFailure_BadServerKeyExchange(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite := ecdheSuiteForTransport(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		cert := buildCertificate([][]byte{testServerCertDER})
		srv.writeHandshake(cert)

		// Send a garbage SKE — client will fail to verify and close the connection.
		// wrapHS builds the 4-byte handshake envelope (type||len24||body).
		badSKE := wrapHS(12 /* ServerKeyExchange. */, []byte{0xDE, 0xAD})
		srv.writeHandshake(badSKE)

		// Drain the client's fatal alert so the pipe does not stall.
		drainConn(serverConn)
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{InsecureSkipVerify: true}, //nolint:gosec // negative test.
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error from bad ServerKeyExchange, got nil")
	}

	t.Logf("BadServerKeyExchange: %v", err)
}

// TestTransportFailure_CloseAfterServerCCS verifies that closing the connection
// after sending the server ChangeCipherSpec (but before sending server Finished)
// causes Handshake() to return a non-nil error when it tries to read the
// server Finished.
func TestTransportFailure_CloseAfterServerCCS(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	// Use AES128-SHA256 (KexRSA) — no SKE scripting needed.
	suite, ok := suites.LookupByName("AES128-SHA256")
	if !ok {
		t.Skip("AES128-SHA256 not registered")
	}

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		cert := buildCertificate([][]byte{testServerCertDER})
		srv.writeHandshake(cert)

		shd := buildServerHelloDone()
		srv.writeHandshake(shd)

		// Drain all client bytes (CKE + CCS + encrypted Finished) using raw
		// reads; we cannot decrypt without keys, so we just discard everything.
		drainConn(serverConn)

		// Send server CCS but close immediately without sending Finished.
		_ = srv.layer.WriteRecord(0x14 /* ChangeCipherSpec. */, []byte{0x01})
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{
			InsecureSkipVerify: true, //nolint:gosec // negative test.
			CipherSuites:       []uint16{suite.ID},
		},
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error when server closes after CCS (before Finished), got nil")
	}

	t.Logf("CloseAfterServerCCS: %v", err)
}

// TestTransportFailure_GarbageRecordInsteadOfServerHello verifies that an
// unexpected application-data record where a ServerHello was expected causes
// Handshake() to return a non-nil error (errUnexpectedRecordType branch in
// readHandshakeRecord).
func TestTransportFailure_GarbageRecordInsteadOfServerHello(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	go func() {
		defer drainAndClose(serverConn)

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		// Send an application-data record (type 0x17) where ServerHello is expected.
		_ = srv.layer.WriteRecord(0x17, []byte("not a handshake"))
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{InsecureSkipVerify: true}, //nolint:gosec // negative test.
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error for garbage record where ServerHello expected, got nil")
	}

	t.Logf("GarbageRecord: %v", err)
}

// TestTransportFailure_MalformedServerCCS verifies that a server CCS with
// payload {0x02} (instead of {0x01}) causes Handshake() to return a non-nil
// error (errMalformedCCS branch in Handshake step 11).
func TestTransportFailure_MalformedServerCCS(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite, ok := suites.LookupByName("AES128-SHA256")
	if !ok {
		t.Skip("AES128-SHA256 not registered")
	}

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	var serverRandom [32]byte

	go func() {
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)

		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		cert := buildCertificate([][]byte{testServerCertDER})
		srv.writeHandshake(cert)

		shd := buildServerHelloDone()
		srv.writeHandshake(shd)

		// Drain all client bytes (CKE + CCS + encrypted Finished) with raw reads.
		drainConn(serverConn)

		// Send a malformed CCS: payload is {0x02} instead of {0x01}.
		_ = srv.layer.WriteRecord(0x14 /* ChangeCipherSpec. */, []byte{0x02})
	}()

	tlsConn := gostls.NewConn(
		withDeadline(clientConn),
		&gostls.Config{
			InsecureSkipVerify: true, //nolint:gosec // negative test.
			CipherSuites:       []uint16{suite.ID},
		},
	)

	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected error for malformed server CCS, got nil")
	}

	t.Logf("MalformedServerCCS: %v", err)
}
