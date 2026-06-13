// White-box unit tests for expandKeys, sendClientHello, recvServerHello,
// recvCertificate, and recvServerFlight branches in client.go that are not
// reachable by the e2e tests in the root package.
//
//nolint:testpackage // white-box: exercises unexported methods
package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// makeClientStateWithKeys returns a ClientState that has masterSecret,
// clientRandom, and serverRandom set — the minimum needed for expandKeys.
func makeClientStateWithKeys(t *testing.T, suite *suites.Suite) *ClientState {
	t.Helper()

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		InsecureSkipVerify: true,
		Rand:               rand.Reader,
	})

	c.suite = suite

	// Fill master secret and randoms with deterministic non-zero bytes.
	c.masterSecret = make([]byte, 48)
	for i := range c.masterSecret {
		c.masterSecret[i] = byte(i + 1)
	}

	for i := range c.clientRandom {
		c.clientRandom[i] = byte(i + 0x10)
		c.serverRandom[i] = byte(i + 0x20)
	}

	return c
}

// TestExpandKeys_AESGCM exercises the AEAD (AES-128-GCM) path of expandKeys.
func TestExpandKeys_AESGCM(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(AES-128-GCM): %v", err)
	}

	if km == nil {
		t.Error("km should not be nil")
	}

	if sendProt == nil {
		t.Error("sendProt should not be nil")
	}

	if recvProt == nil {
		t.Error("recvProt should not be nil")
	}
}

// TestExpandKeys_AESCBC exercises the CBC (AES-128-CBC) path of expandKeys
// where isCBC=true forces ivLen=0 (IV not derived from key block).
func TestExpandKeys_AESCBC(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-SHA256")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(AES-128-CBC): %v", err)
	}

	if km == nil {
		t.Fatal("km should not be nil")
	}

	if sendProt == nil {
		t.Error("sendProt should not be nil")
	}

	if recvProt == nil {
		t.Error("recvProt should not be nil")
	}

	// For CBC the IV is NOT derived from the key block (ivLen=0 passed).
	if len(km.ClientIV) != 0 {
		t.Errorf("ClientIV: got %d bytes, want 0 (CBC uses per-record explicit IV)", len(km.ClientIV))
	}

	if len(km.ServerIV) != 0 {
		t.Errorf("ServerIV: got %d bytes, want 0 (CBC uses per-record explicit IV)", len(km.ServerIV))
	}
}

// TestExpandKeys_GOST28147CNT exercises the GOST28147-CNT path of expandKeys.
// The cipher is non-AEAD and non-CBC so ivLen stays at FixedIVLen=8, meaning
// the IV IS derived from the key block.
func TestExpandKeys_GOST28147CNT(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2001-GOST89-GOST89")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(GOST2001-GOST89-GOST89): %v", err)
	}

	if km == nil {
		t.Fatal("km should not be nil")
	}

	if sendProt == nil {
		t.Error("sendProt should not be nil")
	}

	if recvProt == nil {
		t.Error("recvProt should not be nil")
	}

	// GOST28147-CNT has FixedIVLen=8; since it is not CBC the IV comes from the key block.
	if len(km.ClientIV) != 8 {
		t.Errorf("ClientIV: got %d bytes, want 8 (GOST28147-CNT key-block IV)", len(km.ClientIV))
	}

	if len(km.ServerIV) != 8 {
		t.Errorf("ServerIV: got %d bytes, want 8 (GOST28147-CNT key-block IV)", len(km.ServerIV))
	}
}

// TestExpandKeys_KuznyechikCTROMAC exercises the KUZNYECHIK-CTR-OMAC path
// of expandKeys (non-AEAD, non-CBC GOST stream cipher).
func TestExpandKeys_KuznyechikCTROMAC(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(GOST2012-KUZNYECHIK-KUZNYECHIKOMAC): %v", err)
	}

	if km == nil {
		t.Error("km should not be nil")
	}

	if sendProt == nil {
		t.Error("sendProt should not be nil")
	}

	if recvProt == nil {
		t.Error("recvProt should not be nil")
	}
}

// TestExpandKeys_MagmaCTROMAC exercises the MAGMA-CTR-OMAC path of expandKeys
// (non-AEAD, non-CBC GOST stream cipher).
func TestExpandKeys_MagmaCTROMAC(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2012-MAGMA-MAGMAOMAC")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(GOST2012-MAGMA-MAGMAOMAC): %v", err)
	}

	if km == nil {
		t.Error("km should not be nil")
	}

	if sendProt == nil {
		t.Error("sendProt should not be nil")
	}

	if recvProt == nil {
		t.Error("recvProt should not be nil")
	}
}

// TestExpandKeys_ZeroTotalLen exercises the errKeyExpansionZero path of expandKeys.
// All key/IV lengths are zeroed, AEAD=true keeps isCBC=false so ivLen stays 0,
// giving totalLen = 2*0 + 2*0 + 2*0 = 0.
func TestExpandKeys_ZeroTotalLen(t *testing.T) {
	t.Parallel()

	base := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	zero := *base

	zero.Cipher.KeyLen = 0
	zero.Cipher.FixedIVLen = 0
	zero.MAC.KeyLen = 0
	zero.Cipher.AEAD = true
	zero.Cipher.Name = "AES-128-GCM"

	c := makeClientStateWithKeys(t, &zero)

	km, sp, rp, keyErr := c.expandKeys()

	_ = km
	_ = sp
	_ = rp

	if keyErr == nil {
		t.Fatal("expandKeys with zero key lengths: expected error, got nil")
	}
}

// failRandReader is an io.Reader that always fails.
type failRandReader struct{ msg string }

func (f *failRandReader) Read(_ []byte) (int, error) {
	return 0, errors.New(f.msg)
}

// TestSendClientHello_RandFails exercises the io.ReadFull error branch in
// sendClientHello (generating the client random fails).
func TestSendClientHello_RandFails(t *testing.T) {
	t.Parallel()

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	c := NewClientState(layer, ClientParams{
		Rand:               &failRandReader{msg: "rand-failure"},
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	c.suite = suite

	err := c.sendClientHello()
	if err == nil {
		t.Fatal("sendClientHello with failing rand: expected error, got nil")
	}
}

// failReadWriter is an io.ReadWriter whose Write always fails.
type failReadWriter struct{ msg string }

func (fw *failReadWriter) Read(p []byte) (int, error)  { return 0, fmt.Errorf("read: %s", fw.msg) }
func (fw *failReadWriter) Write(_ []byte) (int, error) { return 0, errors.New(fw.msg) }

// TestSendClientHello_WriteRecordFails exercises the WriteRecord error branch
// in sendClientHello (the network write fails immediately).
func TestSendClientHello_WriteRecordFails(t *testing.T) {
	t.Parallel()

	fw := &failReadWriter{msg: "write-failure"}
	layer := record.NewLayer(fw)

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	c.suite = suite

	err := c.sendClientHello()
	if err == nil {
		t.Fatal("sendClientHello with failing WriteRecord: expected error, got nil")
	}
}

// TestRecvServerHello_ParseFailure exercises the ServerHello parse error path:
// a 1-byte body is too short to parse as a ServerHello.
func TestRecvServerHello_ParseFailure(t *testing.T) {
	t.Parallel()

	badRec := buildHSRecord(TypeServerHello, []byte{0xFF})

	rw := &readWriteBuffer{r: bytes.NewBuffer(badRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with truncated body: expected error, got nil")
	}
}

// TestRecvServerHello_WrongMessageType exercises the errExpectedServerHello
// branch when a Certificate arrives where a ServerHello was expected.
func TestRecvServerHello_WrongMessageType(t *testing.T) {
	t.Parallel()

	certMsg := &Certificate{}
	rec := buildHSRecord(TypeCertificate, certMsg.Marshal())

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with wrong message type: expected error, got nil")
	}
}

// TestRecvServerHello_SuiteNotOffered exercises the errSuiteNotOffered branch
// when the server selects a cipher suite not in the client's offer list.
func TestRecvServerHello_SuiteNotOffered(t *testing.T) {
	t.Parallel()

	ecdheGCM := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	rsaOnly := mustFindSuiteByName(t, "AES128-SHA256")

	var random [32]byte

	// Server selects ECDHE-RSA-AES128-GCM but client only offered AES128-SHA256.
	shBody := buildRawServerHelloBody(random, ecdheGCM.ID, 0x0303, 0x00)
	shRec := buildHSRecord(TypeServerHello, shBody)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{rsaOnly.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with un-offered suite: expected error, got nil")
	}
}

// TestRecvServerHello_WrongVersion exercises the errBadVersion branch when
// the server's ServerHello advertises TLS 1.0 instead of TLS 1.2.
func TestRecvServerHello_WrongVersion(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	var random [32]byte

	shBody := buildRawServerHelloBody(random, suite.ID, 0x0301, 0x00) // TLS 1.0.
	shRec := buildHSRecord(TypeServerHello, shBody)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with wrong TLS version: expected error, got nil")
	}
}

// TestRecvServerHello_NonNullCompression exercises the errNonNullCompression
// branch when the server selects a non-null compression method.
func TestRecvServerHello_NonNullCompression(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	var random [32]byte

	shBody := buildRawServerHelloBody(random, suite.ID, 0x0303, 0x01) // compression=1.
	shRec := buildHSRecord(TypeServerHello, shBody)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with non-null compression: expected error, got nil")
	}
}

// TestRecvCertificate_ParseFailure exercises the parse error path in
// recvCertificate when the Certificate body is malformed.
func TestRecvCertificate_ParseFailure(t *testing.T) {
	t.Parallel()

	// outer_len=3 declared but only 2 bytes present after it → truncated entry.
	badBody := []byte{0x00, 0x00, 0x03, 0xAA, 0xBB}
	rec := buildHSRecord(TypeCertificate, badBody)

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustFindSuiteByName(t, "AES128-SHA256")

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	c.suite = suite

	_, _, err := c.recvCertificate()
	if err == nil {
		t.Fatal("recvCertificate with malformed body: expected error, got nil")
	}
}

// TestRecvCertificate_VerifyPeerCertificateError exercises the
// VerifyPeerCertificate callback error branch in recvCertificate.
func TestRecvCertificate_VerifyPeerCertificateError(t *testing.T) {
	t.Parallel()

	_, _, der := newTestRSACert(t)

	certMsg := &Certificate{RawCerts: [][]byte{der}}
	rec := buildHSRecord(TypeCertificate, certMsg.Marshal())

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustFindSuiteByName(t, "AES128-SHA256")

	callbackErr := errors.New("custom-verify-error")

	c := NewClientState(layer, ClientParams{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
			return callbackErr
		},
	})

	c.suite = suite

	_, _, err := c.recvCertificate()
	if err == nil {
		t.Fatal("recvCertificate with failing VerifyPeerCertificate: expected error, got nil")
	}
}

// TestRecvServerFlight_SKEAfterCertReq_White exercises the errSKEAfterCertReq
// branch: a second ServerKeyExchange arrives after a CertificateRequest,
// violating RFC 5246 §7.3 ordering.
func TestRecvServerFlight_SKEAfterCertReq_White(t *testing.T) {
	t.Parallel()

	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	skeBody := buildECDHESKEBody(t, priv, clientRandom, serverRandom)
	skeRec := buildHSRecord(TypeServerKeyExchange, skeBody)

	certReqBody := buildCertReqBody([]uint8{0x01}) // rsa_sign.
	certReqRec := buildHSRecord(TypeCertificateRequest, certReqBody)

	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	// Order: valid SKE, CertReq, another SKE → errSKEAfterCertReq.
	wire := append(append(append(append([]byte{}, skeRec...), certReqRec...), skeRec...), shdRec...)

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeClientStateForFlight(t, wire, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	_, err := c.recvServerFlight(cert)
	if err == nil {
		t.Fatal("recvServerFlight SKE after CertReq: expected error, got nil")
	}
}

// TestRecvServerFlight_DuplicateCertReq_White exercises the errDuplicateCertReq
// branch when two CertificateRequest messages appear in the server flight.
func TestRecvServerFlight_DuplicateCertReq_White(t *testing.T) {
	t.Parallel()

	certReqBody := buildCertReqBody([]uint8{0x01}) // rsa_sign.
	certReqRec := buildHSRecord(TypeCertificateRequest, certReqBody)
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	// KexRSA: no SKE needed. Send two CertReqs then SHD.
	wire := append(append(append([]byte{}, certReqRec...), certReqRec...), shdRec...)

	suite := mustLookupSuite(t, "AES128-SHA256")
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("recvServerFlight duplicate CertReq: expected error, got nil")
	}
}

// buildRawServerHelloBody is a wire-level builder that produces a minimal
// parseable ServerHello body with the given version, suite, and compression.
// It omits extensions (which keeps the body compact but still parseable).
func buildRawServerHelloBody(random [32]byte, suiteID uint16, version uint16, compression byte) []byte {
	body := make([]byte, 0, 38)

	body = append(body, byte(version>>8), byte(version))
	body = append(body, random[:]...)
	body = append(body, 0x00)                            // session_id len = 0.
	body = append(body, byte(suiteID>>8), byte(suiteID)) // cipher_suite.
	body = append(body, compression)                     // compression_method.

	return body
}
