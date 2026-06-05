package handshake

// Tests for Phase 2: accepting optional CertificateRequest in the server
// flight between Certificate and ServerHelloDone.
//
// These tests drive recvServerFlight directly (an unexported method extracted
// from Handshake) so they stay isolated from cert verification, key derivation,
// and the CKE/Finished exchange.
//
// Tests for Phase 3: emit client Certificate and CertificateVerify messages,
// selectClientSigAlg, and sendClientCertificate wire bytes.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// -----------------------------------------------------------------------
// low-level wire helpers
// -----------------------------------------------------------------------

// buildHSRecord encodes a single TLS handshake record containing exactly one
// handshake message (type + 3-byte length + body).
func buildHSRecord(msgType Type, body []byte) []byte {
	hsMsg := buildEnvelope(msgType, body)
	rec := make([]byte, 5+len(hsMsg))
	rec[0] = record.ContentTypeHandshake
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(len(hsMsg) >> 8)
	rec[4] = byte(len(hsMsg))
	copy(rec[5:], hsMsg)
	return rec
}

// readWriteBuffer pairs a separate Reader and Writer for the record layer.
// Reads come from r; writes (alerts sent by the state machine) go to w.
type readWriteBuffer struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func (rw *readWriteBuffer) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *readWriteBuffer) Write(p []byte) (int, error) { return rw.w.Write(p) }

// makeClientStateForFlight sets up a minimal ClientState with the given suite
// and pre-loaded wire bytes.
func makeClientStateForFlight(t *testing.T, wire []byte, suite *suites.Suite) *ClientState {
	t.Helper()
	rw := &readWriteBuffer{r: bytes.NewBuffer(wire), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})
	c.suite = suite
	return c
}

// mustLookupSuite looks up a suite by name and fails the test if not found.
func mustLookupSuite(t *testing.T, name string) *suites.Suite {
	t.Helper()
	for _, s := range suites.All() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("suite %q not found in registry", name)
	return nil
}

// -----------------------------------------------------------------------
// cert / SKE builders
// -----------------------------------------------------------------------

// newTestECDSACert creates a minimal self-signed ECDSA P-256 cert.
func newTestECDSACert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return priv, cert
}

// newTestRSACert creates a minimal self-signed RSA-2048 cert. Returns private
// key, parsed cert, and DER bytes.
func newTestRSACert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create RSA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse RSA cert: %v", err)
	}
	return priv, cert, der
}

// newTestECDSACertWithDER creates a minimal self-signed ECDSA P-256 cert and
// returns the private key, parsed cert, and DER bytes.
func newTestECDSACertWithDER(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ecdsa-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create ECDSA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ECDSA cert: %v", err)
	}
	return priv, cert, der
}

// buildECDHESKEBody builds a valid ECDHE ServerKeyExchange body signed with priv.
func buildECDHESKEBody(t *testing.T, priv *ecdsa.PrivateKey, clientRandom, serverRandom [32]byte) []byte {
	t.Helper()
	eph, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ephemeral key: %v", err)
	}
	point := elliptic.Marshal(elliptic.P256(), eph.PublicKey.X, eph.PublicKey.Y)

	// ServerECDHParams: curve_type(3=named) || named_curve(P-256=0x0017) || point_len || point
	var params []byte
	params = append(params, 0x03)
	params = append(params, 0x00, 0x17)
	params = append(params, byte(len(point)))
	params = append(params, point...)

	// Signed data: clientRandom || serverRandom || params
	signed := make([]byte, 64+len(params))
	copy(signed[:32], clientRandom[:])
	copy(signed[32:64], serverRandom[:])
	copy(signed[64:], params)

	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign SKE: %v", err)
	}

	// body: params || hashAlg(sha256=0x04) || sigAlg(ecdsa=0x03) || uint16(sigLen) || sig
	var body []byte
	body = append(body, params...)
	body = append(body, 0x04, 0x03)
	body = append(body, byte(len(sig)>>8), byte(len(sig)))
	body = append(body, sig...)
	return body
}

// buildCertReqBody builds a minimal CertificateRequest wire body.
func buildCertReqBody(certTypes []uint8) []byte {
	sigAlgs := []SigAndHash{{Hash: 0x04, Sig: 0x01}} // sha256+rsa
	var body []byte
	body = append(body, byte(len(certTypes)))
	body = append(body, certTypes...)
	sigBytes := make([]byte, 2*len(sigAlgs))
	for i, sa := range sigAlgs {
		sigBytes[2*i] = sa.Hash
		sigBytes[2*i+1] = sa.Sig
	}
	body = append(body, byte(len(sigBytes)>>8), byte(len(sigBytes)))
	body = append(body, sigBytes...)
	body = append(body, 0x00, 0x00) // empty CA list
	return body
}

// buildCertReqBodyWithAlgs builds a CertificateRequest with given sig algs.
func buildCertReqBodyWithAlgs(certTypes []uint8, sigAlgs []SigAndHash) []byte {
	var body []byte
	body = append(body, byte(len(certTypes)))
	body = append(body, certTypes...)
	sigBytes := make([]byte, 2*len(sigAlgs))
	for i, sa := range sigAlgs {
		sigBytes[2*i] = sa.Hash
		sigBytes[2*i+1] = sa.Sig
	}
	body = append(body, byte(len(sigBytes)>>8), byte(len(sigBytes)))
	body = append(body, sigBytes...)
	body = append(body, 0x00, 0x00) // empty CA list
	return body
}

// -----------------------------------------------------------------------
// Test 1: happy path — SKE + CertReq + SHD (ECDHE suite)
// -----------------------------------------------------------------------

func TestRecvServerFlight_SKE_CertReq_SHD(t *testing.T) {
	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte
	for i := range clientRandom {
		clientRandom[i] = byte(i)
		serverRandom[i] = byte(i + 32)
	}

	skeBody := buildECDHESKEBody(t, priv, clientRandom, serverRandom)
	certReqBody := buildCertReqBody([]uint8{0x01, 0x02}) // rsa_sign, dss_sign

	var wire []byte
	wire = append(wire, buildHSRecord(TypeServerKeyExchange, skeBody)...)
	wire = append(wire, buildHSRecord(TypeCertificateRequest, certReqBody)...)
	wire = append(wire, buildHSRecord(TypeServerHelloDone, nil)...)

	suite := mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256")
	c := makeClientStateForFlight(t, wire, suite)
	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	serverKeyExchParams, err := c.recvServerFlight(cert)
	if err != nil {
		t.Fatalf("recvServerFlight: %v", err)
	}
	if serverKeyExchParams == nil {
		t.Error("expected serverKeyExchParams to be non-nil")
	}
	if c.certReq == nil {
		t.Fatal("expected certReq to be set, got nil")
	}
	if len(c.certReq.CertificateTypes) != 2 {
		t.Errorf("CertificateTypes: got %v, want [0x01 0x02]", c.certReq.CertificateTypes)
	}
	if c.certReq.CertificateTypes[0] != 0x01 || c.certReq.CertificateTypes[1] != 0x02 {
		t.Errorf("CertificateTypes values wrong: %v", c.certReq.CertificateTypes)
	}
}

// -----------------------------------------------------------------------
// Test 2: happy path — CertReq only, no SKE (RSA suite)
// -----------------------------------------------------------------------

func TestRecvServerFlight_CertReq_NoSKE(t *testing.T) {
	certReqBody := buildCertReqBody([]uint8{0x01}) // rsa_sign

	var wire []byte
	wire = append(wire, buildHSRecord(TypeCertificateRequest, certReqBody)...)
	wire = append(wire, buildHSRecord(TypeServerHelloDone, nil)...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA
	c := makeClientStateForFlight(t, wire, suite)

	serverKeyExchParams, err := c.recvServerFlight(nil)
	if err != nil {
		t.Fatalf("recvServerFlight: %v", err)
	}
	if serverKeyExchParams != nil {
		t.Errorf("expected serverKeyExchParams nil for RSA (no SKE), got %x", serverKeyExchParams)
	}
	if c.certReq == nil {
		t.Fatal("expected certReq to be set, got nil")
	}
	if len(c.certReq.CertificateTypes) != 1 || c.certReq.CertificateTypes[0] != 0x01 {
		t.Errorf("CertificateTypes: got %v, want [0x01]", c.certReq.CertificateTypes)
	}
}

// -----------------------------------------------------------------------
// Test 3: no CertReq — existing flow, SKE + SHD (ECDHE suite)
// -----------------------------------------------------------------------

func TestRecvServerFlight_SKE_SHD_NoCertReq(t *testing.T) {
	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte
	for i := range clientRandom {
		clientRandom[i] = byte(i + 64)
		serverRandom[i] = byte(i + 96)
	}

	skeBody := buildECDHESKEBody(t, priv, clientRandom, serverRandom)

	var wire []byte
	wire = append(wire, buildHSRecord(TypeServerKeyExchange, skeBody)...)
	wire = append(wire, buildHSRecord(TypeServerHelloDone, nil)...)

	suite := mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256")
	c := makeClientStateForFlight(t, wire, suite)
	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	serverKeyExchParams, err := c.recvServerFlight(cert)
	if err != nil {
		t.Fatalf("recvServerFlight: %v", err)
	}
	if serverKeyExchParams == nil {
		t.Error("expected serverKeyExchParams set, got nil")
	}
	if c.certReq != nil {
		t.Errorf("expected certReq nil (no CertReq in wire), got %+v", c.certReq)
	}
}

// -----------------------------------------------------------------------
// Test 4: duplicate CertReq → fatal error
// -----------------------------------------------------------------------

func TestRecvServerFlight_DuplicateCertReq(t *testing.T) {
	certReqBody := buildCertReqBody([]uint8{0x01})

	var wire []byte
	wire = append(wire, buildHSRecord(TypeCertificateRequest, certReqBody)...)
	wire = append(wire, buildHSRecord(TypeCertificateRequest, certReqBody)...)
	wire = append(wire, buildHSRecord(TypeServerHelloDone, nil)...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("expected error for duplicate CertificateRequest, got nil")
	}
}

// -----------------------------------------------------------------------
// Test 5: out-of-order — SKE after CertReq → fatal error
// -----------------------------------------------------------------------

func TestRecvServerFlight_SKEAfterCertReq(t *testing.T) {
	certReqBody := buildCertReqBody([]uint8{0x01})
	// A minimal fake SKE body that would parse (the error fires before verification).
	skeBody := []byte{0x03, 0x00, 0x17, 0x04} // too short to be valid, but error is out-of-order

	var wire []byte
	wire = append(wire, buildHSRecord(TypeCertificateRequest, certReqBody)...)
	wire = append(wire, buildHSRecord(TypeServerKeyExchange, skeBody)...)
	wire = append(wire, buildHSRecord(TypeServerHelloDone, nil)...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("expected error for out-of-order SKE after CertReq, got nil")
	}
}

// -----------------------------------------------------------------------
// Phase 3 Tests: selectClientSigAlg
// -----------------------------------------------------------------------

// newMinimalClientState builds a minimal ClientState with a certReq and optional
// client certificates, suitable for testing selectClientSigAlg.
func newMinimalClientState(certs []ClientCertificate, serverAlgs []SigAndHash) *ClientState {
	return &ClientState{
		params: ClientParams{
			Certificates: certs,
		},
		certReq: &CertificateRequest{
			SupportedSignatureAlgs: serverAlgs,
		},
	}
}

// TestSelectClientSigAlg_RSA_Server_SHA256_SHA384 tests that an RSA key with
// server offering [sha256+rsa, sha384+rsa] picks sha256+rsa (first advertised).
func TestSelectClientSigAlg_RSA_Server_SHA256_SHA384(t *testing.T) {
	rsaKey, _, _ := newTestRSACert(t)

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: rsaKey}},
		[]SigAndHash{
			{Hash: 0x04, Sig: 0x01}, // sha256+rsa
			{Hash: 0x05, Sig: 0x01}, // sha384+rsa
		},
	)

	alg, ok := c.selectClientSigAlg()
	if !ok {
		t.Fatal("selectClientSigAlg: expected match, got false")
	}
	// Must be the first entry in clientSigAlgsAdvertised that the server also supports.
	// Our ClientHello advertise list: {sha256+rsa, sha384+rsa, sha256+ecdsa, sha384+ecdsa, sha1+rsa}
	// Server has sha256+rsa and sha384+rsa; RSA key compatible with both.
	// First advertised that server also has: sha256+rsa.
	if alg.Hash != 0x04 || alg.Sig != 0x01 {
		t.Errorf("got alg {Hash:0x%02x Sig:0x%02x}, want sha256+rsa {0x04 0x01}", alg.Hash, alg.Sig)
	}
}

// TestSelectClientSigAlg_ECDSA_P256_ServerOnlyHasSHA384ECDSA tests that a P-256
// ECDSA key returns false when server only offers sha384+ecdsa (P-256 is sha256).
func TestSelectClientSigAlg_ECDSA_P256_ServerOnlyHasSHA384ECDSA(t *testing.T) {
	ecKey, _, _ := newTestECDSACertWithDER(t) // P-256

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: ecKey}},
		[]SigAndHash{
			{Hash: 0x05, Sig: 0x03}, // sha384+ecdsa only
		},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: P-256 key should not match sha384+ecdsa, expected false")
	}
}

// TestSelectClientSigAlg_RSA_ServerOnlyHasSHA512 tests that when server only
// offers sha512+rsa (not in our ClientHello advertise list), returns false.
func TestSelectClientSigAlg_RSA_ServerOnlyHasSHA512(t *testing.T) {
	rsaKey, _, _ := newTestRSACert(t)

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: rsaKey}},
		[]SigAndHash{
			{Hash: 0x06, Sig: 0x01}, // sha512+rsa — not in our advertised list
		},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: sha512+rsa not in advertised list, expected false")
	}
}

// TestSelectClientSigAlg_NilCertReq tests that nil certReq returns false.
func TestSelectClientSigAlg_NilCertReq(t *testing.T) {
	rsaKey, _, _ := newTestRSACert(t)

	c := &ClientState{
		params: ClientParams{
			Certificates: []ClientCertificate{{PrivateKey: rsaKey}},
		},
		certReq: nil,
	}

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: nil certReq should return false")
	}
}

// TestSelectClientSigAlg_EmptyCertificates tests that no client certs returns false.
func TestSelectClientSigAlg_EmptyCertificates(t *testing.T) {
	c := newMinimalClientState(
		nil,
		[]SigAndHash{{Hash: 0x04, Sig: 0x01}},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: empty certs should return false")
	}
}

// -----------------------------------------------------------------------
// Phase 3 Tests: sendClientCertificate wire bytes
// -----------------------------------------------------------------------

// makeRecordLayerWithCapture returns a record layer whose writes go to a buffer.
func makeRecordLayerWithCapture() (*record.Layer, *bytes.Buffer) {
	w := new(bytes.Buffer)
	rw := &readWriteBuffer{r: new(bytes.Buffer), w: w}
	return record.NewLayer(rw), w
}

// TestSendClientCertificate_Empty verifies that empty Certificates → empty cert
// message: handshake type 0x0b, 3-byte zero body (7 bytes total payload).
func TestSendClientCertificate_Empty(t *testing.T) {
	layer, w := makeRecordLayerWithCapture()

	c := &ClientState{
		params:     ClientParams{Certificates: nil},
		layer:      layer,
		transcript: NewTranscript(),
	}

	sent, err := c.sendClientCertificate()
	if err != nil {
		t.Fatalf("sendClientCertificate: unexpected error: %v", err)
	}
	if sent {
		t.Fatal("sendClientCertificate: expected sent=false for empty cert list")
	}

	// The expected handshake fragment: 0b 00 00 03 00 00 00 (7 bytes).
	want := MarshalMessage(&Certificate{})
	if len(want) != 7 {
		t.Fatalf("MarshalMessage(&Certificate{}) len=%d, want 7; bytes=%x", len(want), want)
	}

	// Parse the TLS record written to w.
	written := w.Bytes()
	if len(written) < 5 {
		t.Fatalf("output too short: %x", written)
	}
	if written[0] != record.ContentTypeHandshake {
		t.Errorf("content type 0x%02x, want 0x%02x (handshake)", written[0], record.ContentTypeHandshake)
	}
	payloadLen := int(written[3])<<8 | int(written[4])
	if len(written) < 5+payloadLen {
		t.Fatalf("record truncated: have %d, need %d", len(written), 5+payloadLen)
	}
	payload := written[5 : 5+payloadLen]
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %x\nwant    = %x", payload, want)
	}
}

// TestSendClientCertificate_OneRSACert verifies that a single RSA cert produces
// a Certificate message containing the DER bytes.
func TestSendClientCertificate_OneRSACert(t *testing.T) {
	rsaKey, _, der := newTestRSACert(t)

	layer, w := makeRecordLayerWithCapture()

	c := &ClientState{
		params: ClientParams{
			Certificates: []ClientCertificate{
				{RawCertificate: der, PrivateKey: rsaKey},
			},
		},
		layer:      layer,
		transcript: NewTranscript(),
		certReq: &CertificateRequest{
			SupportedSignatureAlgs: []SigAndHash{
				{Hash: 0x04, Sig: 0x01}, // sha256+rsa
			},
		},
	}

	sent, err := c.sendClientCertificate()
	if err != nil {
		t.Fatalf("sendClientCertificate: %v", err)
	}
	if !sent {
		t.Fatal("sendClientCertificate: expected sent=true for RSA cert")
	}

	// Parse the TLS record.
	written := w.Bytes()
	if len(written) < 5 {
		t.Fatalf("output too short: %x", written)
	}
	payloadLen := int(written[3])<<8 | int(written[4])
	if len(written) < 5+payloadLen {
		t.Fatalf("record truncated")
	}
	payload := written[5 : 5+payloadLen]

	// msg type = 0x0b (Certificate).
	if payload[0] != 0x0b {
		t.Errorf("msg type = 0x%02x, want 0x0b", payload[0])
	}

	// The DER cert bytes must appear in the payload.
	if !bytes.Contains(payload, der) {
		t.Errorf("payload does not contain the DER cert bytes\npayload=%x\nder=%x", payload, der)
	}
}

// -----------------------------------------------------------------------
// Phase 3 Tests: sendCertificateVerify
// -----------------------------------------------------------------------

// TestSendCertificateVerify_RSA verifies that sendCertificateVerify with an RSA
// key produces a CertificateVerify message whose signature verifies against the
// transcript.
func TestSendCertificateVerify_RSA(t *testing.T) {
	rsaKey, _, _ := newTestRSACert(t)

	layer, w := makeRecordLayerWithCapture()

	tr := NewTranscript()
	// Write some fake transcript data to simulate prior messages.
	tr.Write([]byte("fake transcript data for testing"))

	c := &ClientState{
		params:     ClientParams{Rand: rand.Reader, Certificates: []ClientCertificate{{PrivateKey: rsaKey}}},
		layer:      layer,
		transcript: tr,
	}

	alg := SigAndHash{Hash: 0x04, Sig: 0x01} // sha256+rsa
	if err := c.sendCertificateVerify(alg); err != nil {
		t.Fatalf("sendCertificateVerify: %v", err)
	}

	// Parse the written record.
	written := w.Bytes()
	if len(written) < 5 {
		t.Fatalf("no output")
	}
	payloadLen := int(written[3])<<8 | int(written[4])
	payload := written[5 : 5+payloadLen]

	// Parse the CertificateVerify message.
	cv, _, err := ParseMessage(payload)
	if err != nil {
		t.Fatalf("parse CertificateVerify: %v", err)
	}
	cvMsg := cv.(*CertificateVerify)
	if cvMsg.Algorithm.Hash != 0x04 || cvMsg.Algorithm.Sig != 0x01 {
		t.Errorf("algorithm mismatch: got {0x%02x,0x%02x}", cvMsg.Algorithm.Hash, cvMsg.Algorithm.Sig)
	}

	// Verify the signature using hashForSigAlg (the shared helper).
	// The transcript at signing time contained only "fake transcript data for testing".
	cryptoHash, hashErr := hashForSigAlg(alg.Hash)
	if hashErr != nil {
		t.Fatalf("hashForSigAlg: %v", hashErr)
	}
	h := cryptoHash.New()
	h.Write([]byte("fake transcript data for testing"))
	expectedDigest := h.Sum(nil)

	if verifyErr := rsa.VerifyPKCS1v15(&rsaKey.PublicKey, cryptoHash, expectedDigest, cvMsg.Signature); verifyErr != nil {
		t.Errorf("signature verification failed: %v", verifyErr)
	}
}
