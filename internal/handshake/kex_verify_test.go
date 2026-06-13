// computeKeyExchange, expandKeysManual, parseAndVerifyLeaf, sendCertificateVerify,
// buildEnvelope.
//
//nolint:testpackage // white-box: exercises unexported verifyDHEServerKeyExchange,
package handshake

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// -----------------------------------------------------------------------
// RFC 7919 ffdhe2048 p constant (256 bytes / 2048 bits)
// -----------------------------------------------------------------------.

const ffdhe2048PHexKEX = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695" +
	"A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A" +
	"D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
	"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A" +
	"BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4" +
	"AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03405CD28342F61" +
	"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005" +
	"C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"

// -----------------------------------------------------------------------
// appendU16PrefixedSlice appends a uint16-prefixed slice.
// -----------------------------------------------------------------------.

func appendU16PrefixedSlice(dst, data []byte) []byte {
	dst = append(dst, byte(len(data)>>8), byte(len(data)))
	return append(dst, data...)
}

// -----------------------------------------------------------------------
// rsaCertFromKeyKEX creates a self-signed RSA cert from an existing private key.
// -----------------------------------------------------------------------.

func rsaCertFromKeyKEX(t *testing.T, priv *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "test-kex"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return cert
}

// -----------------------------------------------------------------------
// buildDHESKEBodyReal builds a valid DHE SKE body, properly signed with RSA-SHA256.
// -----------------------------------------------------------------------.

func buildDHESKEBodyReal(t *testing.T, priv *rsa.PrivateKey, clientRandom, serverRandom [32]byte) []byte {
	t.Helper()

	p, err := hex.DecodeString(ffdhe2048PHexKEX)
	if err != nil {
		t.Fatalf("decode ffdhe2048 prime: %v", err)
	}

	g := []byte{0x02}

	// Ys: a valid value in (1, p-1). Use p-3.
	Ys := make([]byte, len(p))
	copy(Ys, p)

	Ys[len(Ys)-1] -= 3

	params := appendU16PrefixedSlice(nil, p)

	params = appendU16PrefixedSlice(params, g)
	params = appendU16PrefixedSlice(params, Ys)

	signed := make([]byte, 64+len(params))
	copy(signed[:32], clientRandom[:])
	copy(signed[32:64], serverRandom[:])
	copy(signed[64:], params)

	h := sha256.Sum256(signed)

	sig, signErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if signErr != nil {
		t.Fatalf("RSA sign: %v", signErr)
	}

	body := append(params, 0x04, 0x01) // hashAlg=sha256, sigAlg=rsa.

	body = append(body, byte(len(sig)>>8), byte(len(sig)))
	body = append(body, sig...)

	return body
}

// -----------------------------------------------------------------------
// makeMinimalClientState: create a ClientState with a write buffer for tests.
// -----------------------------------------------------------------------.

func makeMinimalClientState(t *testing.T, suite *suites.Suite) *ClientState {
	t.Helper()

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true, Rand: rand.Reader})

	c.suite = suite

	return c
}

// -----------------------------------------------------------------------
// verifyDHEServerKeyExchange — error branches
// -----------------------------------------------------------------------.

func TestVerifyDHEServerKeyExchange_TruncatedDHP(t *testing.T) {
	t.Parallel()

	// Only 1 byte: not enough for the uint16 length prefix of dh_p.
	body := []byte{0x00}

	_, cert, _ := newTestRSACert(t)
	c := makeMinimalClientState(t, mustLookupSuite(t, "DHE-RSA-AES128-SHA256"))

	_, err := c.verifyDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyDHEServerKeyExchange with 1-byte body: expected error, got nil")
	}
}

func TestVerifyDHEServerKeyExchange_SignatureSectionTooShort(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHexKEX)
	g := []byte{0x02}
	Ys := make([]byte, len(p))
	copy(Ys, p)

	Ys[len(Ys)-1] -= 3

	// Build valid params, but only 2 bytes of signature section (< 4 = sigSectionMin).
	params := appendU16PrefixedSlice(nil, p)

	params = appendU16PrefixedSlice(params, g)
	params = appendU16PrefixedSlice(params, Ys)

	body := append(params, 0x04, 0x01) // only 2 bytes for sig section.

	_, cert, _ := newTestRSACert(t)
	c := makeMinimalClientState(t, mustLookupSuite(t, "DHE-RSA-AES128-SHA256"))

	_, err := c.verifyDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyDHEServerKeyExchange with short sig section: expected error, got nil")
	}

	if !errors.Is(err, errDHESigSectionShort) {
		t.Errorf("expected errDHESigSectionShort, got %v", err)
	}
}

func TestVerifyDHEServerKeyExchange_SignatureTruncated(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHexKEX)
	g := []byte{0x02}
	Ys := make([]byte, len(p))
	copy(Ys, p)

	Ys[len(Ys)-1] -= 3

	params := appendU16PrefixedSlice(nil, p)

	params = appendU16PrefixedSlice(params, g)
	params = appendU16PrefixedSlice(params, Ys)

	// Declare sig length of 100, but provide only 5 bytes.
	body := append(params, 0x04, 0x01) // hashAlg + sigAlg.

	body = append(body, 0x00, 0x64)                   // sig length = 100.
	body = append(body, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE) // only 5 bytes of sig.

	_, cert, _ := newTestRSACert(t)
	c := makeMinimalClientState(t, mustLookupSuite(t, "DHE-RSA-AES128-SHA256"))

	_, err := c.verifyDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyDHEServerKeyExchange with truncated sig: expected error, got nil")
	}

	if !errors.Is(err, errDHESigTruncated) {
		t.Errorf("expected errDHESigTruncated, got %v", err)
	}
}

// -----------------------------------------------------------------------
// verifyDHEServerKeyExchange — happy path
// -----------------------------------------------------------------------.

func TestVerifyDHEServerKeyExchange_ValidRSASig(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cert := rsaCertFromKeyKEX(t, rsaKey)

	var clientRandom, serverRandom [32]byte

	for i := range clientRandom {
		clientRandom[i] = byte(i + 1)
		serverRandom[i] = byte(i + 2)
	}

	body := buildDHESKEBodyReal(t, rsaKey, clientRandom, serverRandom)

	suite := mustLookupSuite(t, "DHE-RSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	serverParams, err := c.verifyDHEServerKeyExchange(body, cert)
	if err != nil {
		t.Fatalf("verifyDHEServerKeyExchange: %v", err)
	}

	if len(serverParams) == 0 {
		t.Error("serverParams should be non-empty")
	}
}

func TestVerifyDHEServerKeyExchange_TamperedSignature(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cert := rsaCertFromKeyKEX(t, rsaKey)

	var clientRandom, serverRandom [32]byte

	body := buildDHESKEBodyReal(t, rsaKey, clientRandom, serverRandom)

	// Tamper the last byte of the signature.
	body[len(body)-1] ^= 0xFF

	suite := mustLookupSuite(t, "DHE-RSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	_, err = c.verifyDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyDHEServerKeyExchange with tampered sig: expected error, got nil")
	}
}

// -----------------------------------------------------------------------
// verifyServerKeyExchange — RSA suite receives unexpected SKE
// -----------------------------------------------------------------------.

func TestVerifyServerKeyExchange_RSA_Suite_Returns_Unexpected(t *testing.T) {
	t.Parallel()

	// For KexRSA suites, receiving a SKE is an error (unexpected).
	c := makeMinimalClientState(t, mustLookupSuite(t, "AES128-SHA256")) // KexRSA.

	_, cert, _ := newTestRSACert(t)

	_, err := c.verifyServerKeyExchange([]byte{0x01, 0x02}, cert)
	if err == nil {
		t.Fatal("verifyServerKeyExchange for RSA suite: expected error (unexpected SKE), got nil")
	}

	if !errors.Is(err, errUnexpectedSKE) {
		t.Errorf("expected errUnexpectedSKE, got %v", err)
	}
}

// -----------------------------------------------------------------------
// computeKeyExchange — dispatch table
// -----------------------------------------------------------------------.

func TestComputeKeyExchange_ECDHE(t *testing.T) {
	t.Parallel()

	_, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	for i := range clientRandom {
		clientRandom[i] = byte(i)
		serverRandom[i] = byte(i + 32)
	}

	priv, _ := newTestECDSACert(t)
	skeBody := buildECDHESKEBody(t, priv, clientRandom, serverRandom)

	if len(skeBody) < 4 {
		t.Fatalf("skeBody too short: %d", len(skeBody))
	}

	pointLen := int(skeBody[3])
	serverParams := skeBody[:4+pointLen]

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.params.Rand = rand.Reader

	preMaster, ckeBody, err := c.computeKeyExchange(cert, serverParams, nil)
	if err != nil {
		t.Fatalf("computeKeyExchange(ECDHE): %v", err)
	}

	if len(preMaster) == 0 {
		t.Error("preMaster should be non-empty")
	}

	if len(ckeBody) == 0 {
		t.Error("ckeBody should be non-empty")
	}
}

func TestComputeKeyExchange_RSA(t *testing.T) {
	t.Parallel()

	_, cert, _ := newTestRSACert(t)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA.
	c := makeMinimalClientState(t, suite)

	c.params.Rand = rand.Reader

	preMaster, ckeBody, err := c.computeKeyExchange(cert, nil, nil)
	if err != nil {
		t.Fatalf("computeKeyExchange(RSA): %v", err)
	}

	if len(preMaster) == 0 {
		t.Error("preMaster should be non-empty (RSA premaster)")
	}

	if len(ckeBody) == 0 {
		t.Error("ckeBody should be non-empty (RSA CKE)")
	}
}

func TestComputeKeyExchange_RSA_NonRSACert(t *testing.T) {
	t.Parallel()

	_, ecCert := newTestECDSACert(t)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA.
	c := makeMinimalClientState(t, suite)

	c.params.Rand = rand.Reader

	_, _, err := c.computeKeyExchange(ecCert, nil, nil)
	if err == nil {
		t.Fatal("computeKeyExchange RSA with ECDSA cert: expected error, got nil")
	}

	if !errors.Is(err, errRSAKeyExpected) {
		t.Errorf("expected errRSAKeyExpected, got %v", err)
	}
}

func TestComputeKeyExchange_UnknownKX(t *testing.T) {
	t.Parallel()

	_, cert, _ := newTestRSACert(t)

	// Borrow a valid suite and overwrite its KX to something unknown.
	validSuite := mustLookupSuite(t, "AES128-SHA256")
	fakeSuite := *validSuite

	fakeSuite.KX = suites.KexKind(255) // out-of-range / unknown.

	c := makeMinimalClientState(t, &fakeSuite)

	c.params.Rand = rand.Reader

	_, _, err := c.computeKeyExchange(cert, nil, nil)
	if err == nil {
		t.Fatal("computeKeyExchange with unknown KX: expected error, got nil")
	}

	if !errors.Is(err, errUnknownKXKind) {
		t.Errorf("expected errUnknownKXKind, got %v", err)
	}
}

// -----------------------------------------------------------------------
// parseAndVerifyLeaf — InsecureSkipVerify path and bad DER
// -----------------------------------------------------------------------.

func TestParseAndVerifyLeaf_InsecureSkipVerify(t *testing.T) {
	t.Parallel()

	_, _, der := newTestRSACert(t)

	c := &ClientState{
		params:     ClientParams{InsecureSkipVerify: true},
		transcript: NewTranscript(),
	}

	leaf, chains, err := parseAndVerifyLeaf(c, der)
	if err != nil {
		t.Fatalf("parseAndVerifyLeaf InsecureSkipVerify: %v", err)
	}

	if leaf == nil {
		t.Error("leaf should be non-nil for InsecureSkipVerify")
	}

	if chains != nil {
		t.Errorf("chains should be nil for InsecureSkipVerify, got %v", chains)
	}
}

func TestParseAndVerifyLeaf_BadDER(t *testing.T) {
	t.Parallel()

	badDER := []byte{0x00, 0x01, 0x02, 0x03}

	c := &ClientState{
		params:     ClientParams{InsecureSkipVerify: true},
		transcript: NewTranscript(),
	}

	_, _, err := parseAndVerifyLeaf(c, badDER)
	if err == nil {
		t.Fatal("parseAndVerifyLeaf with bad DER: expected error, got nil")
	}

	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention 'parse', got: %v", err)
	}
}

func TestParseAndVerifyLeaf_NonGOST_InsecureSkipVerify(t *testing.T) {
	t.Parallel()

	_, _, der := newTestECDSACertWithDER(t)

	c := &ClientState{
		params:     ClientParams{InsecureSkipVerify: true},
		transcript: NewTranscript(),
	}

	leaf, chains, err := parseAndVerifyLeaf(c, der)
	if err != nil {
		t.Fatalf("parseAndVerifyLeaf ECDSA InsecureSkipVerify: %v", err)
	}

	if leaf == nil {
		t.Error("leaf should be non-nil")
	}

	if chains != nil {
		t.Error("chains should be nil for InsecureSkipVerify")
	}
}

func TestParseAndVerifyLeaf_NonGOST_WithVerification(t *testing.T) {
	t.Parallel()

	// Create a self-signed cert that is its own root — stdlib verify should succeed.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "verify-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	c := &ClientState{
		params: ClientParams{
			InsecureSkipVerify: false,
			RootCAs:            pool,
			ServerName:         "test.example.com",
		},
		transcript: NewTranscript(),
	}

	leaf, chains, err := parseAndVerifyLeaf(c, der)
	if err != nil {
		t.Fatalf("parseAndVerifyLeaf with verification: %v", err)
	}

	if leaf == nil {
		t.Error("leaf should be non-nil")
	}

	if len(chains) == 0 {
		t.Error("chains should be non-empty for verified non-GOST cert")
	}
}

// -----------------------------------------------------------------------
// expandKeysManual — happy path and zero-length error
// -----------------------------------------------------------------------.

func TestExpandKeysManual_AES128GCM(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}

	for i := range clientRandom {
		clientRandom[i] = byte(i + 100)
		serverRandom[i] = byte(i + 200)
	}

	ivLen := suite.Cipher.FixedIVLen

	km, err := expandKeysManual(suite, masterSecret, clientRandom, serverRandom, ivLen)
	if err != nil {
		t.Fatalf("expandKeysManual AES-128-GCM: %v", err)
	}

	if len(km.ClientEncKey) != suite.Cipher.KeyLen {
		t.Errorf("ClientEncKey len: got %d, want %d", len(km.ClientEncKey), suite.Cipher.KeyLen)
	}

	if len(km.ServerEncKey) != suite.Cipher.KeyLen {
		t.Errorf("ServerEncKey len: got %d, want %d", len(km.ServerEncKey), suite.Cipher.KeyLen)
	}

	if len(km.ClientIV) != ivLen {
		t.Errorf("ClientIV len: got %d, want %d", len(km.ClientIV), ivLen)
	}

	if len(km.ServerIV) != ivLen {
		t.Errorf("ServerIV len: got %d, want %d", len(km.ServerIV), ivLen)
	}
}

func TestExpandKeysManual_Deterministic(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES256-SHA384")
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	// CBC: ivLen=0 override.
	km1, err := expandKeysManual(suite, masterSecret, clientRandom, serverRandom, 0)
	if err != nil {
		t.Fatalf("expandKeysManual #1: %v", err)
	}

	km2, err := expandKeysManual(suite, masterSecret, clientRandom, serverRandom, 0)
	if err != nil {
		t.Fatalf("expandKeysManual #2: %v", err)
	}

	if !bytes.Equal(km1.ClientEncKey, km2.ClientEncKey) {
		t.Error("expandKeysManual: not deterministic — ClientEncKey differs")
	}

	if !bytes.Equal(km1.ServerEncKey, km2.ServerEncKey) {
		t.Error("expandKeysManual: not deterministic — ServerEncKey differs")
	}
}

func TestExpandKeysManual_ZeroTotal_Returns_Error(t *testing.T) {
	t.Parallel()

	// A synthetic suite with zero-length keys: triggers errKeyExpansionZeroLocal.
	suite := &suites.Suite{
		ID:   0xFFFF,
		Name: "fake-zero-suite",
		KX:   suites.KexRSA,
		Cipher: suites.CipherSpec{
			Name:   "FAKE",
			KeyLen: 0,
		},
		MAC: suites.MACSpec{
			KeyLen: 0,
		},
		PRF: suites.PRFSpec{Hash: nil},
	}

	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	_, err := expandKeysManual(suite, masterSecret, clientRandom, serverRandom, 0)
	if err == nil {
		t.Fatal("expandKeysManual with zero total length: expected error, got nil")
	}

	if !errors.Is(err, errKeyExpansionZeroLocal) {
		t.Errorf("expected errKeyExpansionZeroLocal, got %v", err)
	}
}

// -----------------------------------------------------------------------
// sendCertificateVerify — unsupported key type branch
// -----------------------------------------------------------------------.

type unsupportedPrivKey struct{}

func TestSendCertificateVerify_UnsupportedKeyType(t *testing.T) {
	t.Parallel()

	layer, _ := makeRecordLayerWithCapture()

	c := &ClientState{
		params: ClientParams{
			Rand: rand.Reader,
			Certificates: []ClientCertificate{
				{PrivateKey: unsupportedPrivKey{}},
			},
		},
		layer:      layer,
		transcript: NewTranscript(),
	}

	alg := SigAndHash{Hash: sigHashByte, Sig: sigAlgRSA}

	err := c.sendCertificateVerify(alg)
	if err == nil {
		t.Fatal("sendCertificateVerify with unsupported key type: expected error, got nil")
	}

	if !errors.Is(err, errUnsupportedKeyType) {
		t.Errorf("expected errUnsupportedKeyType, got %v", err)
	}
}

func TestSendCertificateVerify_ECDSA(t *testing.T) {
	t.Parallel()

	ecKey, _, _ := newTestECDSACertWithDER(t)

	layer, w := makeRecordLayerWithCapture()

	tr := NewTranscript()
	tr.Write([]byte("ecdsa transcript data"))

	c := &ClientState{
		params:     ClientParams{Rand: rand.Reader, Certificates: []ClientCertificate{{PrivateKey: ecKey}}},
		layer:      layer,
		transcript: tr,
	}

	alg := SigAndHash{Hash: sigHashByte, Sig: sigAlgECDSA} // sha256+ecdsa.

	if err := c.sendCertificateVerify(alg); err != nil {
		t.Fatalf("sendCertificateVerify ECDSA: %v", err)
	}

	written := w.Bytes()
	if len(written) < 5 {
		t.Fatal("no output written")
	}

	payloadLen := int(written[3])<<8 | int(written[4])
	payload := written[5 : 5+payloadLen]

	msg, _, err := ParseMessage(payload)
	if err != nil {
		t.Fatalf("parse CertificateVerify: %v", err)
	}

	cvMsg, ok := msg.(*CertificateVerify)
	if !ok {
		t.Fatalf("expected *CertificateVerify, got %T", msg)
	}

	if cvMsg.Algorithm.Hash != sigHashByte || cvMsg.Algorithm.Sig != sigAlgECDSA {
		t.Errorf("algorithm: got {0x%02x,0x%02x}, want {0x04,0x03}", cvMsg.Algorithm.Hash, cvMsg.Algorithm.Sig)
	}

	// Verify the signature covers "ecdsa transcript data".
	h := sha256.Sum256([]byte("ecdsa transcript data"))
	if !ecdsa.VerifyASN1(&ecKey.PublicKey, h[:], cvMsg.Signature) {
		t.Error("ECDSA signature verification failed")
	}
}

// -----------------------------------------------------------------------
// buildEnvelope — correctness check
// -----------------------------------------------------------------------.

func TestBuildEnvelope_CorrectFormat(t *testing.T) {
	t.Parallel()

	body := []byte{0x01, 0x02, 0x03}
	env := buildEnvelope(TypeServerHello, body)

	if len(env) != 4+len(body) {
		t.Fatalf("envelope length: got %d, want %d", len(env), 4+len(body))
	}

	if env[0] != byte(TypeServerHello) {
		t.Errorf("type byte: got 0x%02x, want 0x%02x", env[0], TypeServerHello)
	}

	declaredLen := int(env[1])<<16 | int(env[2])<<8 | int(env[3])
	if declaredLen != len(body) {
		t.Errorf("declared length: got %d, want %d", declaredLen, len(body))
	}

	if !bytes.Equal(env[4:], body) {
		t.Errorf("body: got %x, want %x", env[4:], body)
	}
}

// -----------------------------------------------------------------------
// SelectClientSigAlg — ECDSA P-384 / unknown key type branches
// -----------------------------------------------------------------------.

func TestSelectClientSigAlg_ECDSA_P384(t *testing.T) {
	t.Parallel()

	privEC, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: privEC}},
		[]SigAndHash{{Hash: 0x05, Sig: 0x03}}, // sha384+ecdsa.
	)

	alg, ok := c.selectClientSigAlg()
	if !ok {
		t.Fatal("selectClientSigAlg: P-384 + sha384+ecdsa should match, got false")
	}

	if alg.Hash != 0x05 || alg.Sig != 0x03 {
		t.Errorf("alg: got {0x%02x,0x%02x}, want {0x05,0x03}", alg.Hash, alg.Sig)
	}
}

func TestSelectClientSigAlg_UnknownKeyType(t *testing.T) {
	t.Parallel()

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: unsupportedPrivKey{}}},
		[]SigAndHash{{Hash: 0x04, Sig: 0x01}},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg with unknown key type: expected false, got true")
	}
}
