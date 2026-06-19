//nolint:testpackage // white-box: exercises unexported parsers, verifiers and error sentinels
package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// TestVerifyECDHESKE_RejectsUnadvertisedSigAlg covers M2: the ServerKeyExchange
// signature algorithm must be one the client advertised. SHA-1 is not
// advertised, so an SKE that uses rsa_pkcs1_sha1 is rejected before the
// signature is even checked.
func TestVerifyECDHESKE_RejectsUnadvertisedSigAlg(t *testing.T) {
	t.Parallel()

	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	body := buildECDHESKEBody(t, priv, clientRandom, serverRandom)

	// Patch the (hash, sig) bytes to sha1+rsa (0x02, 0x01), which is not in
	// clientSigAlgsAdvertised. Layout: curve_type(1) named_curve(2) point_len(1)
	// point(point_len) hashAlg sigAlg ...
	algOff := 4 + int(body[3])

	body[algOff] = 0x02
	body[algOff+1] = 0x01

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	if _, err := c.verifyServerKeyExchange(body, cert); !errors.Is(err, errSKEUnadvertisedSigAlg) {
		t.Fatalf("expected errSKEUnadvertisedSigAlg, got %v", err)
	}
}

// TestParseServerHello_RejectsTrailingBytes covers L5: bytes after the extension
// block must be rejected, not silently ignored.
func TestParseServerHello_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	sh := &ServerHello{Version: tlsVersion12, CipherSuite: 0x002F}
	body := sh.Marshal() // no extensions -> no extension bytes.

	// Append an empty extension list (uint16 length = 0) followed by a stray byte.
	body = append(body, 0x00, 0x00, 0xFF)

	if _, err := parseServerHello(body); !errors.Is(err, errSHTrailingData) {
		t.Fatalf("expected errSHTrailingData, got %v", err)
	}
}

// TestParseCertificate_RejectsTrailingBytes covers L5/D1: bytes after the
// certificate_list must be rejected.
func TestParseCertificate_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	cert := &Certificate{RawCerts: [][]byte{{0x01, 0x02, 0x03}}}
	body := cert.Marshal()

	body = append(body, 0xAA) // stray byte after the certificate_list.

	if _, err := parseCertificate(body); !errors.Is(err, errCertTrailingData) {
		t.Fatalf("expected errCertTrailingData, got %v", err)
	}
}

// TestRecvServerHello_RejectsUnofferedExtension covers L6: a ServerHello carrying
// an extension the client did not offer must abort the handshake. Here the
// client offers no SNI (ServerName == ""), so a server_name extension in the
// ServerHello is un-offered.
func TestRecvServerHello_RejectsUnofferedExtension(t *testing.T) {
	t.Parallel()

	ids := AvailableSuites()
	if len(ids) == 0 {
		t.Fatal("no available suites")
	}

	suiteID := ids[0]

	suite, ok := suites.Lookup(suiteID)
	if !ok {
		t.Fatalf("suite 0x%04x not found", suiteID)
	}

	// ServerHello body with an (un-offered) empty server_name extension.
	shBody := serverHelloBytesWithExt(suiteID, extServerName, nil)
	rec := hsRecord(buildEnvelope(TypeServerHello, shBody))

	c := makeClientStateForFlight(t, rec, suite)

	c.params.OfferedSuites = []uint16{suiteID}
	c.params.ServerName = "" // no SNI offered -> server_name echo is un-offered.

	if err := c.recvServerHello(); !errors.Is(err, errSHUnofferedExt) {
		t.Fatalf("expected errSHUnofferedExt, got %v", err)
	}
}

// TestReadHandshakeRecord_RejectsInterleavedAlert covers M1's interleaving guard:
// a non-handshake record arriving while a handshake message is only partially
// buffered is a protocol violation (RFC 5246 §6.2.1).
func TestReadHandshakeRecord_RejectsInterleavedAlert(t *testing.T) {
	t.Parallel()

	// A Certificate message declaring a 6-byte body but carrying only 2.
	partial := hsRecord([]byte{0x0B, 0x00, 0x00, 0x06, 0xAA, 0xBB})
	// An alert record arriving before the message completes.
	alertRec := []byte{record.ContentTypeAlert, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

	stream := append(partial, alertRec...)

	rw := &readWriteBuffer{r: bytes.NewBuffer(stream), w: new(bytes.Buffer)}
	c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

	if _, _, err := c.readHandshakeRecord(); !errors.Is(err, errInterleavedHandshake) {
		t.Fatalf("expected errInterleavedHandshake, got %v", err)
	}
}

// TestParseAndVerifyChain_UsesWireIntermediates covers L4: the intermediate
// certificate the server sends after the leaf must be used to bridge the leaf to
// a trusted root. Verification succeeds with the intermediate present and fails
// when only the leaf is supplied.
func TestParseAndVerifyChain_UsesWireIntermediates(t *testing.T) {
	t.Parallel()

	rootDER, interDER, leafDER, rootCert := genECDSAChain(t)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	c := &ClientState{
		params:     ClientParams{RootCAs: rootPool, ServerName: "leaf.example.com"},
		transcript: NewTranscript(),
	}

	// Leaf + intermediate on the wire: the chain bridges to the root.
	_, chains, err := parseAndVerifyChain(c, [][]byte{leafDER, interDER})
	if err != nil {
		t.Fatalf("verify with wire intermediate: %v", err)
	}

	if len(chains) == 0 {
		t.Error("expected a non-empty verified chain")
	}

	// Leaf alone: no path to the root, so verification must fail.
	if _, _, err := parseAndVerifyChain(c, [][]byte{leafDER}); err == nil {
		t.Fatal("verify without intermediate: expected error, got nil")
	}

	_ = rootDER
}

// serverHelloBytesWithExt builds a ServerHello body carrying a single extension.
func serverHelloBytesWithExt(suiteID, extType uint16, extBody []byte) []byte {
	var b []byte

	b = appendUint16(b, tlsVersion12)
	b = append(b, make([]byte, tlsRandomLen)...)
	b = append(b, 0x00) // session_id length = 0.
	b = appendUint16(b, suiteID)
	b = append(b, 0x00) // compression = null.

	var ext []byte

	ext = appendUint16(ext, extType)
	ext = appendUint16(ext, uint16(len(extBody)))
	ext = append(ext, extBody...)

	b = appendUint16(b, uint16(len(ext)))
	b = append(b, ext...)

	return b
}

// genECDSAChain creates a root CA, an intermediate CA signed by the root, and a
// leaf signed by the intermediate (SAN leaf.example.com, server-auth EKU). It
// returns the DER for root, intermediate and leaf plus the parsed root.
func genECDSAChain(t *testing.T) (rootDER, interDER, leafDER []byte, rootCert *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("intermediate key: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}

	now := time.Now()

	caTmpl := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}

	rootTmpl := caTmpl(1, "root")

	rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}

	rootCert, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	interTmpl := caTmpl(2, "intermediate")

	interDER, err = x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}

	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}

	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	return rootDER, interDER, leafDER, rootCert
}
