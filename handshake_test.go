package gostls_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bigbes/gostls"
	"github.com/bigbes/gostls/internal/ke"
	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// ============================================================================
// Test fixture generation — cached per test binary.
// ============================================================================

var (
	testCACert    *x509.Certificate
	testCAKey     *rsa.PrivateKey
	testCACertPEM []byte

	testServerCert    *x509.Certificate
	testServerKey     *rsa.PrivateKey
	testServerCertDER []byte

	testFixtureOnce sync.Once
)

func initTestFixtures(t *testing.T) {
	t.Helper()
	testFixtureOnce.Do(func() {
		// Generate RSA-2048 root CA.
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate CA key: %v", err)
		}
		testCAKey = caKey

		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create CA cert: %v", err)
		}
		testCACert, err = x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatalf("parse CA cert: %v", err)
		}
		testCACertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

		// Generate RSA-2048 server certificate signed by the CA.
		serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate server key: %v", err)
		}
		testServerKey = serverKey

		serverTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "test.example.com"},
			DNSNames:     []string{"test.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, testCACert, &serverKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create server cert: %v", err)
		}
		testServerCertDER = serverDER
		testServerCert, err = x509.ParseCertificate(serverDER)
		if err != nil {
			t.Fatalf("parse server cert: %v", err)
		}
	})
}

// rootCAsForTest builds a cert pool containing the test CA.
func rootCAsForTest(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(testCACertPEM) {
		t.Fatal("failed to add test CA to cert pool")
	}
	return pool
}

// ============================================================================
// hashAccumulator tracks handshake transcript bytes with a given hash function.
// ============================================================================

type hashAccumulator struct {
	h hash.Hash
}

func newHashAccumulator(newHash func() hash.Hash) *hashAccumulator {
	return &hashAccumulator{h: newHash()}
}

func (a *hashAccumulator) Write(msg []byte) {
	a.h.Write(msg)
}

func (a *hashAccumulator) Sum() []byte {
	return a.h.Sum(nil)
}

// ============================================================================
// scripted server helper
// ============================================================================

type scriptedServer struct {
	layer *record.Layer
	t     *testing.T
}

func newScriptedServer(t *testing.T, conn net.Conn) *scriptedServer {
	t.Helper()
	return &scriptedServer{
		layer: record.NewLayer(conn),
		t:     t,
	}
}

// readClientHello reads a ClientHello record and returns the full 4-byte-enveloped payload.
func (s *scriptedServer) readClientHello() []byte {
	s.t.Helper()
	ct, payload, err := s.layer.ReadRecord()
	if err != nil {
		s.t.Fatalf("scripted server: read ClientHello: %v", err)
	}
	if ct != record.ContentTypeHandshake {
		s.t.Fatalf("scripted server: expected handshake record, got %d", ct)
	}
	if len(payload) < 4 || payload[0] != 1 {
		s.t.Fatalf("scripted server: expected ClientHello (1), got %d", payload[0])
	}
	return payload
}

// writeHandshake sends the pre-built 4-byte-enveloped handshake message.
func (s *scriptedServer) writeHandshake(msg []byte) {
	s.t.Helper()
	if err := s.layer.WriteRecord(record.ContentTypeHandshake, msg); err != nil {
		s.t.Fatalf("scripted server: write handshake record: %v", err)
	}
}

// writeCCS sends a ChangeCipherSpec record.
func (s *scriptedServer) writeCCS() {
	s.t.Helper()
	if err := s.layer.WriteRecord(record.ContentTypeChangeCipherSpec, []byte{1}); err != nil {
		s.t.Fatalf("scripted server: write CCS: %v", err)
	}
}

// readHandshakeMessage reads the next handshake record.
// Returns msgType and body (without 4-byte envelope), and the full envelope.
func (s *scriptedServer) readHandshakeMessage() (msgType uint8, body []byte, envelope []byte) {
	s.t.Helper()
	ct, payload, err := s.layer.ReadRecord()
	if err != nil {
		s.t.Fatalf("scripted server: read record: %v", err)
	}
	if ct != record.ContentTypeHandshake {
		s.t.Fatalf("scripted server: expected handshake, got content type %d", ct)
	}
	if len(payload) < 4 {
		s.t.Fatalf("scripted server: handshake record too short")
	}
	msgType = payload[0]
	bodyLen := uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	if uint32(len(payload)) < 4+bodyLen {
		s.t.Fatalf("scripted server: body truncated")
	}
	return msgType, payload[4 : 4+bodyLen], payload[:4+bodyLen]
}

// readCCS reads and validates a ChangeCipherSpec from the client.
func (s *scriptedServer) readCCS() {
	s.t.Helper()
	ct, payload, err := s.layer.ReadRecord()
	if err != nil {
		s.t.Fatalf("scripted server: read CCS: %v", err)
	}
	if ct != record.ContentTypeChangeCipherSpec {
		s.t.Fatalf("scripted server: expected CCS, got %d", ct)
	}
	if len(payload) != 1 || payload[0] != 1 {
		s.t.Fatalf("scripted server: malformed CCS")
	}
}

// ============================================================================
// Handshake message builders.
// ============================================================================

func buildServerHello(random [32]byte, suiteID uint16) []byte {
	var body []byte
	body = appendUint16(body, 0x0303)
	body = append(body, random[:]...)
	body = append(body, 0x00)          // session_id length = 0
	body = appendUint16(body, suiteID) // cipher_suite
	body = append(body, 0x00)          // compression_method = null
	// renegotiation_info extension (RFC 5746): type=0xFF01, len=1, body={0x00}.
	extBody := []byte{0x00}
	ext := marshalExt(0xFF01, extBody)
	extList := appendUint16(nil, uint16(len(ext)))
	extList = append(extList, ext...)
	body = append(body, extList...)
	return wrapHS(2, body)
}

func buildCertificate(derCerts [][]byte) []byte {
	innerLen := 0
	for _, c := range derCerts {
		innerLen += 3 + len(c)
	}
	body := appendUint24(nil, uint32(innerLen))
	for _, c := range derCerts {
		body = appendUint24(body, uint32(len(c)))
		body = append(body, c...)
	}
	return wrapHS(11, body)
}

func buildServerHelloDone() []byte {
	return wrapHS(14, nil)
}

// wrapHS wraps body in the 4-byte handshake envelope.
func wrapHS(msgType uint8, body []byte) []byte {
	env := make([]byte, 4+len(body))
	env[0] = msgType
	env[1] = byte(len(body) >> 16)
	env[2] = byte(len(body) >> 8)
	env[3] = byte(len(body))
	copy(env[4:], body)
	return env
}

func appendUint16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func appendUint24(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>16), byte(v>>8), byte(v))
}

func marshalExt(extType uint16, body []byte) []byte {
	out := appendUint16(nil, extType)
	out = appendUint16(out, uint16(len(body)))
	return append(out, body...)
}

func appendU16LenPrefixed(dst, data []byte) []byte {
	dst = appendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}

// buildECDHEServerKeyExchange builds a ServerKeyExchange for ECDHE-RSA with P-256.
func buildECDHEServerKeyExchange(
	serverECPub []byte,
	clientRandom, serverRandom [32]byte,
	signerKey *rsa.PrivateKey,
) []byte {
	// ServerECDHParams: curve_type=3, named_curve=0x0017 (P-256), public.
	params := []byte{0x03, 0x00, 0x17}
	params = append(params, byte(len(serverECPub)))
	params = append(params, serverECPub...)

	// Signature covers: clientRandom || serverRandom || ServerECDHParams.
	signed := make([]byte, 0, 32+32+len(params))
	signed = append(signed, clientRandom[:]...)
	signed = append(signed, serverRandom[:]...)
	signed = append(signed, params...)

	h := sha256.Sum256(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, signerKey, crypto.SHA256, h[:])
	if err != nil {
		panic(fmt.Sprintf("buildECDHEServerKeyExchange: sign: %v", err))
	}

	body := append([]byte{}, params...)
	body = append(body, 0x04, 0x01) // sha256, rsa
	body = appendUint16(body, uint16(len(sig)))
	body = append(body, sig...)
	return wrapHS(12, body)
}

// buildDHEServerKeyExchange builds a ServerKeyExchange for DHE-RSA with ffdhe2048.
func buildDHEServerKeyExchange(
	pBytes, gBytes, YsBytes []byte,
	clientRandom, serverRandom [32]byte,
	signerKey *rsa.PrivateKey,
) []byte {
	var dhParams []byte
	dhParams = appendU16LenPrefixed(dhParams, pBytes)
	dhParams = appendU16LenPrefixed(dhParams, gBytes)
	dhParams = appendU16LenPrefixed(dhParams, YsBytes)

	signed := make([]byte, 0, 32+32+len(dhParams))
	signed = append(signed, clientRandom[:]...)
	signed = append(signed, serverRandom[:]...)
	signed = append(signed, dhParams...)

	h := sha256.Sum256(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, signerKey, crypto.SHA256, h[:])
	if err != nil {
		panic(fmt.Sprintf("buildDHEServerKeyExchange: sign: %v", err))
	}

	body := append([]byte{}, dhParams...)
	body = append(body, 0x04, 0x01)
	body = appendUint16(body, uint16(len(sig)))
	body = append(body, sig...)
	return wrapHS(12, body)
}

func buildServerFinished(suite *suites.Suite, masterSecret, transcriptHash []byte) []byte {
	verifyData, err := suites.FinishedVerifyData(suite, masterSecret, "server finished", transcriptHash)
	if err != nil {
		panic(fmt.Sprintf("buildServerFinished: %v", err))
	}
	body := make([]byte, 12)
	copy(body, verifyData)
	return wrapHS(20, body)
}

// ============================================================================
// ffdhe2048 constants for DHE tests.
// ============================================================================

var ffdhe2048P = mustDecodeHex(
	"FFFFFFFFFFFFFFFF" +
		"ADF85458A2BB4A9A" +
		"AFDC5620273D3CF1" +
		"D8B9C583CE2D3695" +
		"A9E13641146433FB" +
		"CC939DCE249B3EF9" +
		"7D2FE363630C75D8" +
		"F681B202AEC4617A" +
		"D3DF1ED5D5FD6561" +
		"2433F51F5F066ED0" +
		"856365553DED1AF3" +
		"B557135E7F57C935" +
		"984F0C70E0E68B77" +
		"E2A689DAF3EFE872" +
		"1DF158A136ADE735" +
		"30ACCA4F483A797A" +
		"BC0AB182B324FB61" +
		"D108A94BB2C8E3FB" +
		"B96ADAB760D7F468" +
		"1D4F42A3DE394DF4" +
		"AE56EDE76372BB19" +
		"0B07A7C8EE0A6D70" +
		"9E02FCE1CDF7E2EC" +
		"C03405CD28342F61" +
		"9172FE9CE98583FF" +
		"8E4F1232EEF28183" +
		"C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005" +
		"C58EF1837D1683B2" +
		"C6F34A26C1B2EFFA" +
		"886B423861285C97" +
		"FFFFFFFFFFFFFFFF",
)
var ffdhe2048G = []byte{0x02}

func mustDecodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		hi := hexNibble(s[2*i])
		lo := hexNibble(s[2*i+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		panic(fmt.Sprintf("invalid hex nibble %q", c))
	}
}

// ============================================================================
// Key material helpers for the server side.
// ============================================================================

func expandKeysForTest(suite *suites.Suite, masterSecret, clientRandom, serverRandom []byte, ivLen int) (*suites.KeyMaterial, error) {
	seed := make([]byte, 64)
	copy(seed[:32], serverRandom)
	copy(seed[32:], clientRandom)

	macKeyLen := suite.MAC.KeyLen
	encKeyLen := suite.Cipher.KeyLen
	totalLen := 2*macKeyLen + 2*encKeyLen + 2*ivLen
	if totalLen == 0 {
		return nil, fmt.Errorf("key block length is zero")
	}

	keyBlock, err := suites.PRF(suite.PRF.Hash, masterSecret, []byte("key expansion"), seed, totalLen)
	if err != nil {
		return nil, err
	}

	km := &suites.KeyMaterial{}
	off := 0
	if macKeyLen > 0 {
		km.ClientMACKey = keyBlock[off : off+macKeyLen]
		off += macKeyLen
		km.ServerMACKey = keyBlock[off : off+macKeyLen]
		off += macKeyLen
	}
	km.ClientEncKey = keyBlock[off : off+encKeyLen]
	off += encKeyLen
	km.ServerEncKey = keyBlock[off : off+encKeyLen]
	off += encKeyLen
	if ivLen > 0 {
		km.ClientIV = keyBlock[off : off+ivLen]
		off += ivLen
		km.ServerIV = keyBlock[off : off+ivLen]
	}
	return km, nil
}

func buildProtectorForTest(suite *suites.Suite, encKey, macKey, iv []byte) (record.Protector, error) {
	if suite.Cipher.AEAD {
		return record.NewAEADProtector(encKey, iv)
	}
	var newHash record.NewHashFunc
	switch suite.MAC.MACLen {
	case 20:
		newHash = record.SHA1Hash
	case 32:
		newHash = record.SHA256Hash
	case 48:
		newHash = record.SHA384Hash
	default:
		return nil, fmt.Errorf("unsupported MAC len %d", suite.MAC.MACLen)
	}
	return record.NewCBCHMACProtector(record.NewAESCipher, newHash, encKey, macKey)
}

// ============================================================================
// serverHandshakeRunner drives the scripted server through the full handshake.
// ============================================================================

// serverRunner holds all the state needed to script the server side.
type serverRunner struct {
	t            *testing.T
	srv          *scriptedServer
	suite        *suites.Suite
	tr           *hashAccumulator
	masterSecret []byte
	km           *suites.KeyMaterial
}

func newServerRunner(t *testing.T, srv *scriptedServer, suite *suites.Suite) *serverRunner {
	t.Helper()
	return &serverRunner{
		t:     t,
		srv:   srv,
		suite: suite,
		tr:    newHashAccumulator(suite.PRF.Hash),
	}
}

// runHandshakeUntilAppData runs the full server-side handshake.
// Returns clientRandom extracted from the ClientHello.
func (r *serverRunner) runFullHandshake(serverRandom [32]byte) {
	r.t.Helper()
	suite := r.suite

	// Read ClientHello.
	chEnv := r.srv.readClientHello()
	r.tr.Write(chEnv)
	var clientRandom [32]byte
	copy(clientRandom[:], chEnv[6:38]) // 4-byte envelope + 2-byte version

	// Send ServerHello.
	sh := buildServerHello(serverRandom, suite.ID)
	r.tr.Write(sh)
	r.srv.writeHandshake(sh)

	// Send Certificate.
	cert := buildCertificate([][]byte{testServerCertDER})
	r.tr.Write(cert)
	r.srv.writeHandshake(cert)

	// Suite-specific ServerKeyExchange.
	var preMaster []byte
	switch suite.KX {
	case suites.KexECDHE:
		preMaster = r.doECDHE(clientRandom, serverRandom)
	case suites.KexDHE:
		preMaster = r.doDHE(clientRandom, serverRandom)
	case suites.KexRSA:
		preMaster = r.doRSAKx()
	default:
		r.t.Fatalf("serverRunner: unknown KX kind %d", suite.KX)
	}

	// Derive master secret + key material.
	var err error
	r.masterSecret, err = suites.MasterSecret(suite, preMaster, clientRandom[:], serverRandom[:])
	if err != nil {
		r.t.Fatalf("serverRunner: master secret: %v", err)
	}

	ivLen := 0
	if suite.Cipher.AEAD {
		ivLen = suite.Cipher.FixedIVLen
	}
	r.km, err = expandKeysForTest(suite, r.masterSecret, clientRandom[:], serverRandom[:], ivLen)
	if err != nil {
		r.t.Fatalf("serverRunner: key expansion: %v", err)
	}

	// Read client CCS.
	r.srv.readCCS()

	// Install server recv protector (= client write keys).
	recvProt, err := buildProtectorForTest(suite, r.km.ClientEncKey, r.km.ClientMACKey, r.km.ClientIV)
	if err != nil {
		r.t.Fatalf("serverRunner: recv protector: %v", err)
	}
	r.srv.layer.ChangeCipherSpec(nil, recvProt)

	// Read client Finished (now encrypted).
	// Per RFC 5246 §7.4.9, server Finished covers all messages including client Finished.
	finType, _, finEnv := r.srv.readHandshakeMessage()
	if finType != 20 {
		r.t.Fatalf("serverRunner: expected Finished (20), got %d", finType)
	}
	// Add client Finished to transcript so server Finished verify_data matches.
	r.tr.Write(finEnv)

	// Send server CCS.
	r.srv.writeCCS()

	// Install server send protector (= server write keys).
	sendProt, err := buildProtectorForTest(suite, r.km.ServerEncKey, r.km.ServerMACKey, r.km.ServerIV)
	if err != nil {
		r.t.Fatalf("serverRunner: send protector: %v", err)
	}
	r.srv.layer.ChangeCipherSpec(sendProt, nil)

	// Send server Finished.
	serverTranscriptHash := r.tr.Sum()
	serverFinished := buildServerFinished(suite, r.masterSecret, serverTranscriptHash)
	r.srv.writeHandshake(serverFinished)
}

func (r *serverRunner) doECDHE(clientRandom, serverRandom [32]byte) []byte {
	r.t.Helper()
	serverECPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		r.t.Fatalf("doECDHE: generate key: %v", err)
	}
	serverECPub := serverECPriv.PublicKey().Bytes()

	ske := buildECDHEServerKeyExchange(serverECPub, clientRandom, serverRandom, testServerKey)
	r.tr.Write(ske)
	r.srv.writeHandshake(ske)

	shd := buildServerHelloDone()
	r.tr.Write(shd)
	r.srv.writeHandshake(shd)

	// Read CKE.
	ckeType, ckeBody, ckeEnv := r.srv.readHandshakeMessage()
	if ckeType != 16 {
		r.t.Fatalf("doECDHE: expected CKE (16), got %d", ckeType)
	}
	r.tr.Write(ckeEnv)

	if len(ckeBody) < 1 {
		r.t.Fatalf("doECDHE: CKE too short")
	}
	clientPubLen := int(ckeBody[0])
	if len(ckeBody) < 1+clientPubLen {
		r.t.Fatalf("doECDHE: CKE truncated")
	}
	clientPub, err := ecdh.P256().NewPublicKey(ckeBody[1 : 1+clientPubLen])
	if err != nil {
		r.t.Fatalf("doECDHE: parse client pub: %v", err)
	}
	preMaster, err := serverECPriv.ECDH(clientPub)
	if err != nil {
		r.t.Fatalf("doECDHE: ECDH: %v", err)
	}
	return preMaster
}

func (r *serverRunner) doDHE(clientRandom, serverRandom [32]byte) []byte {
	r.t.Helper()
	serverPrivX := make([]byte, len(ffdhe2048P))
	if _, err := rand.Read(serverPrivX); err != nil {
		r.t.Fatalf("doDHE: generate private exponent: %v", err)
	}
	serverYs, err := ke.DHEComputePublic(ffdhe2048P, ffdhe2048G, serverPrivX)
	if err != nil {
		r.t.Fatalf("doDHE: compute Ys: %v", err)
	}

	ske := buildDHEServerKeyExchange(ffdhe2048P, ffdhe2048G, serverYs, clientRandom, serverRandom, testServerKey)
	r.tr.Write(ske)
	r.srv.writeHandshake(ske)

	shd := buildServerHelloDone()
	r.tr.Write(shd)
	r.srv.writeHandshake(shd)

	// Read CKE.
	ckeType, ckeBody, ckeEnv := r.srv.readHandshakeMessage()
	if ckeType != 16 {
		r.t.Fatalf("doDHE: expected CKE (16), got %d", ckeType)
	}
	r.tr.Write(ckeEnv)

	if len(ckeBody) < 2 {
		r.t.Fatalf("doDHE: CKE too short")
	}
	ycLen := int(binary.BigEndian.Uint16(ckeBody[:2]))
	if len(ckeBody) < 2+ycLen {
		r.t.Fatalf("doDHE: CKE truncated")
	}
	YcBytes := ckeBody[2 : 2+ycLen]

	// Compute Z = Yc^serverPrivX mod p.
	preMaster, err := ke.DHEComputePublic(ffdhe2048P, YcBytes, serverPrivX)
	if err != nil {
		r.t.Fatalf("doDHE: compute shared secret: %v", err)
	}
	return preMaster
}

func (r *serverRunner) doRSAKx() []byte {
	r.t.Helper()
	shd := buildServerHelloDone()
	r.tr.Write(shd)
	r.srv.writeHandshake(shd)

	// Read CKE — encrypted pre-master secret.
	ckeType, ckeBody, ckeEnv := r.srv.readHandshakeMessage()
	if ckeType != 16 {
		r.t.Fatalf("doRSAKx: expected CKE (16), got %d", ckeType)
	}
	r.tr.Write(ckeEnv)

	// Per RFC 5246 §7.4.7.1, ckeBody = uint16 length prefix || ciphertext.
	if len(ckeBody) < 2 {
		r.t.Fatalf("doRSAKx: CKE body too short: %d bytes", len(ckeBody))
	}
	prefixLen := int(ckeBody[0])<<8 | int(ckeBody[1])
	if len(ckeBody) != 2+prefixLen {
		r.t.Fatalf("doRSAKx: CKE length prefix=%d, body len=%d, want %d", prefixLen, len(ckeBody), 2+prefixLen)
	}
	ciphertext := ckeBody[2:]

	preMaster, err := rsa.DecryptPKCS1v15(rand.Reader, testServerKey, ciphertext)
	if err != nil {
		r.t.Fatalf("doRSAKx: decrypt pre-master: %v", err)
	}
	if len(preMaster) != 48 || preMaster[0] != 0x03 || preMaster[1] != 0x03 {
		r.t.Fatalf("doRSAKx: bad pre-master format: len=%d", len(preMaster))
	}
	return preMaster
}

// ============================================================================
// runHandshakeTest is the shared orchestrator for basic handshake tests.
// ============================================================================

func runHandshakeTest(t *testing.T, suiteName string) (*gostls.Conn, func()) {
	t.Helper()
	initTestFixtures(t)

	suite, ok := suites.LookupByName(suiteName)
	if !ok {
		t.Fatalf("suite %q not registered", suiteName)
	}

	clientConn, serverConn := net.Pipe()

	var serverRandom [32]byte
	serverRandom[0] = 0xDE
	serverRandom[1] = 0xAD

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		defer func() {
			if r := recover(); r != nil {
				serverDone <- fmt.Errorf("server panic: %v", r)
			}
		}()
		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)
		runner.runFullHandshake(serverRandom)
		serverDone <- nil
	}()

	config := &gostls.Config{
		ServerName:         "test.example.com",
		RootCAs:            rootCAsForTest(t),
		InsecureSkipVerify: false,
	}
	tlsConn := gostls.NewConn(clientConn, config)

	cleanup := func() {
		clientConn.Close()
		serverConn.Close()
		if err := <-serverDone; err != nil {
			t.Errorf("server error: %v", err)
		}
	}

	return tlsConn, cleanup
}

// ============================================================================
// Tests
// ============================================================================

func TestClient_Handshake_ECDHE_GCM(t *testing.T) {
	tlsConn, cleanup := runHandshakeTest(t, "ECDHE-RSA-AES128-GCM-SHA256")
	defer cleanup()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	t.Log("ECDHE-RSA-AES128-GCM-SHA256 handshake succeeded")
}

func TestClient_Handshake_DHE_CBC(t *testing.T) {
	tlsConn, cleanup := runHandshakeTest(t, "DHE-RSA-AES256-SHA256")
	defer cleanup()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	t.Log("DHE-RSA-AES256-SHA256 handshake succeeded")
}

func TestClient_Handshake_RSA_kx(t *testing.T) {
	tlsConn, cleanup := runHandshakeTest(t, "AES256-GCM-SHA384")
	defer cleanup()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	t.Log("AES256-GCM-SHA384 handshake succeeded")
}

func TestClient_Handshake_ECDHE_CBC(t *testing.T) {
	tlsConn, cleanup := runHandshakeTest(t, "ECDHE-RSA-AES128-SHA256")
	defer cleanup()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	t.Log("ECDHE-RSA-AES128-SHA256 handshake succeeded")
}

func TestClient_Handshake_GOST(t *testing.T) {
	// Phase 6/7/8 landed the GOST suites, VKO kx, IMIT/CNT record protector,
	// and x509gost parse/verify. The handshake wiring (cert path) now also
	// routes GOST-signed certs through x509gost (always compiled in).
	// What's still needed to make this a real end-to-end test:
	//   1. Scripted GOST server (new serverRunner variant that speaks GOST PRF,
	//      IMIT MAC, CNT cipher, and GOST-VKO key agreement — the fixtures for
	//      these live in tls/internal/{suites,ke,record}, but no server driver
	//      composes them yet).
	//   2. GOST CA + server cert fixtures (x509gost/certbuilder_test.go can
	//      produce these but they are package-internal to x509gost today).
	//   3. ClientParams.GOSTRoots wired through Config.GOSTRoots.
	// These depend on Phase-10 live capture to lock in wire formats, so keep
	// the skip for now.
	t.Skip("deferred: needs scripted GOST server + GOST cert fixtures (Phase 10)")
}

func TestClient_RejectsUnknownCipher(t *testing.T) {
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var serverRandom [32]byte
	// 0x00FF is not in our offered cipher suites.
	unknownSuiteID := uint16(0x00FF)

	go func() {
		defer serverConn.Close()
		srv := newScriptedServer(t, serverConn)
		_ = srv.readClientHello()
		sh := buildServerHello(serverRandom, unknownSuiteID)
		srv.writeHandshake(sh)
		// Drain any alert the client may send.
		serverConn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 256)
		serverConn.Read(buf) //nolint:errcheck
	}()

	config := &gostls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true,
	}
	tlsConn := gostls.NewConn(clientConn, config)
	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected handshake to fail for unknown cipher suite, got nil")
	}
	t.Logf("correctly rejected unknown cipher: %v", err)
}

func TestClient_RejectsBadFinished(t *testing.T) {
	initTestFixtures(t)

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("suite not found")
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var serverRandom [32]byte
	serverRandom[0] = 0xBE

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)

		// Run handshake partially — up to and including client Finished.
		suite := runner.suite

		chEnv := srv.readClientHello()
		runner.tr.Write(chEnv)
		var clientRandom [32]byte
		copy(clientRandom[:], chEnv[6:38])

		sh := buildServerHello(serverRandom, suite.ID)
		runner.tr.Write(sh)
		srv.writeHandshake(sh)

		cert := buildCertificate([][]byte{testServerCertDER})
		runner.tr.Write(cert)
		srv.writeHandshake(cert)

		preMaster := runner.doECDHE(clientRandom, serverRandom)

		var err error
		runner.masterSecret, err = suites.MasterSecret(suite, preMaster, clientRandom[:], serverRandom[:])
		if err != nil {
			serverDone <- err
			return
		}

		ivLen := suite.Cipher.FixedIVLen
		runner.km, err = expandKeysForTest(suite, runner.masterSecret, clientRandom[:], serverRandom[:], ivLen)
		if err != nil {
			serverDone <- err
			return
		}

		srv.readCCS()

		recvProt, err := buildProtectorForTest(suite, runner.km.ClientEncKey, runner.km.ClientMACKey, runner.km.ClientIV)
		if err != nil {
			serverDone <- err
			return
		}
		srv.layer.ChangeCipherSpec(nil, recvProt)
		srv.readHandshakeMessage() // client Finished

		srv.writeCCS()

		sendProt, err := buildProtectorForTest(suite, runner.km.ServerEncKey, runner.km.ServerMACKey, runner.km.ServerIV)
		if err != nil {
			serverDone <- err
			return
		}
		srv.layer.ChangeCipherSpec(sendProt, nil)

		// Send a Finished with wrong verify_data (all zeros instead of correct value).
		badFinished := make([]byte, 12) // all zeros = wrong
		srv.writeHandshake(wrapHS(20, badFinished))

		serverDone <- nil
	}()

	config := &gostls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true,
	}
	tlsConn := gostls.NewConn(clientConn, config)
	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected handshake to fail for bad server Finished, got nil")
	}
	t.Logf("correctly rejected bad server Finished: %v", err)

	if serverErr := <-serverDone; serverErr != nil {
		t.Errorf("server error: %v", serverErr)
	}
}

func TestClient_RejectsBadCert(t *testing.T) {
	initTestFixtures(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("suite not found")
	}

	var serverRandom [32]byte

	go func() {
		defer serverConn.Close()
		srv := newScriptedServer(t, serverConn)
		_ = srv.readClientHello()

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)

		// Generate and send an untrusted self-signed cert.
		untrustedKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "untrusted.example.com"},
			DNSNames:     []string{"test.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &untrustedKey.PublicKey, untrustedKey)
		cert := buildCertificate([][]byte{certDER})
		srv.writeHandshake(cert)

		// Drain client's fatal alert.
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		serverConn.Read(buf) //nolint:errcheck
	}()

	// Pool trusts only our test CA — the self-signed cert above is not trusted.
	config := &gostls.Config{
		ServerName:         "test.example.com",
		RootCAs:            rootCAsForTest(t),
		InsecureSkipVerify: false,
	}
	tlsConn := gostls.NewConn(clientConn, config)
	err := tlsConn.Handshake()
	if err == nil {
		t.Fatal("expected handshake to fail for untrusted cert, got nil")
	}
	t.Logf("correctly rejected bad certificate: %v", err)
}

func TestClient_Handshake_ApplicationData_RoundTrip(t *testing.T) {
	initTestFixtures(t)

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("suite not found")
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var serverRandom [32]byte
	serverRandom[0] = 0xCA

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)
		runner.runFullHandshake(serverRandom)

		// Echo back whatever the client sends.
		ct, payload, err := srv.layer.ReadRecord()
		if err != nil {
			serverDone <- fmt.Errorf("server: read app data: %v", err)
			return
		}
		if ct != record.ContentTypeApplicationData {
			serverDone <- fmt.Errorf("server: expected app data, got %d", ct)
			return
		}
		if err := srv.layer.WriteRecord(record.ContentTypeApplicationData, payload); err != nil {
			serverDone <- fmt.Errorf("server: echo: %v", err)
			return
		}
		serverDone <- nil
	}()

	config := &gostls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true,
	}
	tlsConn := gostls.NewConn(clientConn, config)

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	want := []byte("hello")
	if _, err := tlsConn.Write(want); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := tlsConn.Read(got); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, want)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestClient_Close_SendsCloseNotify(t *testing.T) {
	initTestFixtures(t)

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("suite not found")
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var serverRandom [32]byte
	serverRandom[0] = 0xAA

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)
		runner.runFullHandshake(serverRandom)

		// Expect a close_notify alert.
		ct, payload, err := srv.layer.ReadRecord()
		if err != nil {
			serverDone <- fmt.Errorf("server: read close_notify: %v", err)
			return
		}
		if ct != record.ContentTypeAlert {
			serverDone <- fmt.Errorf("server: expected alert record, got %d", ct)
			return
		}
		if len(payload) < 2 {
			serverDone <- fmt.Errorf("server: alert too short")
			return
		}
		_, desc := record.DecodeAlert(payload)
		if desc != record.AlertCloseNotify {
			serverDone <- fmt.Errorf("server: expected close_notify (%d), got desc=%d",
				record.AlertCloseNotify, desc)
			return
		}
		serverDone <- nil
	}()

	config := &gostls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true,
	}
	tlsConn := gostls.NewConn(clientConn, config)

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if err := tlsConn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// TestFixture_StdlibTLSAcceptsTestCert sanity-checks that our test CA and
// server cert work with stdlib crypto/tls.
func TestFixture_StdlibTLSAcceptsTestCert(t *testing.T) {
	initTestFixtures(t)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{testServerCertDER},
		PrivateKey:  testServerKey,
	}
	server := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
		done <- nil
	}()

	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(testCACertPEM)
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs:    clientPool,
		ServerName: "test.example.com",
		MaxVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("stdlib TLS dial: %v", err)
	}
	client.Close()
	<-done
}
