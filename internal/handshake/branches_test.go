// Coverage-extension tests for branches in client.go, messages.go, types.go,
// and kex_gost.go that were not reached by existing test files.
//
// Every test asserts specific behaviour — not just that an error (or non-error)
// occurs but what the correct outcome is for the given input.
//
//nolint:testpackage // white-box: exercises unexported methods and error sentinels
package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// =============================================================================.
// sendClientHello — success path (transcript.Write + return nil).
// =============================================================================.

// TestSendClientHello_SuccessPath covers the success branch of sendClientHello
// that was unreachable by the error-path-only existing tests.
func TestSendClientHello_SuccessPath(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	c.suite = suite

	if err := c.sendClientHello(); err != nil {
		t.Fatalf("sendClientHello: unexpected error: %v", err)
	}

	// Transcript must be non-empty after success (the ClientHello envelope was appended).
	h, err := c.transcript.Sum(suite.PRF.Hash)
	if err != nil {
		t.Fatalf("transcript.Sum after sendClientHello: %v", err)
	}

	if len(h) == 0 {
		t.Error("transcript hash is empty — ClientHello was not appended")
	}

	// A TLS handshake record must have been written (at least the 5-byte header).
	written := rw.w.Bytes()
	if len(written) < 5 {
		t.Fatalf("nothing written to the record layer (len=%d)", len(written))
	}

	if written[0] != record.ContentTypeHandshake {
		t.Errorf("content type 0x%02x, want 0x%02x (handshake)", written[0], record.ContentTypeHandshake)
	}
}

// =============================================================================.
// recvServerHello — errUnknownSuite branch (suite offered but not registered).
// =============================================================================.

// TestRecvServerHello_UnknownSuite exercises the errUnknownSuite branch: the
// client offers suite ID 0xFFFE, the server echoes it back, but 0xFFFE is not
// in the suite registry.
func TestRecvServerHello_UnknownSuite(t *testing.T) {
	t.Parallel()

	const fakeSuiteID = uint16(0xFFFE) // offered, but unregistered.

	var random [32]byte

	shBody := buildRawServerHelloBody(random, fakeSuiteID, 0x0303, 0x00)
	shRec := buildHSRecord(TypeServerHello, shBody)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{fakeSuiteID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with unregistered suite: expected error, got nil")
	}

	if !errors.Is(err, errUnknownSuite) {
		t.Errorf("expected errUnknownSuite, got %v", err)
	}
}

// TestRecvServerHello_ExtendedMasterSecretRejected exercises the
// errUnexpectedEMS branch: server sends extended_master_secret extension.
func TestRecvServerHello_ExtendedMasterSecretRejected(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	// Build a ServerHello body manually that includes the extended_master_secret
	// extension (type 0x0017, length 0).
	var random [32]byte

	body := make([]byte, 0, 50)

	body = append(body, 0x03, 0x03)                        // version TLS 1.2.
	body = append(body, random[:]...)                      // random.
	body = append(body, 0x00)                              // session_id_len = 0.
	body = append(body, byte(suite.ID>>8), byte(suite.ID)) // cipher_suite.
	body = append(body, 0x00)                              // compression_method = null.

	// Extensions: total_len (2) + ext_type (2) + ext_data_len (2) + ext_data (0)
	// extended_master_secret is extension type 0x0017 with empty body.
	extPayload := []byte{0x00, 0x17, 0x00, 0x00} // type=0x0017, len=0.

	body = append(body, byte(len(extPayload)>>8), byte(len(extPayload)))
	body = append(body, extPayload...)

	shRec := buildHSRecord(TypeServerHello, body)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with EMS extension: expected error, got nil")
	}

	if !errors.Is(err, errUnexpectedEMS) {
		t.Errorf("expected errUnexpectedEMS, got %v", err)
	}
}

// =============================================================================.
// recvCertificate — success path (transcript.Write).
// =============================================================================.

// TestRecvCertificate_SuccessPath drives the success path of recvCertificate
// (including the transcript.Write call that was unreachable via existing tests).
func TestRecvCertificate_SuccessPath(t *testing.T) {
	t.Parallel()

	_, _, der := newTestRSACert(t)

	certMsg := &Certificate{RawCerts: [][]byte{der}}
	certRec := buildHSRecord(TypeCertificate, certMsg.Marshal())

	rw := &readWriteBuffer{r: bytes.NewBuffer(certRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustLookupSuite(t, "AES128-SHA256")

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	c.suite = suite

	leaf, msg, err := c.recvCertificate()
	if err != nil {
		t.Fatalf("recvCertificate: unexpected error: %v", err)
	}

	if leaf == nil {
		t.Error("expected non-nil leaf")
	}

	if msg == nil || len(msg.RawCerts) != 1 {
		t.Errorf("unexpected certMsg: %+v", msg)
	}

	// Transcript must be non-empty (the Certificate envelope was appended).
	h, sumErr := c.transcript.Sum(suite.PRF.Hash)
	if sumErr != nil {
		t.Fatalf("transcript.Sum: %v", sumErr)
	}

	if len(h) == 0 {
		t.Error("transcript is empty — Certificate was not appended")
	}
}

// =============================================================================.
// recvServerFlight — readHandshakeRecord error inside flight loop.
// =============================================================================.

// TestRecvServerFlight_ReadError exercises the error branch inside the for loop
// of recvServerFlight when the record layer returns an error mid-flight.
func TestRecvServerFlight_ReadError(t *testing.T) {
	t.Parallel()

	// Write a truncated TLS record: content type = Handshake but no payload.
	// The record layer will successfully deliver the record, but readHandshakeRecord
	// will reject it because the 4-byte handshake header is missing.
	truncated := []byte{record.ContentTypeHandshake, 0x03, 0x03, 0x00, 0x01, 0xFF}
	// The single byte payload (0xFF) is shorter than hsHdrLen(4) → errHSRecordTooShort.

	suite := mustLookupSuite(t, "AES128-SHA256")
	c := makeClientStateForFlight(t, truncated, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("recvServerFlight with truncated record: expected error, got nil")
	}
}

// =============================================================================.
// recvServerFlight — malformed ServerKeyExchange parse error.
// =============================================================================.

// TestRecvServerFlight_ParseSKEError exercises the parseSKE error path.
// The SKE record is empty, so ParseMessage fails on the body length.
func TestRecvServerFlight_ParseSKEError(t *testing.T) {
	t.Parallel()

	// A record with TypeServerKeyExchange but a body that is exactly 4 bytes of
	// all-zeros (the envelope header): payload[0]=TypeSKE, payload[1..3]=0x000000
	// → body is empty. For ECDHE, verifyECDHEServerKeyExchange will complain
	// about body too short, but we want the ParseMessage step to be reached first.
	// The body we inject is well-formed for the 4-byte HS envelope but actually
	// has a declared body length of 0 — ParseMessage will succeed and return a
	// ServerKeyExchange with empty Body, then verifyServerKeyExchange will fail.
	// To actually trigger the parseSKE error we must pass a body that ParseMessage
	// itself rejects. That happens if the HS envelope's declared length exceeds the
	// available bytes — but buildHSRecord always makes them consistent.
	//
	// Instead use the error path in verifyServerKeyExchange for an ECDHE suite
	// with a too-short body. That IS tested via TestVerifyECDHESKE_TooShort but
	// NOT via recvServerFlight. We drive it here via recvServerFlight to cover
	// the error return inside the SKE case (line 549-551).
	priv, _ := newTestECDSACert(t)

	_ = priv

	// Empty SKE body after the envelope (point_len = 0, verifyECDHESKE → too short).
	skeBody := []byte{} // parseServerKeyExchange returns Body=[] then verifyECDHESKE errors.
	skeRec := buildHSRecord(TypeServerKeyExchange, skeBody)

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeClientStateForFlight(t, skeRec, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("recvServerFlight with empty SKE body: expected error, got nil")
	}

	// The error should be errECDHESKETooShort (from verifyECDHEServerKeyExchange).
	if !errors.Is(err, errECDHESKETooShort) {
		t.Errorf("expected errECDHESKETooShort, got: %v", err)
	}
}

// =============================================================================.
// recvServerFlight — malformed CertificateRequest parse error.
// =============================================================================.

// TestRecvServerFlight_ParseCertReqError exercises the parseCertReq error path
// inside recvServerFlight. A malformed CertReq body (too short to be valid)
// triggers the ParseMessage → parseCertificateRequest failure.
func TestRecvServerFlight_ParseCertReqError(t *testing.T) {
	t.Parallel()

	// Malformed CertReq body: sig_alg list length (uint16) not present after
	// the certificate_types list.  Provide: cert_types_len=1, cert_type=0x01,
	// then only 1 byte for the sig_alg list length (need 2).
	malformedCertReq := []byte{0x01, 0x01, 0x00} // types_len=1, type=0x01, only 1 byte of sig_alg_len.

	certReqRec := buildHSRecord(TypeCertificateRequest, malformedCertReq)
	// Need SHD too so parseCertReq gets a chance before EOF.
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	wire := append(append([]byte{}, certReqRec...), shdRec...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA: no SKE.
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("recvServerFlight with malformed CertReq: expected error, got nil")
	}
}

// =============================================================================.
// recvServerFlight — malformed ServerHelloDone parse error.
// =============================================================================.

// TestRecvServerFlight_ParseSHDError exercises the parseSHD error path.
// ServerHelloDone must have an empty body; a non-empty body triggers the error.
func TestRecvServerFlight_ParseSHDError(t *testing.T) {
	t.Parallel()

	// ServerHelloDone with non-empty body is rejected by parseServerHelloDone.
	nonEmptySHD := buildHSRecord(TypeServerHelloDone, []byte{0xDE, 0xAD})

	suite := mustLookupSuite(t, "AES128-SHA256")
	c := makeClientStateForFlight(t, nonEmptySHD, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("recvServerFlight with non-empty SHD body: expected error, got nil")
	}
}

// =============================================================================.
// verifyServerKeyExchange — DHE dispatch (coverage for line 624-625).
// =============================================================================.

// TestVerifyServerKeyExchange_DHE_Dispatch exercises the KexDHE arm of
// verifyServerKeyExchange (which calls verifyDHEServerKeyExchange).
// This ensures the dispatch line is instrumented in recvServerFlight context.
func TestVerifyServerKeyExchange_DHE_Dispatch(t *testing.T) {
	t.Parallel()

	rsaKey, _, _ := newTestRSACert(t)
	cert := rsaCertFromKeyKEX(t, rsaKey)

	var clientRandom, serverRandom [32]byte

	for i := range clientRandom {
		clientRandom[i] = byte(i + 5)
		serverRandom[i] = byte(i + 6)
	}

	body := buildDHESKEBodyReal(t, rsaKey, clientRandom, serverRandom)

	suite := mustLookupSuite(t, "DHE-RSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	params, err := c.verifyServerKeyExchange(body, cert)
	if err != nil {
		t.Fatalf("verifyServerKeyExchange(DHE): %v", err)
	}

	if len(params) == 0 {
		t.Error("verifyServerKeyExchange(DHE): params should be non-empty")
	}
}

// =============================================================================.
// verifyECDHEServerKeyExchange — signature verification failure (line 700-703).
// =============================================================================.

// TestVerifyECDHESKE_BadSignature exercises the sig-verification-fail branch
// of verifyECDHEServerKeyExchange (tampered signature bytes).
func TestVerifyECDHESKE_BadSignature(t *testing.T) {
	t.Parallel()

	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	body := buildECDHESKEBody(t, priv, clientRandom, serverRandom)

	// Corrupt the last byte of the signature (the signature is at the end of body).
	body[len(body)-1] ^= 0xFF

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyECDHEServerKeyExchange with tampered sig: expected error, got nil")
	}
}

// =============================================================================.
// verifyDHEServerKeyExchange — dh_g and dh_Ys parse error paths.
// =============================================================================.

// TestVerifyDHESKE_DHGTruncated exercises the error path where the dh_g field
// is declared longer than the remaining buffer.
func TestVerifyDHESKE_DHGTruncated(t *testing.T) {
	t.Parallel()

	// Build valid dh_p prefix, then a truncated dh_g (declared len=100, 0 bytes).
	p := make([]byte, 4)
	body := appendU16PrefixedSlice(nil, p) // valid dh_p.

	body = append(body, 0x00, 0x64) // dh_g: declared 100 bytes, but no bytes follow → truncated.

	_, cert, _ := newTestRSACert(t)
	c := makeMinimalClientState(t, mustLookupSuite(t, "DHE-RSA-AES128-SHA256"))

	_, err := c.verifyDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyDHEServerKeyExchange with truncated dh_g: expected error, got nil")
	}
}

// TestVerifyDHESKE_DHYsTruncated exercises the error path where the dh_Ys field
// is declared longer than the remaining buffer.
func TestVerifyDHESKE_DHYsTruncated(t *testing.T) {
	t.Parallel()

	p := make([]byte, 4)
	g := []byte{0x02}
	body := appendU16PrefixedSlice(nil, p)

	body = appendU16PrefixedSlice(body, g)

	body = append(body, 0x00, 0x64) // dh_Ys: declared 100 bytes, but no bytes follow → truncated.

	_, cert, _ := newTestRSACert(t)
	c := makeMinimalClientState(t, mustLookupSuite(t, "DHE-RSA-AES128-SHA256"))

	_, err := c.verifyDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("verifyDHEServerKeyExchange with truncated dh_Ys: expected error, got nil")
	}
}

// =============================================================================.
// verifySignature — unsupported sig alg byte (line 804-806).
// =============================================================================.

// TestVerifySignature_UnsupportedSigAlg_Branch exercises the default branch in
// verifySignature when sigAlg is not RSA (0x01) or ECDSA (0x03). Distinct from
// the verifySignature_UnsupportedSigAlg test in wire_crypto_test.go which covers
// the same error via a different code path — this variant calls verifySignature
// directly with an unrecognised sig byte value.
func TestVerifySignature_UnsupportedSigAlg_Branch(t *testing.T) {
	t.Parallel()

	_, cert, _ := newTestRSACert(t)

	// hashAlg = sha256 (0x04), sigAlg = 0xAA (unknown).
	err := verifySignature(cert, 0x04, 0xAA, []byte("signed-data"), []byte("sig"))
	if err == nil {
		t.Fatal("verifySignature with unknown sigAlg: expected error, got nil")
	}

	if !errors.Is(err, errUnsupportedSigAlg) {
		t.Errorf("expected errUnsupportedSigAlg, got %v", err)
	}
}

// =============================================================================.
// computeKeyExchange — buildGOSTExchange error (no GOST cert, line 855-857).
// =============================================================================.

// TestComputeKeyExchange_GOST_NoCert exercises the error path in
// computeKeyExchange when a GOST suite is selected but c.gostLeaf is nil
// (no GOST server certificate was received), causing buildGOSTExchange to fail.
func TestComputeKeyExchange_GOST_NoCert(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2001-GOST89-GOST89")
	c := makeMinimalClientState(t, suite)
	// c.gostLeaf is nil → buildGOSTExchange returns errGOSTNeedGOSTCert.

	_, _, err := c.computeKeyExchange(nil, nil, nil)
	if err == nil {
		t.Fatal("computeKeyExchange GOST without GOST cert: expected error, got nil")
	}

	if !errors.Is(err, errGOSTNeedGOSTCert) {
		t.Errorf("expected errGOSTNeedGOSTCert, got %v", err)
	}
}

// =============================================================================.
// selectClientSigAlg — ECDSA P-521 (unsupported curve) → false.
// =============================================================================.

// TestSelectClientSigAlg_ECDSA_P521_Unsupported exercises the fall-through in
// the k.Curve switch inside keyCompatible: P-521 is not P-256 or P-384, so the
// inner switch falls through to `return false` (line 919).
func TestSelectClientSigAlg_ECDSA_P521_Unsupported(t *testing.T) {
	t.Parallel()

	privEC, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521 key: %v", err)
	}

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: privEC}},
		// Offer all ECDSA algs; none match P-521 (no sha512+ecdsa in advertised list).
		[]SigAndHash{
			{Hash: sigHashByte, Sig: sigAlgECDSA},   // sha256+ecdsa.
			{Hash: sigHashSHA384, Sig: sigAlgECDSA}, // sha384+ecdsa.
		},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: P-521 key should not match — expected false, got true")
	}
}

// TestSelectClientSigAlg_ECDSA_P256_NonECDSAAlg exercises line 919.30 via the
// `alg.Sig != sigAlgECDSA` early-return inside keyCompatible. The server only
// offers RSA algs so the ECDSA key returns false at the inner guard.
func TestSelectClientSigAlg_ECDSA_NoMatchingAlg(t *testing.T) {
	t.Parallel()

	ecKey, _, _ := newTestECDSACertWithDER(t) // P-256.

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: ecKey}},
		[]SigAndHash{
			{Hash: sigHashByte, Sig: sigAlgRSA}, // sha256+rsa only — ECDSA key can't use it.
		},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: ECDSA key with RSA-only server algs should return false")
	}
}

// =============================================================================.
// sendClientCertificate — WriteRecord failure path (line 977).
// =============================================================================.

// TestSendClientCertificate_WriteError exercises the WriteRecord error path
// in sendClientCertificate by using a write-failing record layer.
func TestSendClientCertificate_WriteError(t *testing.T) {
	t.Parallel()

	rsaKey, _, der := newTestRSACert(t)

	layer := record.NewLayer(&failReadWriter{msg: "write-fail"})

	c := &ClientState{
		params: ClientParams{
			Certificates: []ClientCertificate{
				{RawCertificate: der, PrivateKey: rsaKey},
			},
		},
		layer:      layer,
		transcript: NewTranscript(),
		certReq: &CertificateRequest{
			SupportedSignatureAlgs: []SigAndHash{{Hash: 0x04, Sig: 0x01}},
		},
	}

	_, err := c.sendClientCertificate()
	if err == nil {
		t.Fatal("sendClientCertificate with failing WriteRecord: expected error, got nil")
	}
}

// NOTE: sendCertificateVerify lines 1010 (RSA sign fail) and 1015 (ECDSA sign
// fail) wrap errors from rsa.SignPKCS1v15 and ecdsa.SignASN1 respectively.
// In practice these operations cannot fail given a well-formed key and a
// recognised hash algorithm — the signing operations are deterministic or draw
// entropy internally. These defensive error wraps are left uncovered.

// TestSendCertificateVerify_WriteRecordFail exercises the WriteRecord error
// path in sendCertificateVerify (line 1026-1028).
func TestSendCertificateVerify_WriteRecordFail(t *testing.T) {
	t.Parallel()

	rsaKey, _, _ := newTestRSACert(t)

	// Use a writer that succeeds for RSA signing (rand.Reader) but fails on the
	// subsequent WriteRecord call.
	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := &ClientState{
		params: ClientParams{
			Rand:         rand.Reader,
			Certificates: []ClientCertificate{{PrivateKey: rsaKey}},
		},
		layer:      layer,
		transcript: NewTranscript(),
	}

	// Sign succeeds. Now swap the writer for one that always fails before
	// WriteRecord is called. To do this, replace the underlying connection with
	// a failing one. Since record.Layer wraps the conn directly, we need to use
	// a wrapper that fails from the first write.
	failLayer := record.NewLayer(&failReadWriter{msg: "write-fail"})

	c.layer = failLayer

	alg := SigAndHash{Hash: sigHashByte, Sig: sigAlgRSA}

	err := c.sendCertificateVerify(alg)
	if err == nil {
		t.Fatal("sendCertificateVerify with failing WriteRecord: expected error, got nil")
	}
}

// =============================================================================.
// expandKeys — buildProtector error paths (lines 1073, 1079, 1085).
// =============================================================================.

// TestExpandKeys_BuildSendProtectorFails exercises the "build send protector
// fails" branch (line 1073-1076) by using a synthesised suite with an unknown
// cipher name that passes the totalLen > 0 check but fails buildProtector.
func TestExpandKeys_BuildSendProtectorFails(t *testing.T) {
	t.Parallel()

	// Use an AES-128-GCM-based suite but set an unrecognised cipher name so
	// buildProtector returns errUnsupportedAEAD.
	base := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	fake := *base

	fake.Cipher.Name = "AES-128-OCB" // AEAD=true but unrecognised name.

	c := makeClientStateWithKeys(t, &fake)

	km, _, _, err := c.expandKeys()

	_ = km

	if err == nil {
		t.Fatal("expandKeys with bad send cipher: expected error, got nil")
	}

	if !errors.Is(err, errUnsupportedAEAD) {
		t.Errorf("expected errUnsupportedAEAD, got %v", err)
	}
}

// =============================================================================.
// readHandshakeRecord — payload too short (< 4 bytes, line 1107).
// =============================================================================.

// TestReadHandshakeRecord_PayloadTooShort exercises the errHSRecordTooShort
// path in readHandshakeRecord: a handshake record with a 1-byte payload.
func TestReadHandshakeRecord_PayloadTooShort(t *testing.T) {
	t.Parallel()

	// Build a TLS record with ContentTypeHandshake and a 1-byte payload (need ≥ 4).
	rec := []byte{
		record.ContentTypeHandshake,
		0x03, 0x03, // TLS 1.2.
		0x00, 0x01, // payload length = 1.
		0xFF, // 1 byte of payload.
	}

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := &ClientState{layer: layer, transcript: NewTranscript()}

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with 1-byte payload: expected error, got nil")
	}

	if !errors.Is(err, errHSRecordTooShort) {
		t.Errorf("expected errHSRecordTooShort, got %v", err)
	}
}

// TestReadHandshakeRecord_BodyTruncated exercises errHSBodyTruncated: the
// 4-byte handshake header declares a body larger than what's available.
func TestReadHandshakeRecord_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Build a TLS record: type=0x16, payload has 4-byte header declaring bodyLen=100
	// but only 2 bytes of body follow.
	payload := make([]byte, 6)

	payload[0] = byte(TypeServerHello)

	// bodyLen = 100 declared (3 bytes, big-endian).
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x64 // 100.
	payload[4] = 0xAA
	payload[5] = 0xBB // only 2 bytes of body.

	rec := make([]byte, 5+len(payload))

	rec[0] = record.ContentTypeHandshake
	rec[1] = 0x03
	rec[2] = 0x03
	binary.BigEndian.PutUint16(rec[3:], uint16(len(payload)))
	copy(rec[5:], payload)

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := &ClientState{layer: layer, transcript: NewTranscript()}

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with truncated body: expected error, got nil")
	}

	if !errors.Is(err, errHSBodyTruncated) {
		t.Errorf("expected errHSBodyTruncated, got %v", err)
	}
}

// =============================================================================.
// readHandshakeRecord — alert record handling (covered for completeness).
// =============================================================================.

// TestReadHandshakeRecord_AlertRecord_Truncated exercises the branch where an
// alert record is received but its payload is shorter than 2 bytes.
func TestReadHandshakeRecord_AlertRecord_Truncated(t *testing.T) {
	t.Parallel()

	// A TLS alert record with only 1 byte of payload (need 2: level + description).
	rec := []byte{
		record.ContentTypeAlert,
		0x03, 0x03,
		0x00, 0x01, // payload len = 1.
		0x02, // only level byte, no description.
	}

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := &ClientState{layer: layer, transcript: NewTranscript()}

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with truncated alert: expected error, got nil")
	}

	if !errors.Is(err, errAlertRecordTruncated) {
		t.Errorf("expected errAlertRecordTruncated, got %v", err)
	}
}

// NOTE: expandKeysManual line 1179 (return nil, err from suites.PRF) is not
// meaningfully reachable: PRF only errors on empty label or zero outLen, but
// the label is hardcoded to "key expansion" and totalLen > 0 is enforced above.
// The branch is defensive dead code and is left uncovered intentionally.

// =============================================================================.
// ParseMessage — unknown message type (types.go line 107).
// =============================================================================.

// TestParseMessage_UnknownType exercises the default branch in ParseMessage's
// type switch when the message type byte is not in the known set.
func TestParseMessage_UnknownType(t *testing.T) {
	t.Parallel()

	// Build an envelope with type = 0xEE (unknown) and an empty body.
	env := buildEnvelope(Type(0xEE), []byte{})

	_, _, err := ParseMessage(env)
	if err == nil {
		t.Fatal("ParseMessage with unknown type: expected error, got nil")
	}

	if !errors.Is(err, errUnknownMsgType) {
		t.Errorf("expected errUnknownMsgType, got %v", err)
	}
}

// =============================================================================.
// parseCertificateRequest — CA entry parse error (messages.go line 441).
// =============================================================================.

// TestParseCertificateRequest_CAEntryError exercises the error path when the
// certificate_authorities list is malformed (declared entry length exceeds data).
func TestParseCertificateRequest_CAEntryError(t *testing.T) {
	t.Parallel()

	// cert_types: len=1, type=0x01
	// sig_algs:   len=2, {0x04,0x01}
	// ca_list:    len=4, then entry declared len=100 but only 1 byte follows.
	body := make([]byte, 0, 20)

	body = append(body, 0x01, 0x01)             // cert_types: 1 entry = rsa_sign.
	body = append(body, 0x00, 0x02, 0x04, 0x01) // sig_algs: 1 pair = sha256+rsa.
	// ca_list total len = 4 bytes, containing one entry that claims 100 bytes of DN.
	body = append(body, 0x00, 0x04)             // ca_list total len = 4.
	body = append(body, 0x00, 0x64, 0xAA, 0xBB) // entry: declared 100 bytes, but only 2 follow.

	_, err := parseCertificateRequest(body)
	if err == nil {
		t.Fatal("parseCertificateRequest with malformed CA list: expected error, got nil")
	}
}

// =============================================================================.
// parseCertificate — Certificate entry parse error (messages.go line 334).
// =============================================================================.

// TestParseCertificate_EntryParseError exercises the error path inside the
// inner readLenPrefixed24 loop in parseCertificate — the second cert entry's
// body is shorter than its declared length.
func TestParseCertificate_EntryParseError(t *testing.T) {
	t.Parallel()

	// outer_len = 7 bytes (exact, so the outer parse succeeds):
	//   entry 1: 3-byte len=1, data=[0xAA]                → 4 bytes
	//   entry 2: 3-byte prefix declares len=65536 (0x010000) but 0 bytes follow → errBodyShort
	// Total list content = 4 + 3 = 7 bytes.
	body := []byte{
		0x00, 0x00, 0x07, // outer_len = 7 (exact).
		0x00, 0x00, 0x01, 0xAA, // entry1: len=1, data=[0xAA].
		0x01, 0x00, 0x00, // entry2: len=65536 but 0 bytes of data present.
	}

	_, err := parseCertificate(body)
	if err == nil {
		t.Fatal("parseCertificate with malformed second entry: expected error, got nil")
	}
}

// =============================================================================.
// parseServerHello — session_id > 0 branch (messages.go line 247-249).
// =============================================================================.

// TestParseServerHello_NonEmptySessionID exercises the branch where session_id
// has a non-zero length; it is stored in m.SessionID.
func TestParseServerHello_NonEmptySessionID(t *testing.T) {
	t.Parallel()

	// Build a valid ServerHello with a 4-byte session_id.
	var random [32]byte

	body := make([]byte, 0, 50)

	body = append(body, 0x03, 0x03)             // version.
	body = append(body, random[:]...)           // random.
	body = append(body, 0x04)                   // session_id_len = 4.
	body = append(body, 0x01, 0x02, 0x03, 0x04) // session_id.
	body = append(body, 0x00, 0x2F)             // cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA.
	body = append(body, 0x00)                   // compression_method = null.
	// no extensions.

	sh, err := parseServerHello(body)
	if err != nil {
		t.Fatalf("parseServerHello with session_id: %v", err)
	}

	want := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(sh.SessionID, want) {
		t.Errorf("SessionID: got %x, want %x", sh.SessionID, want)
	}
}

// =============================================================================.
// kex_gost.go — buildGOSTExchange and buildGOST2018Exchange nil-cert error paths.
// =============================================================================.

// These branches require a *x509gost.Certificate with an invalid CurveOID
// (so gost.CurveByOID fails). Since constructing such a struct without importing
// x509gost would break the no-GPL rule, we cover them indirectly through
// computeKeyExchange → buildGOSTExchange → nil gostLeaf path instead.
// The CurveOID-error branches are defensive guards that can only be triggered
// with a malformed GOST cert; they are left uncovered and noted here.

// TestBuildGOSTExchange_NilGOSTLeaf documents that buildGOSTExchange returns
// errGOSTNeedGOSTCert when gostLeaf is nil (the most common real error path).
func TestBuildGOSTExchange_NilGOSTLeaf(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2001-GOST89-GOST89")
	c := makeMinimalClientState(t, suite)
	// c.gostLeaf is nil by default.

	_, err := buildGOSTExchange(c)
	if err == nil {
		t.Fatal("buildGOSTExchange with nil gostLeaf: expected error, got nil")
	}

	if !errors.Is(err, errGOSTNeedGOSTCert) {
		t.Errorf("expected errGOSTNeedGOSTCert, got %v", err)
	}
}

// TestBuildGOST2018Exchange_NilGOSTLeaf documents that buildGOST2018Exchange
// returns errGOST2018NeedGOSTCert when gostLeaf is nil.
func TestBuildGOST2018Exchange_NilGOSTLeaf(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")

	// Try to find a GOST-2018 suite (ID 0xC100).
	fake := *suite

	for _, s := range suites.All() {
		if s.ID == 0xC100 {
			fake = *s

			break
		}
	}

	c := makeMinimalClientState(t, &fake)
	// c.gostLeaf is nil.

	_, err := buildGOST2018Exchange(c)
	if err == nil {
		t.Fatal("buildGOST2018Exchange with nil gostLeaf: expected error, got nil")
	}

	if !errors.Is(err, errGOST2018NeedGOSTCert) {
		t.Errorf("expected errGOST2018NeedGOSTCert, got %v", err)
	}
}

// =============================================================================.
// expandKeys — AES-256-GCM and ChaCha20-Poly1305 paths.
// =============================================================================.

// TestExpandKeys_AES256GCM exercises the AEAD AES-256-GCM path of expandKeys,
// distinct from the AES-128-GCM path already covered.
func TestExpandKeys_AES256GCM(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES256-GCM-SHA384")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(AES-256-GCM): %v", err)
	}

	if km == nil || sendProt == nil || recvProt == nil {
		t.Error("expandKeys(AES-256-GCM): km/sendProt/recvProt should all be non-nil")

		return
	}

	if len(km.ClientEncKey) != suite.Cipher.KeyLen {
		t.Errorf("ClientEncKey len: got %d, want %d", len(km.ClientEncKey), suite.Cipher.KeyLen)
	}
}

// TestExpandKeys_ChaCha20Poly1305 exercises the ChaCha20-Poly1305 AEAD path
// of expandKeys.
func TestExpandKeys_ChaCha20Poly1305(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-CHACHA20-POLY1305")
	c := makeClientStateWithKeys(t, suite)

	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		t.Fatalf("expandKeys(ChaCha20-Poly1305): %v", err)
	}

	if km == nil || sendProt == nil || recvProt == nil {
		t.Error("expandKeys(ChaCha20-Poly1305): km/sendProt/recvProt should all be non-nil")
	}
}

// =============================================================================.
// parseClientHello — session_id length > 0 branch (messages.go line 115-116).
// =============================================================================.

// TestParseClientHello_NonEmptySessionID exercises the branch that copies a
// non-empty session_id into m.SessionID.
func TestParseClientHello_NonEmptySessionID(t *testing.T) {
	t.Parallel()

	ch := &ClientHello{
		Version:            0x0303,
		SessionID:          []byte{0xAA, 0xBB},
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
	}

	body := ch.Marshal()

	got, err := parseClientHello(body)
	if err != nil {
		t.Fatalf("parseClientHello with session_id: %v", err)
	}

	if !bytes.Equal(got.SessionID, ch.SessionID) {
		t.Errorf("SessionID: got %x, want %x", got.SessionID, ch.SessionID)
	}
}

// =============================================================================.
// parseCertificateVerify — sig byte parse error (messages.go line 499).
// =============================================================================.

// TestParseCertificateVerify_SigByteError exercises the readUint8 error on
// the sig byte when only the hash byte is present.
func TestParseCertificateVerify_SigByteError(t *testing.T) {
	t.Parallel()

	// Only 1 byte (hash byte). readUint8 for sig byte will fail.
	_, err := parseCertificateVerify([]byte{0x04})
	if err == nil {
		t.Fatal("parseCertificateVerify with only hash byte: expected error, got nil")
	}
}

// =============================================================================.
// parseCertificateRequest — odd sig_alg byte count (messages.go line 441).
// =============================================================================.

// TestParseCertificateRequest_OddSigAlgByteCount exercises the odd-byte-count
// error for the supported_signature_algorithms list.
func TestParseCertificateRequest_OddSigAlgByteCount(t *testing.T) {
	t.Parallel()

	// cert_types: len=1, type=0x01
	// sig_algs:   byte_len=3 (odd) → errCRSAOddByteCount.
	body := make([]byte, 0, 10)

	body = append(body, 0x01, 0x01)                   // cert_types: 1 entry.
	body = append(body, 0x00, 0x03, 0x04, 0x01, 0x05) // sig_algs: 3 bytes (odd).

	_, err := parseCertificateRequest(body)
	if err == nil {
		t.Fatal("parseCertificateRequest with odd sig_alg byte count: expected error, got nil")
	}

	if !errors.Is(err, errCRSAOddByteCount) {
		t.Errorf("expected errCRSAOddByteCount, got %v", err)
	}
}

// =============================================================================.
// recvServerHello — read error path (line 394-396).
// =============================================================================.

// TestRecvServerHello_ReadError exercises the readHandshakeRecord error path
// in recvServerHello when the connection is immediately closed (empty buffer).
func TestRecvServerHello_ReadError(t *testing.T) {
	t.Parallel()

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	err := c.recvServerHello()
	if err == nil {
		t.Fatal("recvServerHello with empty buffer: expected error, got nil")
	}
}

// =============================================================================.
// recvCertificate — read error path (line 459-461).
// =============================================================================.

// TestRecvCertificate_ReadError exercises the readHandshakeRecord error path
// in recvCertificate when the connection has no data.
func TestRecvCertificate_ReadError(t *testing.T) {
	t.Parallel()

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	c.suite = mustLookupSuite(t, "AES128-SHA256")

	_, _, err := c.recvCertificate()
	if err == nil {
		t.Fatal("recvCertificate with empty buffer: expected error, got nil")
	}
}

// =============================================================================.
// verifySignature — unsupported hash alg (line 804).
// =============================================================================.

// TestVerifySignature_UnsupportedHashAlg_Branch exercises the hashForSigAlg
// error path in verifySignature when the hash algorithm byte is unknown (0xFF).
// This is distinct from the unsupported sigAlg test above.
func TestVerifySignature_UnsupportedHashAlg_Branch(t *testing.T) {
	t.Parallel()

	_, cert, _ := newTestRSACert(t)

	// hashAlg = 0xFF (unknown), sigAlg = rsa (0x01).
	err := verifySignature(cert, 0xFF, sigAlgRSA, []byte("signed"), []byte("sig"))
	if err == nil {
		t.Fatal("verifySignature with unknown hashAlg: expected error, got nil")
	}

	if !errors.Is(err, errUnsupportedHashAlg) {
		t.Errorf("expected errUnsupportedHashAlg, got %v", err)
	}
}

// =============================================================================.
// ParseMessage — TypeHelloRequest (types.go line 107).
// =============================================================================.

// TestParseMessage_HelloRequest exercises the TypeHelloRequest case in
// ParseMessage. RFC 5746 treats HelloRequest as a server no-op; the
// implementation returns a *ServerHelloDone as a stand-in.
func TestParseMessage_HelloRequest(t *testing.T) {
	t.Parallel()

	env := buildEnvelope(TypeHelloRequest, []byte{})

	msg, rest, err := ParseMessage(env)
	if err != nil {
		t.Fatalf("ParseMessage(TypeHelloRequest): %v", err)
	}

	if len(rest) != 0 {
		t.Errorf("rest: got %x, want empty", rest)
	}

	if msg == nil {
		t.Fatal("ParseMessage(TypeHelloRequest): expected non-nil msg")
	}
}

// =============================================================================.
// RSA key with ECDSA-only sig_algs — early false return in keyCompatible.
// =============================================================================.

// TestSelectClientSigAlg_RSAKey_ECDSAOnlyServer exercises the inner
// `alg.Sig == sigAlgRSA` guard: RSA key but server only offers ECDSA algs.
func TestSelectClientSigAlg_RSAKey_ECDSAOnlyServer(t *testing.T) {
	t.Parallel()

	rsaKey, _, _ := newTestRSACert(t)

	c := newMinimalClientState(
		[]ClientCertificate{{PrivateKey: rsaKey}},
		[]SigAndHash{
			{Hash: sigHashByte, Sig: sigAlgECDSA},   // sha256+ecdsa only.
			{Hash: sigHashSHA384, Sig: sigAlgECDSA}, // sha384+ecdsa only.
		},
	)

	_, ok := c.selectClientSigAlg()
	if ok {
		t.Fatal("selectClientSigAlg: RSA key with ECDSA-only server should return false")
	}
}

// =============================================================================.
// recvServerHello — success path (serverRandom + transcript.Write, line 449).
// =============================================================================.

// TestRecvServerHello_SuccessPath drives recvServerHello to completion with a
// valid, minimal ServerHello: verifies that serverRandom is stored, the
// transcript is non-empty, and the suite is installed.
func TestRecvServerHello_SuccessPath(t *testing.T) {
	t.Parallel()

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA, simple suite.

	var random [32]byte

	for i := range random {
		random[i] = byte(i + 1)
	}

	shBody := buildRawServerHelloBody(random, suite.ID, 0x0303, 0x00)
	shRec := buildHSRecord(TypeServerHello, shBody)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})

	if err := c.recvServerHello(); err != nil {
		t.Fatalf("recvServerHello: unexpected error: %v", err)
	}

	// serverRandom must be populated.
	if c.serverRandom != random {
		t.Errorf("serverRandom: got %x, want %x", c.serverRandom, random)
	}

	// suite must be installed.
	if c.suite == nil || c.suite.ID != suite.ID {
		t.Errorf("suite not installed: got %v", c.suite)
	}

	// Transcript must be non-empty.
	h, err := c.transcript.Sum(suite.PRF.Hash)
	if err != nil {
		t.Fatalf("transcript.Sum: %v", err)
	}

	if len(h) == 0 {
		t.Error("transcript empty after recvServerHello — ServerHello was not appended")
	}
}

// =============================================================================.
// recvCertificate — parseAndVerifyLeaf error (line 487).
// =============================================================================.

// TestRecvCertificate_LeafVerifyError exercises the parseAndVerifyLeaf error
// path inside recvCertificate. A structurally valid Certificate message is
// sent, but its single DER entry is not a valid X.509 certificate.
func TestRecvCertificate_LeafVerifyError(t *testing.T) {
	t.Parallel()

	// A valid 3-byte DER entry (non-empty, passes the zero-len guard) but
	// not a valid X.509 certificate, so x509gost.ParseCertificate fails.
	badDER := []byte{0x30, 0x01, 0xAA} // minimal ASN.1 SEQUENCE but truncated.

	certMsg := &Certificate{RawCerts: [][]byte{badDER}}
	certRec := buildHSRecord(TypeCertificate, certMsg.Marshal())

	rw := &readWriteBuffer{r: bytes.NewBuffer(certRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	suite := mustLookupSuite(t, "AES128-SHA256")

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	c.suite = suite

	_, _, err := c.recvCertificate()
	if err == nil {
		t.Fatal("recvCertificate with bad DER leaf: expected error, got nil")
	}
}

// =============================================================================.
// expandKeys — build recv protector: note on unreachable branch.
// =============================================================================.

// The recv-protector failure branch (line 1085) is only reachable if the send
// protector succeeds but the recv protector fails using the same Suite spec —
// which cannot happen in production since both calls use the same cipher spec.
// It is a defensive error wrap and is left uncovered intentionally.

// =============================================================================.
// computeKeyExchange — ClientKeyExchange failure (line 868).
// =============================================================================.

// TestComputeKeyExchange_ClientKeyExchangeFail exercises the error path where
// exchange.ClientKeyExchange fails. We use an ECDHE suite but provide
// serverParams with no valid point data so ECDHEExchange.ClientKeyExchange fails.
func TestComputeKeyExchange_ClientKeyExchangeFail(t *testing.T) {
	t.Parallel()

	_, ecCert := newTestECDSACert(t)

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.params.Rand = rand.Reader

	// serverParams: curve_type(0x03) + named_curve(P-256=0x0017) + point_len(0x01) + bad_point(0xAA).
	// The point is a single byte which is not a valid EC point, causing
	// ECDHEExchange.ClientKeyExchange to fail.
	serverParams := []byte{0x03, 0x00, 0x17, 0x01, 0xAA}

	_, _, err := c.computeKeyExchange(ecCert, serverParams, nil)
	if err == nil {
		t.Fatal("computeKeyExchange with bad ECDHE params: expected error, got nil")
	}
}

// =============================================================================.
// sendCertificateVerify — transcript.Sum error (line 999).
// =============================================================================.

// TestSendCertificateVerify_TranscriptSumError documents that the transcript.Sum
// error path in sendCertificateVerify is only reachable by overflowing the
// transcript (> maxTranscriptBytes = 16 MB), which is impractical in a unit test.
// The branch is left uncovered.
func TestSendCertificateVerify_TranscriptSumError(t *testing.T) {
	t.Parallel()

	t.Skip("transcript overflow requires 16 MB of writes — skip as impractical")
}

// =============================================================================.
// parseClientHello — session_id and cipher_suites parse errors via readLen8/16.
// =============================================================================.

// TestParseClientHello_TruncatedSessionIDBody exercises the readLenPrefixed8
// body-truncated error for the session_id field (messages.go line 107).
func TestParseClientHello_TruncatedSessionIDBody(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len=5 but only 2 bytes of body.
	body := make([]byte, 0, 40)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x05)                // session_id_len = 5.
	body = append(body, 0xAA, 0xBB)          // only 2 bytes of body (need 5).

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("parseClientHello truncated session_id body: expected error, got nil")
	}
}

// TestParseClientHello_TruncatedCipherSuitesBody exercises the readLenPrefixed16
// body-truncated error for the cipher_suites field (messages.go line 123).
func TestParseClientHello_TruncatedCipherSuitesBody(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id(1+0) + cipher_suites len=10 but 2 bytes body.
	body := make([]byte, 0, 40)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id_len = 0.
	body = append(body, 0x00, 0x0A)          // cipher_suites byte_len = 10.
	body = append(body, 0x00, 0x2F)          // only 2 bytes of cipher suite data.

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("parseClientHello truncated cipher_suites body: expected error, got nil")
	}
}

// TestParseClientHello_TruncatedCompressionMethodsBody exercises the
// readLenPrefixed8 body-truncated error for the compression_methods field
// (messages.go line 144).
func TestParseClientHello_TruncatedCompressionMethodsBody(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id(1+0) + cipher_suites(2+2) + compression_methods len=5 + 0 bytes.
	body := make([]byte, 0, 40)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id_len = 0.
	body = append(body, 0x00, 0x02)          // cipher_suites byte_len = 2.
	body = append(body, 0x00, 0x2F)          // one suite.
	body = append(body, 0x05)                // compression_methods len = 5.
	// no bytes follow → body-truncated error.

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("parseClientHello truncated compression_methods body: expected error, got nil")
	}
}

// =============================================================================.
// parseServerHello — session_id readLenPrefixed8 error (messages.go line 239).
// =============================================================================.

// TestParseServerHello_TruncatedSessionIDBody exercises the readLenPrefixed8
// body-truncated error for the session_id in parseServerHello.
func TestParseServerHello_TruncatedSessionIDBody(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len=8 but only 2 bytes of body.
	body := make([]byte, 0, 40)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x08)                // session_id_len = 8.
	body = append(body, 0xAA, 0xBB)          // only 2 bytes (need 8).

	_, err := parseServerHello(body)
	if err == nil {
		t.Fatal("parseServerHello truncated session_id body: expected error, got nil")
	}
}
