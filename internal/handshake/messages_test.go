package handshake_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bigbes/gostls/internal/handshake"
)

// hexDecode decodes a hex string, panicking on error (test helper).
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("hexDecode: %v", err)
	}

	return b
}

// --- ClientHello ---.

func TestMessage_ClientHello_RoundTrip(t *testing.T) {
	t.Parallel()

	// Build a ClientHello struct.
	random := [32]byte{}
	for i := range random {
		random[i] = byte(i)
	}

	sessionID := []byte{0xAA, 0xBB, 0xCC}

	hello := &handshake.ClientHello{
		Version:            0x0303,
		Random:             random,
		SessionID:          sessionID,
		CipherSuites:       []uint16{0x002F, 0xC02C},
		CompressionMethods: []uint8{0x00},
		ServerName:         "example.com",
		SupportedGroups:    []uint16{0x0017, 0x0018},
		ECPointFormats:     []uint8{0x00},
		SignatureAlgorithms: []handshake.SigAndHash{
			{Hash: 0x04, Sig: 0x01},
			{Hash: 0x05, Sig: 0x01},
		},
	}

	// Marshal the body, wrap in message envelope.
	body := hello.Marshal()
	msg := handshake.MarshalMessage(hello)

	// Sanity check: envelope prefix is msg_type + 3-byte length.
	if msg[0] != byte(handshake.TypeClientHello) {
		t.Fatalf("expected TypeClientHello byte %02x, got %02x", handshake.TypeClientHello, msg[0])
	}

	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if bodyLen != len(body) {
		t.Fatalf("envelope length %d != body length %d", bodyLen, len(body))
	}

	// ParseMessage from the full wire bytes.
	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining bytes, got %d", len(remaining))
	}

	got, ok := parsed.(*handshake.ClientHello)
	if !ok {
		t.Fatalf("expected *ClientHello, got %T", parsed)
	}

	if got.Version != hello.Version {
		t.Errorf("Version: got %04x, want %04x", got.Version, hello.Version)
	}

	if got.Random != hello.Random {
		t.Errorf("Random mismatch")
	}

	if !bytes.Equal(got.SessionID, hello.SessionID) {
		t.Errorf("SessionID: got %v, want %v", got.SessionID, hello.SessionID)
	}

	if len(got.CipherSuites) != len(hello.CipherSuites) {
		t.Errorf("CipherSuites len: got %d, want %d", len(got.CipherSuites), len(hello.CipherSuites))
	} else {
		for i, cs := range hello.CipherSuites {
			if got.CipherSuites[i] != cs {
				t.Errorf("CipherSuites[%d]: got %04x, want %04x", i, got.CipherSuites[i], cs)
			}
		}
	}

	if got.ServerName != hello.ServerName {
		t.Errorf("ServerName: got %q, want %q", got.ServerName, hello.ServerName)
	}

	if len(got.SupportedGroups) != len(hello.SupportedGroups) {
		t.Errorf("SupportedGroups len mismatch")
	}

	if len(got.SignatureAlgorithms) != len(hello.SignatureAlgorithms) {
		t.Errorf("SignatureAlgorithms len mismatch")
	}
}

// --- ServerHello ---.

func TestMessage_ServerHello_RoundTrip(t *testing.T) {
	t.Parallel()

	random := [32]byte{}
	for i := range random {
		random[i] = byte(i + 32)
	}

	hello := &handshake.ServerHello{
		Version:           0x0303,
		Random:            random,
		SessionID:         []byte{0x01, 0x02},
		CipherSuite:       0xC02C,
		CompressionMethod: 0x00,
		RenegotiationInfo: true,
	}

	msg := handshake.MarshalMessage(hello)

	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining bytes: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.ServerHello)
	if !ok {
		t.Fatalf("expected *ServerHello, got %T", parsed)
	}

	if got.Version != hello.Version {
		t.Errorf("Version: got %04x, want %04x", got.Version, hello.Version)
	}

	if got.Random != hello.Random {
		t.Errorf("Random mismatch")
	}

	if got.CipherSuite != hello.CipherSuite {
		t.Errorf("CipherSuite: got %04x, want %04x", got.CipherSuite, hello.CipherSuite)
	}

	if got.CompressionMethod != hello.CompressionMethod {
		t.Errorf("CompressionMethod: got %02x, want %02x", got.CompressionMethod, hello.CompressionMethod)
	}

	if got.RenegotiationInfo != hello.RenegotiationInfo {
		t.Errorf("RenegotiationInfo: got %v, want %v", got.RenegotiationInfo, hello.RenegotiationInfo)
	}
}

// --- Certificate ---.

func TestMessage_Certificate_RoundTrip(t *testing.T) {
	t.Parallel()

	// Use two fake DER-encoded certs (just raw bytes for wire format test).
	cert1 := []byte{0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB} // fake DER.
	cert2 := []byte{0x30, 0x82, 0x02, 0x00, 0xCC, 0xDD, 0xEE}

	certMsg := &handshake.Certificate{
		Certificates: []*x509.Certificate(nil),
		RawCerts:     [][]byte{cert1, cert2},
	}

	msg := handshake.MarshalMessage(certMsg)

	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.Certificate)
	if !ok {
		t.Fatalf("expected *Certificate, got %T", parsed)
	}

	if len(got.RawCerts) != 2 {
		t.Fatalf("expected 2 raw certs, got %d", len(got.RawCerts))
	}

	if !bytes.Equal(got.RawCerts[0], cert1) {
		t.Errorf("RawCerts[0] mismatch")
	}

	if !bytes.Equal(got.RawCerts[1], cert2) {
		t.Errorf("RawCerts[1] mismatch")
	}
}

// --- ServerKeyExchange ---.

func TestMessage_ServerKeyExchange_RoundTrip(t *testing.T) {
	t.Parallel()

	params := []byte{0x03, 0x00, 0x17, 0x41, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}

	ske := &handshake.ServerKeyExchange{
		Body: params,
	}

	msg := handshake.MarshalMessage(ske)

	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.ServerKeyExchange)
	if !ok {
		t.Fatalf("expected *ServerKeyExchange, got %T", parsed)
	}

	if !bytes.Equal(got.Body, params) {
		t.Errorf("Body mismatch: got %x, want %x", got.Body, params)
	}
}

// --- ServerHelloDone ---.

func TestMessage_ServerHelloDone_RoundTrip(t *testing.T) {
	t.Parallel()

	done := &handshake.ServerHelloDone{}

	msg := handshake.MarshalMessage(done)
	if len(msg) != 4 {
		t.Fatalf("ServerHelloDone should be 4 bytes (header only), got %d", len(msg))
	}

	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining: %d", len(remaining))
	}

	_, ok := parsed.(*handshake.ServerHelloDone)
	if !ok {
		t.Fatalf("expected *ServerHelloDone, got %T", parsed)
	}
}

// --- ClientKeyExchange ---.

func TestMessage_ClientKeyExchange_RoundTrip(t *testing.T) {
	t.Parallel()

	body := []byte{0x41, 0x04, 0xCA, 0xFE, 0xBA, 0xBE}

	cke := &handshake.ClientKeyExchange{
		Body: body,
	}

	msg := handshake.MarshalMessage(cke)

	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.ClientKeyExchange)
	if !ok {
		t.Fatalf("expected *ClientKeyExchange, got %T", parsed)
	}

	if !bytes.Equal(got.Body, body) {
		t.Errorf("Body mismatch: got %x, want %x", got.Body, body)
	}
}

// --- CertificateVerify ---.

func TestMessage_CertificateVerify_RoundTrip(t *testing.T) {
	t.Parallel()

	sig := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	cv := &handshake.CertificateVerify{
		Algorithm: handshake.SigAndHash{Hash: 0x04, Sig: 0x01},
		Signature: sig,
	}

	msg := handshake.MarshalMessage(cv)

	parsed, remaining, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.CertificateVerify)
	if !ok {
		t.Fatalf("expected *CertificateVerify, got %T", parsed)
	}

	if got.Algorithm != cv.Algorithm {
		t.Errorf("Algorithm: got %v, want %v", got.Algorithm, cv.Algorithm)
	}

	if !bytes.Equal(got.Signature, cv.Signature) {
		t.Errorf("Signature mismatch")
	}
}

// --- Finished ---.

func TestMessage_Finished_RoundTrip(t *testing.T) {
	t.Parallel()

	// verify_data is 12 bytes for standard TLS 1.2 / 32 bytes for GOST 2018.
	for _, vdLen := range []int{12, 32} {
		vd := make([]byte, vdLen)
		for i := range vd {
			vd[i] = byte(i + 1)
		}

		fin := &handshake.Finished{VerifyData: vd}

		msg := handshake.MarshalMessage(fin)

		parsed, remaining, err := handshake.ParseMessage(msg)
		if err != nil {
			t.Fatalf("len=%d ParseMessage: %v", vdLen, err)
		}

		if len(remaining) != 0 {
			t.Fatalf("len=%d unexpected remaining: %d", vdLen, len(remaining))
		}

		got, ok := parsed.(*handshake.Finished)
		if !ok {
			t.Fatalf("len=%d expected *Finished, got %T", vdLen, parsed)
		}

		if !bytes.Equal(got.VerifyData, fin.VerifyData) {
			t.Errorf("len=%d VerifyData mismatch: got %x, want %x", vdLen, got.VerifyData, fin.VerifyData)
		}
	}
}

// --- Unknown extension rejection ---.

func TestMessage_ClientHello_RejectsUnknownExtension(t *testing.T) {
	t.Parallel()

	// Build a valid ClientHello wire body with an unknown extension type 0xFFFF.
	random := [32]byte{}
	hello := &handshake.ClientHello{
		Version:            0x0303,
		Random:             random,
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
	}
	body := hello.Marshal()

	// Append an extension list with unknown type 0xFFFF.
	// Extensions list: uint16 total_len, then each: uint16 type, uint16 len, body.
	extBody := []byte{0xFF, 0xFF, 0x00, 0x02, 0xAA, 0xBB} // type=0xFFFF, len=2, body=AABB.
	extList := make([]byte, 2+len(extBody))

	extList[0] = 0x00
	extList[1] = byte(len(extBody))
	copy(extList[2:], extBody)

	wire := append(body, extList...)
	msg := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeClientHello,
		Body:    wire,
	})

	_, _, err := handshake.ParseMessage(msg)
	if err == nil {
		t.Fatal("expected error for unknown extension, got nil")
	}

	if !strings.Contains(err.Error(), "unknown extension") {
		t.Errorf("error should mention 'unknown extension', got: %v", err)
	}
}

// --- Truncated length rejection ---.

func TestMessage_Rejects_TruncatedLength(t *testing.T) {
	t.Parallel()

	// For each message type that has a non-trivial body, feed a buffer
	// that claims more bytes than actually present.
	tests := []struct {
		name string
		// wire is the full MarshalMessage output, then we truncate.
		build func() []byte
	}{
		{
			name: "ClientHello",
			build: func() []byte {
				random := [32]byte{}
				h := &handshake.ClientHello{
					Version:            0x0303,
					Random:             random,
					CipherSuites:       []uint16{0x002F},
					CompressionMethods: []uint8{0x00},
				}

				return handshake.MarshalMessage(h)
			},
		},
		{
			name: "ServerHello",
			build: func() []byte {
				random := [32]byte{}
				h := &handshake.ServerHello{
					Version:     0x0303,
					Random:      random,
					CipherSuite: 0x002F,
				}

				return handshake.MarshalMessage(h)
			},
		},
		{
			name: "Certificate",
			build: func() []byte {
				c := &handshake.Certificate{
					RawCerts: [][]byte{{0x30, 0x01, 0xAA}},
				}

				return handshake.MarshalMessage(c)
			},
		},
		{
			name: "CertificateVerify",
			build: func() []byte {
				cv := &handshake.CertificateVerify{
					Algorithm: handshake.SigAndHash{Hash: 0x04, Sig: 0x01},
					Signature: []byte{0xAA, 0xBB},
				}

				return handshake.MarshalMessage(cv)
			},
		},
		{
			name: "Finished",
			build: func() []byte {
				fin := &handshake.Finished{}
				return handshake.MarshalMessage(fin)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wire := tc.build()
			// Truncate: remove last byte but keep the length field intact.
			truncated := wire[:len(wire)-1]

			_, _, err := handshake.ParseMessage(truncated)
			if err == nil {
				t.Fatalf("expected error for truncated %s, got nil", tc.name)
			}
		})
	}
}

// --- Transcript tests ---.

func TestTranscript_MultiHash_Before_Collapse(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()

	msg1 := []byte("handshake message 1")
	msg2 := []byte("second message bytes")
	msg3 := []byte("third message content")

	tr.Write(msg1)
	tr.Write(msg2)
	tr.Write(msg3)

	// Concatenation of all messages.
	all := append(append(append([]byte{}, msg1...), msg2...), msg3...)

	// SHA-256 of the concatenation.
	h256 := sha256.New()
	h256.Write(all)

	wantSHA256 := h256.Sum(nil)

	// SHA-384 of the concatenation.
	h384 := sha512.New384()
	h384.Write(all)

	wantSHA384 := h384.Sum(nil)

	got256, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum(sha256): %v", err)
	}

	if !bytes.Equal(got256, wantSHA256) {
		t.Errorf("SHA-256 mismatch:\n  got  %x\n  want %x", got256, wantSHA256)
	}

	got384, err := tr.Sum(sha512.New384)
	if err != nil {
		t.Fatalf("Sum(sha384): %v", err)
	}

	if !bytes.Equal(got384, wantSHA384) {
		t.Errorf("SHA-384 mismatch:\n  got  %x\n  want %x", got384, wantSHA384)
	}
}

// --- Renegotiation info ---.

func TestExtensions_RenegotiationInfo_EmptyOnly(t *testing.T) {
	t.Parallel()

	// Build a ServerHello with renegotiation_info extension.
	// Empty body → OK.
	random := [32]byte{}
	hello := &handshake.ServerHello{
		Version:           0x0303,
		Random:            random,
		CipherSuite:       0x002F,
		RenegotiationInfo: true,
	}
	msg := handshake.MarshalMessage(hello)

	parsed, _, err := handshake.ParseMessage(msg)
	if err != nil {
		t.Fatalf("empty renegotiation_info should be accepted: %v", err)
	}

	got, ok := parsed.(*handshake.ServerHello)
	if !ok {
		t.Fatalf("expected *ServerHello, got %T", parsed)
	}

	if !got.RenegotiationInfo {
		t.Error("RenegotiationInfo should be true")
	}

	// Non-empty renegotiation_info body → must be rejected.
	// We build the wire manually by injecting bad extension bytes into a
	// ServerHello body that has no extensions.
	// renegotiation_info ext: type=0xFF01, len=3, content={0x01, 0xAA, 0xBB}
	// Per RFC 5746, the body is: uint8 renegotiated_connection length + data.
	// Non-empty means the uint8 length > 0.
	badExt := []byte{
		0xFF, 0x01, // type renegotiation_info.
		0x00, 0x03, // ext length = 3.
		0x02, 0xAA, 0xBB, // renegotiated_connection length=2 + 2 bytes data.
	}
	extList := make([]byte, 2+len(badExt))

	extList[0] = 0x00
	extList[1] = byte(len(badExt))
	copy(extList[2:], badExt)

	// Remove the old extension list from body (none was added since we had
	// renegotiation_info=true and it marshals with empty body).
	// Instead build a raw ServerHello without extensions first.
	helloNoExt := &handshake.ServerHello{
		Version:     0x0303,
		Random:      random,
		CipherSuite: 0x002F,
	}
	bodyNoExt := helloNoExt.Marshal()
	wireWithBadExt := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeServerHello,
		Body:    append(bodyNoExt, extList...),
	})

	_, _, err = handshake.ParseMessage(wireWithBadExt)
	if err == nil {
		t.Fatal("expected error for non-empty renegotiation_info, got nil")
	}

	if !strings.Contains(err.Error(), "renegotiation") {
		t.Errorf("error should mention renegotiation, got: %v", err)
	}
}

// --- CertificateRequest ---.

// buildCertificateRequestWire builds the raw wire body (no 4-byte envelope)
// for a CertificateRequest message from its parts.
//
// RFC 5246 §7.4.4 encoding:
//
//	uint8 cert_types_len + cert_types
//	uint16 sig_algs_byte_len + sig_alg pairs (hash, sig)
//	uint16 cas_byte_len + { uint16 dn_len + dn_bytes } *
func buildCertificateRequestWire(certTypes []uint8, sigAlgs []handshake.SigAndHash, cas [][]byte) []byte {
	// supported_signature_algorithms: uint16 byte-length prefix.
	sigBytes := make([]byte, 2*len(sigAlgs))
	for i, sa := range sigAlgs {
		sigBytes[2*i] = sa.Hash
		sigBytes[2*i+1] = sa.Sig
	}

	// certificate_authorities body.
	casLen := 0
	for _, dn := range cas {
		casLen += 2 + len(dn)
	}

	casBody := make([]byte, 0, casLen)

	for _, dn := range cas {
		casBody = append(casBody, uint8(len(dn)>>8), uint8(len(dn)))
		casBody = append(casBody, dn...)
	}

	body := make([]byte, 0, 1+len(certTypes)+2+len(sigBytes)+2+len(casBody))

	// certificate_types: uint8 length prefix.
	body = append(body, uint8(len(certTypes)))
	body = append(body, certTypes...)

	body = append(body, uint8(len(sigBytes)>>8), uint8(len(sigBytes)))
	body = append(body, sigBytes...)

	body = append(body, uint8(len(casBody)>>8), uint8(len(casBody)))
	body = append(body, casBody...)

	return body
}

// TestMessage_CertificateRequest_Minimal tests parsing of a CertificateRequest
// with 1 cert type, 2 sig-algs, and 1 empty CA (zero-length DN).
func TestMessage_CertificateRequest_Minimal(t *testing.T) {
	t.Parallel()

	certTypes := []uint8{0x01} // rsa_sign.
	sigAlgs := []handshake.SigAndHash{
		{Hash: 0x04, Sig: 0x01}, // sha256+rsa.
		{Hash: 0x05, Sig: 0x01}, // sha384+rsa.
	}
	// One CA with an empty DN (zero-length).
	cas := [][]byte{{}}

	wire := buildCertificateRequestWire(certTypes, sigAlgs, cas)
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    wire,
	})

	parsed, remaining, err := handshake.ParseMessage(envelope)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining bytes: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.CertificateRequest)
	if !ok {
		t.Fatalf("expected *CertificateRequest, got %T", parsed)
	}

	if len(got.CertificateTypes) != 1 || got.CertificateTypes[0] != 0x01 {
		t.Errorf("CertificateTypes: got %v, want [0x01]", got.CertificateTypes)
	}

	if len(got.SupportedSignatureAlgs) != 2 {
		t.Fatalf("SupportedSignatureAlgs: got %d, want 2", len(got.SupportedSignatureAlgs))
	}

	if got.SupportedSignatureAlgs[0] != sigAlgs[0] {
		t.Errorf("SigAlgs[0]: got %v, want %v", got.SupportedSignatureAlgs[0], sigAlgs[0])
	}

	if got.SupportedSignatureAlgs[1] != sigAlgs[1] {
		t.Errorf("SigAlgs[1]: got %v, want %v", got.SupportedSignatureAlgs[1], sigAlgs[1])
	}

	if len(got.CertificateAuthorities) != 1 {
		t.Fatalf("CertificateAuthorities: got %d, want 1", len(got.CertificateAuthorities))
	}

	if len(got.CertificateAuthorities[0]) != 0 {
		t.Errorf("CertificateAuthorities[0]: expected empty DN, got %d bytes", len(got.CertificateAuthorities[0]))
	}
}

// TestMessage_CertificateRequest_TwoCAs tests parsing with two non-empty CA DNs.
func TestMessage_CertificateRequest_TwoCAs(t *testing.T) {
	t.Parallel()

	certTypes := []uint8{0x01, 0x02} // rsa_sign, dss_sign.
	sigAlgs := []handshake.SigAndHash{
		{Hash: 0x04, Sig: 0x01},
	}
	ca1 := []byte{0x30, 0x0A, 0x31, 0x08, 0x30, 0x06}             // fake DN 1.
	ca2 := []byte{0x30, 0x12, 0x31, 0x10, 0x30, 0x0E, 0xAB, 0xCD} // fake DN 2.

	wire := buildCertificateRequestWire(certTypes, sigAlgs, [][]byte{ca1, ca2})
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    wire,
	})

	parsed, remaining, err := handshake.ParseMessage(envelope)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining bytes: %d", len(remaining))
	}

	got, ok := parsed.(*handshake.CertificateRequest)
	if !ok {
		t.Fatalf("expected *CertificateRequest, got %T", parsed)
	}

	if len(got.CertificateTypes) != 2 {
		t.Errorf("CertificateTypes: got %d, want 2", len(got.CertificateTypes))
	}

	if len(got.SupportedSignatureAlgs) != 1 {
		t.Errorf("SupportedSignatureAlgs: got %d, want 1", len(got.SupportedSignatureAlgs))
	}

	if len(got.CertificateAuthorities) != 2 {
		t.Fatalf("CertificateAuthorities: got %d, want 2", len(got.CertificateAuthorities))
	}

	if !bytes.Equal(got.CertificateAuthorities[0], ca1) {
		t.Errorf("CA[0] mismatch: got %x, want %x", got.CertificateAuthorities[0], ca1)
	}

	if !bytes.Equal(got.CertificateAuthorities[1], ca2) {
		t.Errorf("CA[1] mismatch: got %x, want %x", got.CertificateAuthorities[1], ca2)
	}
}

// TestMessage_CertificateRequest_EmptyCAs tests parsing with an empty
// certificate_authorities list (legal per RFC 5246).
func TestMessage_CertificateRequest_EmptyCAs(t *testing.T) {
	t.Parallel()

	certTypes := []uint8{0x01}
	sigAlgs := []handshake.SigAndHash{{Hash: 0x04, Sig: 0x01}}

	var cas [][]byte // empty.

	wire := buildCertificateRequestWire(certTypes, sigAlgs, cas)
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    wire,
	})

	parsed, _, err := handshake.ParseMessage(envelope)
	if err != nil {
		t.Fatalf("ParseMessage with empty CAs: %v", err)
	}

	got, ok := parsed.(*handshake.CertificateRequest)
	if !ok {
		t.Fatalf("expected *CertificateRequest, got %T", parsed)
	}

	if len(got.CertificateAuthorities) != 0 {
		t.Errorf("expected 0 CAs, got %d", len(got.CertificateAuthorities))
	}
}

// TestMessage_CertificateRequest_Truncated_CertTypes tests truncation at the
// certificate_types length prefix.
func TestMessage_CertificateRequest_Truncated_CertTypes(t *testing.T) {
	t.Parallel()

	// Only the cert_types length byte, no actual cert type bytes.
	// Declare 1 cert type but provide 0 bytes.
	body := []byte{0x01} // says 1 byte follows, but nothing does.
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	if err == nil {
		t.Fatal("expected error for truncated certificate_types, got nil")
	}
}

// TestMessage_CertificateRequest_Truncated_SigAlgs tests truncation at the
// supported_signature_algorithms length prefix.
func TestMessage_CertificateRequest_Truncated_SigAlgs(t *testing.T) {
	t.Parallel()

	// Valid cert types, then only 1 byte of the 2-byte sig_algs length prefix.
	body := []byte{
		0x01, 0x01, // cert_types: length=1, value=0x01.
		0x00, // only 1 byte of the uint16 sig_algs length (truncated).
	}
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	if err == nil {
		t.Fatal("expected error for truncated sig_algs length prefix, got nil")
	}
}

// TestMessage_CertificateRequest_Truncated_CAs tests truncation at the
// certificate_authorities length prefix.
func TestMessage_CertificateRequest_Truncated_CAs(t *testing.T) {
	t.Parallel()

	// Valid cert types and sig_algs, then only 1 byte of the 2-byte CA length prefix.
	body := []byte{
		0x01, 0x01, // cert_types: length=1, value=0x01.
		0x00, 0x02, // sig_algs: length=2 bytes.
		0x04, 0x01, // one sig_alg: sha256+rsa.
		0x00, // only 1 byte of the uint16 CA list length (truncated).
	}
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	if err == nil {
		t.Fatal("expected error for truncated CA list length prefix, got nil")
	}
}

// TestMessage_CertificateRequest_SigAlgsOddByteCount tests that an odd number
// of bytes in the sig_algs section is rejected.
func TestMessage_CertificateRequest_SigAlgsOddByteCount(t *testing.T) {
	t.Parallel()

	body := []byte{
		0x01, 0x01, // cert_types: length=1, value=0x01.
		0x00, 0x03, // sig_algs: length=3 bytes (odd — invalid).
		0x04, 0x01, 0x05, // 3 bytes: can't form whole SigAndHash pairs.
		0x00, 0x00, // CA list: empty.
	}
	envelope := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	if err == nil {
		t.Fatal("expected error for odd sig_algs byte count, got nil")
	}
}

// TestMessage_CertificateRequest_Marshal tests that Marshal returns nil
// (client never sends this message; it is server-only).
func TestMessage_CertificateRequest_Marshal(t *testing.T) {
	t.Parallel()

	cr := &handshake.CertificateRequest{
		CertificateTypes:       []uint8{0x01},
		SupportedSignatureAlgs: []handshake.SigAndHash{{Hash: 0x04, Sig: 0x01}},
	}
	if cr.Marshal() != nil {
		t.Error("CertificateRequest.Marshal() should return nil (client never sends it)")
	}

	if cr.Type() != handshake.TypeCertificateRequest {
		t.Errorf("Type(): got %v, want TypeCertificateRequest", cr.Type())
	}
}

// hexDecode is referenced but also declared above; used for completeness.
var _ = hexDecode
