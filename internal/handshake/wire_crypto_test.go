// verifyECDSASignature, verifyRSASignature, readU16LenPrefixedBuf, readHandshakeRecord,
// buildProtector, and GOST protector builders.
//
//nolint:testpackage // white-box: exercises unexported wire helpers, hashForSigAlg,
package handshake

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// -----------------------------------------------------------------------
// wire.go: readUint8 — truncation error branch
// -----------------------------------------------------------------------.

func TestReadUint8_Empty(t *testing.T) {
	t.Parallel()

	_, _, err := readUint8(nil)
	if err == nil {
		t.Fatal("readUint8(nil): expected error, got nil")
	}

	if !errors.Is(err, errTruncated1) {
		t.Errorf("readUint8(nil): got %v, want wrapping errTruncated1", err)
	}
}

func TestReadUint8_Success(t *testing.T) {
	t.Parallel()

	v, rest, err := readUint8([]byte{0xAB, 0xCD})
	if err != nil {
		t.Fatalf("readUint8: unexpected error: %v", err)
	}

	if v != 0xAB {
		t.Errorf("value: got 0x%02x, want 0xAB", v)
	}

	if !bytes.Equal(rest, []byte{0xCD}) {
		t.Errorf("rest: got %x, want [CD]", rest)
	}
}

// -----------------------------------------------------------------------
// wire.go: readBytes — truncation error branch
// -----------------------------------------------------------------------.

func TestReadBytes_Short(t *testing.T) {
	t.Parallel()

	_, _, err := readBytes([]byte{0x01, 0x02}, 5)
	if err == nil {
		t.Fatal("readBytes with insufficient buffer: expected error, got nil")
	}

	if !errors.Is(err, errNeedBytes) {
		t.Errorf("readBytes: got %v, want wrapping errNeedBytes", err)
	}
}

func TestReadBytes_Exact(t *testing.T) {
	t.Parallel()

	data, rest, err := readBytes([]byte{0x01, 0x02, 0x03, 0x04}, 3)
	if err != nil {
		t.Fatalf("readBytes exact: %v", err)
	}

	if !bytes.Equal(data, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("data: got %x, want [01 02 03]", data)
	}

	if !bytes.Equal(rest, []byte{0x04}) {
		t.Errorf("rest: got %x, want [04]", rest)
	}
}

func TestReadBytes_ZeroLen(t *testing.T) {
	t.Parallel()

	data, rest, err := readBytes([]byte{0xAA}, 0)
	if err != nil {
		t.Fatalf("readBytes(0): %v", err)
	}

	if len(data) != 0 {
		t.Errorf("data: want empty, got %x", data)
	}

	if !bytes.Equal(rest, []byte{0xAA}) {
		t.Errorf("rest: got %x, want [AA]", rest)
	}
}

// -----------------------------------------------------------------------
// client.go: hashForSigAlg — all branches including unknown
// -----------------------------------------------------------------------.

func TestHashForSigAlg_AllKnown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hashByte uint8
		want     crypto.Hash
	}{
		{"SHA1", sigHashSHA1, crypto.SHA1},
		{"SHA256", sigHashByte, crypto.SHA256},
		{"SHA384", sigHashSHA384, crypto.SHA384},
		{"SHA512", sigHashSHA512, crypto.SHA512},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := hashForSigAlg(tc.hashByte)
			if err != nil {
				t.Fatalf("hashForSigAlg(0x%02x): unexpected error: %v", tc.hashByte, err)
			}

			if got != tc.want {
				t.Errorf("hashForSigAlg(0x%02x): got %v, want %v", tc.hashByte, got, tc.want)
			}
		})
	}
}

func TestHashForSigAlg_Unknown(t *testing.T) {
	t.Parallel()

	_, err := hashForSigAlg(0xFF)
	if err == nil {
		t.Fatal("hashForSigAlg(0xFF): expected error for unknown hash, got nil")
	}

	if !errors.Is(err, errUnsupportedHashAlg) {
		t.Errorf("hashForSigAlg(0xFF): got %v, want wrapping errUnsupportedHashAlg", err)
	}
}

// -----------------------------------------------------------------------
// crypto.go: verifyECDSASignature — good and tampered
// -----------------------------------------------------------------------.

func TestVerifyECDSASignature_Good(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := verifyECDSASignature(&priv.PublicKey, digest, sig); err != nil {
		t.Errorf("verifyECDSASignature: unexpected error: %v", err)
	}
}

func TestVerifyECDSASignature_WrongDigest(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := make([]byte, 32)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper digest.
	tampered := make([]byte, 32)

	tampered[0] = 0xFF

	err = verifyECDSASignature(&priv.PublicKey, tampered, sig)
	if err == nil {
		t.Fatal("verifyECDSASignature with tampered digest: expected error, got nil")
	}

	if !errors.Is(err, errECDSAVerifyFailed) {
		t.Errorf("expected errECDSAVerifyFailed, got %v", err)
	}
}

func TestVerifyECDSASignature_TrailingBytes(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := make([]byte, 32)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Append trailing byte to sig.
	sig = append(sig, 0x00)

	err = verifyECDSASignature(&priv.PublicKey, digest, sig)
	if err == nil {
		t.Fatal("verifyECDSASignature with trailing bytes: expected error, got nil")
	}

	if !errors.Is(err, errECDSATrailingBytes) {
		t.Errorf("expected errECDSATrailingBytes, got %v", err)
	}
}

func TestVerifyECDSASignature_MalformedASN1(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := make([]byte, 32)

	// Feed garbage instead of valid DER.
	err = verifyECDSASignature(&priv.PublicKey, digest, []byte{0xFF, 0xFE, 0xFD})
	if err == nil {
		t.Fatal("verifyECDSASignature with malformed ASN1: expected error, got nil")
	}
}

// -----------------------------------------------------------------------
// crypto.go: verifyRSASignature — good and tampered
// -----------------------------------------------------------------------.

func TestVerifyRSASignature_Good(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := verifyRSASignature(&priv.PublicKey, sigHashByte, digest, sig); err != nil {
		t.Errorf("verifyRSASignature: unexpected error: %v", err)
	}
}

func TestVerifyRSASignature_TamperedSignature(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	digest := make([]byte, 32)

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Flip last byte of signature.
	sig[len(sig)-1] ^= 0xFF

	err = verifyRSASignature(&priv.PublicKey, sigHashByte, digest, sig)
	if err == nil {
		t.Fatal("verifyRSASignature with tampered sig: expected error, got nil")
	}
}

func TestVerifyRSASignature_UnknownHash(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	digest := make([]byte, 32)

	err = verifyRSASignature(&priv.PublicKey, 0xFF, digest, []byte{0x01})
	if err == nil {
		t.Fatal("verifyRSASignature with unknown hash: expected error, got nil")
	}

	if !errors.Is(err, errUnsupportedHashAlg) {
		t.Errorf("expected errUnsupportedHashAlg, got %v", err)
	}
}

// -----------------------------------------------------------------------
// client.go: readU16LenPrefixedBuf — truncation branches
// -----------------------------------------------------------------------.

func TestReadU16LenPrefixedBuf_TruncatedPrefix(t *testing.T) {
	t.Parallel()

	// Only 1 byte when 2 are needed for the length prefix.
	_, err := readU16LenPrefixedBuf([]byte{0x00})
	if err == nil {
		t.Fatal("readU16LenPrefixedBuf with 1 byte: expected error, got nil")
	}

	if !errors.Is(err, errU16PrefixTruncated) {
		t.Errorf("expected errU16PrefixTruncated, got %v", err)
	}
}

func TestReadU16LenPrefixedBuf_TruncatedBody(t *testing.T) {
	t.Parallel()

	// Length prefix declares 5 bytes but only 2 follow.
	buf := []byte{0x00, 0x05, 0xAA, 0xBB}

	_, err := readU16LenPrefixedBuf(buf)
	if err == nil {
		t.Fatal("readU16LenPrefixedBuf body truncated: expected error, got nil")
	}

	if !errors.Is(err, errU16BodyTruncated) {
		t.Errorf("expected errU16BodyTruncated, got %v", err)
	}
}

func TestReadU16LenPrefixedBuf_Success(t *testing.T) {
	t.Parallel()

	// Length = 3, body = [AA BB CC], trailing = [DD].
	buf := []byte{0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xDD}

	rest, err := readU16LenPrefixedBuf(buf)
	if err != nil {
		t.Fatalf("readU16LenPrefixedBuf: unexpected error: %v", err)
	}

	if !bytes.Equal(rest, []byte{0xDD}) {
		t.Errorf("rest: got %x, want [DD]", rest)
	}
}

func TestReadU16LenPrefixedBuf_ZeroLength(t *testing.T) {
	t.Parallel()

	// Zero-length field: 2-byte prefix declares 0 bytes. rest = remainder.
	buf := []byte{0x00, 0x00, 0xEE, 0xFF}

	rest, err := readU16LenPrefixedBuf(buf)
	if err != nil {
		t.Fatalf("readU16LenPrefixedBuf zero-length: %v", err)
	}

	if !bytes.Equal(rest, []byte{0xEE, 0xFF}) {
		t.Errorf("rest: got %x, want [EE FF]", rest)
	}
}

// -----------------------------------------------------------------------
// client.go: readHandshakeRecord — alert and unexpected record type branches
// -----------------------------------------------------------------------.

// makeAlertRecord builds a 2-byte fatal alert TLS record.
func makeAlertRecord(level, desc byte) []byte {
	return []byte{
		record.ContentTypeAlert, // 0x15.
		0x03, 0x03,              // TLS 1.2.
		0x00, 0x02, // length = 2.
		level, desc,
	}
}

// makeUnexpectedRecord builds a TLS record with content type 0x17 (AppData during handshake).
func makeUnexpectedRecord() []byte {
	return []byte{
		0x17, // ContentTypeApplicationData.
		0x03, 0x03,
		0x00, 0x01, // length = 1.
		0xFF,
	}
}

func TestReadHandshakeRecord_AlertReceived(t *testing.T) {
	t.Parallel()

	// Build an alert record (level=2 fatal, desc=40 handshake_failure).
	alertData := makeAlertRecord(record.AlertLevelFatal, record.AlertHandshakeFailure)

	rw := &readWriteBuffer{r: bytes.NewBuffer(alertData), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := NewClientState(layer, ClientParams{})

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with alert: expected error, got nil")
	}

	if !errors.Is(err, errAlertReceived) {
		t.Errorf("expected errAlertReceived, got %v", err)
	}
}

func TestReadHandshakeRecord_UnexpectedRecordType(t *testing.T) {
	t.Parallel()

	unexpectedData := makeUnexpectedRecord()

	rw := &readWriteBuffer{r: bytes.NewBuffer(unexpectedData), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := NewClientState(layer, ClientParams{})

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with app-data record: expected error, got nil")
	}

	if !errors.Is(err, errUnexpectedRecordType) {
		t.Errorf("expected errUnexpectedRecordType, got %v", err)
	}
}

func TestReadHandshakeRecord_TruncatedAlertRecord(t *testing.T) {
	t.Parallel()

	// An alert record with only 1 byte payload (< 2).
	alertData := []byte{
		record.ContentTypeAlert,
		0x03, 0x03,
		0x00, 0x01, // length = 1.
		0x02, // only one byte instead of two.
	}

	rw := &readWriteBuffer{r: bytes.NewBuffer(alertData), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := NewClientState(layer, ClientParams{})

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with truncated alert: expected error, got nil")
	}

	if !errors.Is(err, errAlertRecordTruncated) {
		t.Errorf("expected errAlertRecordTruncated, got %v", err)
	}
}

func TestReadHandshakeRecord_HandshakeBodyTruncated(t *testing.T) {
	t.Parallel()

	// A handshake record whose header says body length = 10, but only 2 bytes follow.
	// Envelope: type=0x02 (ServerHello), length=0x00000A (10).
	hsPayload := []byte{
		0x02,             // TypeServerHello.
		0x00, 0x00, 0x0A, // body length = 10.
		0xAA, 0xBB, // only 2 bytes body (< 10).
	}
	rec := make([]byte, 0, 5+len(hsPayload))

	rec = append(rec,
		record.ContentTypeHandshake,
		0x03, 0x03,
		0x00, byte(len(hsPayload)),
	)

	rec = append(rec, hsPayload...)

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := NewClientState(layer, ClientParams{})

	_, _, err := c.readHandshakeRecord()
	if err == nil {
		t.Fatal("readHandshakeRecord with truncated body: expected error, got nil")
	}

	if !errors.Is(err, errHSBodyTruncated) {
		t.Errorf("expected errHSBodyTruncated, got %v", err)
	}
}

// -----------------------------------------------------------------------
// crypto.go: buildProtector — all non-GOST branches (AEAD and CBC)
// -----------------------------------------------------------------------.

func TestBuildProtector_AES128GCM(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	encKey := make([]byte, suite.Cipher.KeyLen)
	iv := make([]byte, suite.Cipher.FixedIVLen)

	prot, err := buildProtector(suite, encKey, nil, iv, rand.Reader)
	if err != nil {
		t.Fatalf("buildProtector AES-128-GCM: %v", err)
	}

	if prot == nil {
		t.Error("buildProtector AES-128-GCM: returned nil protector")
	}
}

func TestBuildProtector_AES256GCM(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES256-GCM-SHA384")
	encKey := make([]byte, suite.Cipher.KeyLen)
	iv := make([]byte, suite.Cipher.FixedIVLen)

	prot, err := buildProtector(suite, encKey, nil, iv, rand.Reader)
	if err != nil {
		t.Fatalf("buildProtector AES-256-GCM: %v", err)
	}

	if prot == nil {
		t.Error("buildProtector AES-256-GCM: returned nil protector")
	}
}

func TestBuildProtector_ChaCha20Poly1305(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-CHACHA20-POLY1305")
	encKey := make([]byte, suite.Cipher.KeyLen)
	iv := make([]byte, suite.Cipher.FixedIVLen)

	prot, err := buildProtector(suite, encKey, nil, iv, rand.Reader)
	if err != nil {
		t.Fatalf("buildProtector ChaCha20-Poly1305: %v", err)
	}

	if prot == nil {
		t.Error("buildProtector ChaCha20-Poly1305: returned nil protector")
	}
}

func TestBuildProtector_AES128CBC_SHA256(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-SHA256")
	encKey := make([]byte, suite.Cipher.KeyLen)
	macKey := make([]byte, suite.MAC.KeyLen)

	prot, err := buildProtector(suite, encKey, macKey, nil, rand.Reader)
	if err != nil {
		t.Fatalf("buildProtector AES-128-CBC/SHA-256: %v", err)
	}

	if prot == nil {
		t.Error("buildProtector AES-128-CBC/SHA-256: returned nil protector")
	}
}

func TestBuildProtector_AES256CBC_SHA384(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "ECDHE-RSA-AES256-SHA384")
	encKey := make([]byte, suite.Cipher.KeyLen)
	macKey := make([]byte, suite.MAC.KeyLen)

	prot, err := buildProtector(suite, encKey, macKey, nil, rand.Reader)
	if err != nil {
		t.Fatalf("buildProtector AES-256-CBC/SHA-384: %v", err)
	}

	if prot == nil {
		t.Error("buildProtector AES-256-CBC/SHA-384: returned nil protector")
	}
}

// -----------------------------------------------------------------------
// protector_gost.go: buildGOSTProtector, buildKuznyechikCTROMACProtector,
// buildMagmaCTROMACProtector — unit tests with synthetic key material
// -----------------------------------------------------------------------.

func TestBuildGOSTProtector_GOST2001Suite(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2001-GOST89-GOST89")
	encKey := make([]byte, suite.Cipher.KeyLen) // 32 bytes.
	macKey := make([]byte, suite.MAC.KeyLen)    // 32 bytes.
	iv := make([]byte, suite.Cipher.FixedIVLen) // 8 bytes.

	prot, err := buildGOSTProtector(suite, encKey, macKey, iv)
	if err != nil {
		t.Fatalf("buildGOSTProtector (GOST2001): %v", err)
	}

	if prot == nil {
		t.Error("buildGOSTProtector: returned nil protector")
	}
}

func TestBuildGOSTProtector_GOST2012Suite(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2012-GOST8912-GOST8912")
	encKey := make([]byte, suite.Cipher.KeyLen) // 32 bytes.
	macKey := make([]byte, suite.MAC.KeyLen)    // 32 bytes.
	iv := make([]byte, suite.Cipher.FixedIVLen) // 8 bytes.

	prot, err := buildGOSTProtector(suite, encKey, macKey, iv)
	if err != nil {
		t.Fatalf("buildGOSTProtector (GOST2012_256): %v", err)
	}

	if prot == nil {
		t.Error("buildGOSTProtector (GOST2012_256): returned nil protector")
	}
}

func TestBuildKuznyechikCTROMACProtector(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
	encKey := make([]byte, suite.Cipher.KeyLen) // 32 bytes.
	macKey := make([]byte, suite.MAC.KeyLen)    // 32 bytes.
	iv := make([]byte, suite.Cipher.FixedIVLen) // 16 bytes.

	prot, err := buildKuznyechikCTROMACProtector(suite, encKey, macKey, iv)
	if err != nil {
		t.Fatalf("buildKuznyechikCTROMACProtector: %v", err)
	}

	if prot == nil {
		t.Error("buildKuznyechikCTROMACProtector: returned nil protector")
	}
}

func TestBuildMagmaCTROMACProtector(t *testing.T) {
	t.Parallel()

	suite := mustFindSuiteByName(t, "GOST2012-MAGMA-MAGMAOMAC")
	encKey := make([]byte, suite.Cipher.KeyLen) // 32 bytes.
	macKey := make([]byte, suite.MAC.KeyLen)    // 32 bytes.
	iv := make([]byte, suite.Cipher.FixedIVLen) // 8 bytes.

	prot, err := buildMagmaCTROMACProtector(suite, encKey, macKey, iv)
	if err != nil {
		t.Fatalf("buildMagmaCTROMACProtector: %v", err)
	}

	if prot == nil {
		t.Error("buildMagmaCTROMACProtector: returned nil protector")
	}
}

// buildProtector routes GOST suites through the GOST builders; verify
// that routing is correct via buildProtector itself.
func TestBuildProtector_GOSTRouting(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		cipher string
	}{
		{"GOST28147-CNT", "GOST2001-GOST89-GOST89"},
		{"KUZNYECHIK-CTR-OMAC", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC"},
		{"MAGMA-CTR-OMAC", "GOST2012-MAGMA-MAGMAOMAC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			suite := mustFindSuiteByName(t, tc.cipher)
			encKey := make([]byte, suite.Cipher.KeyLen)
			macKey := make([]byte, suite.MAC.KeyLen)
			iv := make([]byte, suite.Cipher.FixedIVLen)

			prot, err := buildProtector(suite, encKey, macKey, iv, rand.Reader)
			if err != nil {
				t.Fatalf("buildProtector(%q): %v", tc.cipher, err)
			}

			if prot == nil {
				t.Errorf("buildProtector(%q): returned nil", tc.cipher)
			}
		})
	}
}

// -----------------------------------------------------------------------
// client.go: verifySignature — unsupported sig alg branch
// -----------------------------------------------------------------------.

func TestVerifySignature_UnsupportedSigAlg(t *testing.T) {
	t.Parallel()

	cert := buildMinimalRSACert2(t)

	signed := make([]byte, 32)
	sig := []byte{0xDE, 0xAD}

	// sig alg 0xFF is not RSA (0x01) or ECDSA (0x03).
	err := verifySignature(cert, sigHashByte, 0xFF, signed, sig)
	if err == nil {
		t.Fatal("verifySignature with unknown sig alg: expected error, got nil")
	}

	if !errors.Is(err, errUnsupportedSigAlg) {
		t.Errorf("expected errUnsupportedSigAlg, got %v", err)
	}
}

// TestVerifySignature_CertNotRSA checks the "cert not RSA" branch when
// sigAlg=RSA but the cert has an ECDSA key.
func TestVerifySignature_CertNotRSA(t *testing.T) {
	t.Parallel()

	cert := buildMinimalECDSACert2(t)

	signed := make([]byte, 32)
	sig := make([]byte, 64)

	err := verifySignature(cert, sigHashByte, sigAlgRSA, signed, sig)
	if err == nil {
		t.Fatal("verifySignature: expected errCertNotRSA, got nil")
	}

	if !errors.Is(err, errCertNotRSA) {
		t.Errorf("expected errCertNotRSA, got %v", err)
	}
}

// TestVerifySignature_CertNotECDSA checks the "cert not ECDSA" branch.
func TestVerifySignature_CertNotECDSA(t *testing.T) {
	t.Parallel()

	cert := buildMinimalRSACert2(t)

	// Build a valid ECDSA ASN1 signature so ASN1 parsing doesn't fail first.
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	digest := make([]byte, 32)

	sig, err := ecdsa.SignASN1(rand.Reader, privEC, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	err = verifySignature(cert, sigHashByte, sigAlgECDSA, digest, sig)
	if err == nil {
		t.Fatal("verifySignature: expected errCertNotECDSA, got nil")
	}

	if !errors.Is(err, errCertNotECDSA) {
		t.Errorf("expected errCertNotECDSA, got %v", err)
	}
}

// -----------------------------------------------------------------------
// ECDSA signature helpers for inline cert building
// -----------------------------------------------------------------------.

// buildMinimalRSACert2 returns a *x509.Certificate with an RSA public key.
func buildMinimalRSACert2(t *testing.T) *x509.Certificate {
	t.Helper()

	_, cert, _ := newTestRSACert(t)

	return cert
}

// buildMinimalECDSACert2 returns a *x509.Certificate with an ECDSA public key.
func buildMinimalECDSACert2(t *testing.T) *x509.Certificate {
	t.Helper()

	_, cert := newTestECDSACert(t)

	return cert
}

// -----------------------------------------------------------------------
// Helper: mustFindSuiteByName panics-safe lookup
// -----------------------------------------------------------------------.

func mustFindSuiteByName(t *testing.T, name string) *suites.Suite {
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
// Test ECDSA ASN1 sig struct (for the asn1 parse error branch of
// verifyECDSASignature): ensure the R,S struct unmarshal fails gracefully.
// -----------------------------------------------------------------------.

func TestVerifyECDSASignature_ASN1ParseError(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Valid signature but with wrong ASN1 structure — marshal R only (missing S).
	partial, err := asn1.Marshal(struct{ R *big.Int }{R: big.NewInt(12345)})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}

	digest := make([]byte, 32)

	err = verifyECDSASignature(&priv.PublicKey, digest, partial)
	// Should error: unmarshalling a struct{R} where struct{R,S} is expected
	// leaves trailing bytes — hits errECDSATrailingBytes, or fails with ASN1 parse error.
	if err == nil {
		t.Fatal("verifyECDSASignature with partial ASN1: expected error, got nil")
	}
}
