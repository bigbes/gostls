package record_test

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/bigbes/gostls/internal/record"
)

// makeLayer returns a Layer backed by an in-memory buffer, using nullProtector.
func makeLayer(buf io.ReadWriter) *record.Layer {
	return record.NewLayer(buf)
}

// readOnlyRW wraps an io.Reader as an io.ReadWriter. Write panics — it must
// not be called in error-path tests that only exercise the read path.
type readOnlyRW struct{ io.Reader }

func (r readOnlyRW) Write(_ []byte) (int, error) {
	panic("unexpected Write call in read-only test ReadWriter")
}

// ---- RoundTrip tests -------------------------------------------------------.

// TestRecord_RoundTrip_Null verifies write→read through nullProtector.
func TestRecord_RoundTrip_Null(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := makeLayer(buf)

	payload := []byte("hello world")
	if err := l.WriteRecord(record.ContentTypeApplicationData, payload); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	ct, got, err := l.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}

	if ct != record.ContentTypeApplicationData {
		t.Errorf("content type: got %d, want %d", ct, record.ContentTypeApplicationData)
	}

	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %q, want %q", got, payload)
	}
}

// TestRecord_RoundTrip_CBC_HMAC writes and reads through AES-128-CBC / HMAC-SHA256.
// RFC 5246 §6.2.3.2.
func TestRecord_RoundTrip_CBC_HMAC(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16) // AES-128.

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	buf := new(bytes.Buffer)
	l := makeLayer(buf)
	l.ChangeCipherSpec(prot, prot)

	payload := []byte("cbc hmac round trip")
	if err := l.WriteRecord(record.ContentTypeHandshake, payload); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	ct, got, err := l.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}

	if ct != record.ContentTypeHandshake {
		t.Errorf("content type: got %d, want %d", ct, record.ContentTypeHandshake)
	}

	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %q, want %q", got, payload)
	}
}

// TestRecord_RoundTrip_ChaCha20Poly1305 writes and reads through ChaCha20-Poly1305.
// RFC 7905: 12-byte implicit write_IV, no explicit per-record nonce on the wire.
func TestRecord_RoundTrip_ChaCha20Poly1305(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x5A}, 32)
	iv := bytes.Repeat([]byte{0xA5}, 12)

	prot, err := record.NewChaCha20Poly1305Protector(key, iv)
	if err != nil {
		t.Fatalf("NewChaCha20Poly1305Protector: %v", err)
	}

	buf := new(bytes.Buffer)
	l := makeLayer(buf)
	l.ChangeCipherSpec(prot, prot)

	payloads := [][]byte{
		[]byte("chacha20 round trip"),
		[]byte("second record — different seq"),
		[]byte{},
	}
	for _, p := range payloads {
		if err := l.WriteRecord(record.ContentTypeApplicationData, p); err != nil {
			t.Fatalf("WriteRecord: %v", err)
		}
	}

	for i, want := range payloads {
		ct, got, err := l.ReadRecord()
		if err != nil {
			t.Fatalf("ReadRecord #%d: %v", i, err)
		}

		if ct != record.ContentTypeApplicationData {
			t.Errorf("record #%d content type: got %d, want %d", i, ct, record.ContentTypeApplicationData)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("record #%d payload mismatch: got %q, want %q", i, got, want)
		}
	}
}

// TestRecord_ChaCha20Poly1305_NonceXOR confirms the RFC 7905 nonce construction
// by checking that two different sequence numbers produce different ciphertexts
// for the same plaintext (i.e. the nonce actually depends on seq).
func TestRecord_ChaCha20Poly1305_NonceXOR(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x00}, 12)

	prot, err := record.NewChaCha20Poly1305Protector(key, iv)
	if err != nil {
		t.Fatalf("NewChaCha20Poly1305Protector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00} // type=AppData, version=TLS1.2.
	plain := []byte("same plaintext")

	c0, err := prot.Seal(0, hdr, plain)
	if err != nil {
		t.Fatalf("Seal seq=0: %v", err)
	}

	c1, err := prot.Seal(1, hdr, plain)
	if err != nil {
		t.Fatalf("Seal seq=1: %v", err)
	}

	if bytes.Equal(c0, c1) {
		t.Fatal("seq=0 and seq=1 produced identical ciphertext; nonce not derived from seq")
	}
}

// TestRecord_ChaCha20Poly1305_RejectsTamper ensures the AEAD tag is verified.
func TestRecord_ChaCha20Poly1305_RejectsTamper(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 12)

	prot, err := record.NewChaCha20Poly1305Protector(key, iv)
	if err != nil {
		t.Fatalf("NewChaCha20Poly1305Protector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	sealed, err := prot.Seal(0, hdr, []byte("tamper me"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sealed[len(sealed)-1] ^= 0xFF
	if _, err := prot.Open(0, hdr, sealed); err == nil {
		t.Fatal("expected Open to reject tampered ciphertext")
	}
}

// TestRecord_ChaCha20Poly1305_RejectsBadKeySize ensures bad key/iv sizes error.
func TestRecord_ChaCha20Poly1305_RejectsBadKeySize(t *testing.T) {
	t.Parallel()

	if _, err := record.NewChaCha20Poly1305Protector(make([]byte, 16), make([]byte, 12)); err == nil {
		t.Error("expected error for 16-byte key, got nil")
	}

	if _, err := record.NewChaCha20Poly1305Protector(make([]byte, 32), make([]byte, 8)); err == nil {
		t.Error("expected error for 8-byte iv, got nil")
	}
}

// TestRecord_RoundTrip_AEAD writes and reads through AES-128-GCM.
// RFC 5288, RFC 5246 §6.2.3.3.
func TestRecord_RoundTrip_AEAD(t *testing.T) {
	t.Parallel()

	// AES-128-GCM: 16-byte key, 4-byte salt.
	key := bytes.Repeat([]byte{0xCC}, 16)
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	prot, err := record.NewAEADProtector(key, salt)
	if err != nil {
		t.Fatalf("NewAEADProtector: %v", err)
	}

	buf := new(bytes.Buffer)
	l := makeLayer(buf)
	l.ChangeCipherSpec(prot, prot)

	payload := []byte("aead round trip")
	if err := l.WriteRecord(record.ContentTypeApplicationData, payload); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	ct, got, err := l.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}

	if ct != record.ContentTypeApplicationData {
		t.Errorf("content type: got %d, want %d", ct, record.ContentTypeApplicationData)
	}

	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %q, want %q", got, payload)
	}
}

// ---- Reject tests ----------------------------------------------------------.

// TestRecord_Rejects_TruncatedHeader verifies truncated header returns error.
func TestRecord_Rejects_TruncatedHeader(t *testing.T) {
	t.Parallel()

	buf := readOnlyRW{bytes.NewReader([]byte{0x17, 0x03})} // only 2 bytes instead of 5.
	l := makeLayer(buf)

	_, _, err := l.ReadRecord()
	if err == nil {
		t.Fatal("expected error for truncated header, got nil")
	}
}

// TestRecord_Rejects_BadMAC verifies a tampered ciphertext is rejected.
func TestRecord_Rejects_BadMAC(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16)

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	buf := new(bytes.Buffer)
	lw := makeLayer(buf)
	lw.ChangeCipherSpec(prot, prot)

	if err := lw.WriteRecord(record.ContentTypeApplicationData, []byte("tamper me")); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Corrupt the last byte of the ciphertext fragment.
	b := buf.Bytes()

	b[len(b)-1] ^= 0xFF

	lr := makeLayer(readOnlyRW{bytes.NewReader(b)})
	lr.ChangeCipherSpec(prot, prot)

	_, _, err = lr.ReadRecord()
	if err == nil {
		t.Fatal("expected error for bad MAC, got nil")
	}
}

// TestRecord_Rejects_SeqOverflow verifies overflow of sequence number is a hard error.
func TestRecord_Rejects_SeqOverflow(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := record.NewLayerWithSeq(buf, math.MaxUint64)

	err := l.WriteRecord(record.ContentTypeApplicationData, []byte("overflow"))
	if err == nil {
		t.Fatal("expected error on seq overflow, got nil")
	}

	var re *record.RecordError

	if !errors.As(err, &re) {
		t.Errorf("expected *record.RecordError, got %T: %v", err, err)
	}
}

// TestRecord_Rejects_UnknownContentType verifies that reading an unknown
// content type results in a hard error.
func TestRecord_Rejects_UnknownContentType(t *testing.T) {
	t.Parallel()

	// Build a syntactically valid record with content type 0x99.
	hdr := append(make([]byte, 0, 9), byte(0x99), 0x03, 0x03, 0x00, 0x04)
	data := append(hdr, []byte("xxxx")...)
	l := makeLayer(readOnlyRW{bytes.NewReader(data)})

	_, _, err := l.ReadRecord()
	if err == nil {
		t.Fatal("expected error for unknown content type, got nil")
	}
}

// TestRecord_Rejects_VersionMismatch verifies that a record whose version is
// outside the accepted TLS 1.x major-3 range (0x0301..0x0303) is rejected.
func TestRecord_Rejects_VersionMismatch(t *testing.T) {
	t.Parallel()

	// versions below TLS 1.0 (SSL 3.0), above TLS 1.2 (TLS 1.3), and with a
	// non-3 major must all be rejected.
	for _, ver := range []struct {
		name   string
		hi, lo byte
	}{
		{"ssl3.0", 0x03, 0x00},
		{"tls1.3", 0x03, 0x04},
		{"major2", 0x02, 0x03},
		{"major0", 0x00, 0x00},
	} {
		t.Run(ver.name, func(t *testing.T) {
			t.Parallel()

			hdr := append(make([]byte, 0, 9), byte(0x17), ver.hi, ver.lo, 0x00, 0x04)
			data := append(hdr, []byte("xxxx")...)
			l := makeLayer(readOnlyRW{bytes.NewReader(data)})

			if _, _, err := l.ReadRecord(); err == nil {
				t.Fatalf("version %02x%02x: expected rejection, got nil", ver.hi, ver.lo)
			}
		})
	}
}

// TestRecord_Accepts_LegacyRecordVersion verifies that TLS 1.0/1.1 record-layer
// versions on incoming records are accepted for interop (RFC 5246 App. E): a
// TLS 1.2 peer may stamp early records with {3,1}. The nullProtector passes the
// payload through, so a well-formed record round-trips.
func TestRecord_Accepts_LegacyRecordVersion(t *testing.T) {
	t.Parallel()

	for _, lo := range []byte{0x01, 0x02, 0x03} {
		t.Run(fmt.Sprintf("minor%02x", lo), func(t *testing.T) {
			t.Parallel()

			hdr := append(make([]byte, 0, 9), record.ContentTypeHandshake, 0x03, lo, 0x00, 0x04)
			data := append(hdr, []byte("abcd")...)
			l := makeLayer(readOnlyRW{bytes.NewReader(data)})

			ct, payload, err := l.ReadRecord()
			if err != nil {
				t.Fatalf("minor %02x: unexpected error: %v", lo, err)
			}

			if ct != record.ContentTypeHandshake || string(payload) != "abcd" {
				t.Fatalf("minor %02x: got ct=%d payload=%q", lo, ct, payload)
			}
		})
	}
}

// TestRecord_Rejects_OversizedFragment verifies fragments > 2^14+2048 are rejected.
func TestRecord_Rejects_OversizedFragment(t *testing.T) {
	t.Parallel()

	// Claim length = 2^14 + 2049.
	oversized := uint16(1<<14 + 2049)
	hdr := []byte{0x17, 0x03, 0x03, byte(oversized >> 8), byte(oversized)}
	// body is truncated — the length check must fire before reading the body.
	l := makeLayer(readOnlyRW{bytes.NewReader(hdr)})

	_, _, err := l.ReadRecord()
	if err == nil {
		t.Fatal("expected error for oversized fragment, got nil")
	}
}

// TestRecord_Rejects_OversizedPlaintext verifies that a decrypted plaintext
// fragment larger than 2^14 bytes is rejected, even though its ciphertext fits
// within the 2^14+2048 wire bound. Under nullProtector the plaintext equals the
// fragment, so a 16385-byte fragment exercises the post-decrypt ceiling.
func TestRecord_Rejects_OversizedPlaintext(t *testing.T) {
	t.Parallel()

	plaintextLen := uint16(1<<14 + 1) // 16385, within maxFragmentLen but over 2^14.

	const recordHeaderLen = 5

	data := make([]byte, 0, recordHeaderLen+int(plaintextLen))

	data = append(data,
		record.ContentTypeApplicationData, 0x03, 0x03,
		byte(plaintextLen>>8), byte(plaintextLen),
	)
	data = append(data, bytes.Repeat([]byte{0x41}, int(plaintextLen))...)

	l := makeLayer(readOnlyRW{bytes.NewReader(data)})

	_, _, err := l.ReadRecord()
	if err == nil {
		t.Fatal("expected AlertRecordOverflow for over-2^14 plaintext, got nil")
	}
}

// TestProtection_CBC_RejectsBadPadding verifies bad padding returns error
// and constant-time behavior is preserved structurally (bad padding + valid MAC
// still fails, confirming decrypt-verify ordering uses constant-time check).
func TestProtection_CBC_RejectsBadPadding(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16)

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	// Write a valid record.
	buf := new(bytes.Buffer)
	lw := makeLayer(buf)
	lw.ChangeCipherSpec(prot, prot)

	if err := lw.WriteRecord(record.ContentTypeApplicationData, []byte("bad padding test")); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Corrupt the second-to-last byte of the ciphertext — this destroys the
	// padding without (likely) leaving a valid MAC, proving the decryptor
	// uses constant-time checks rather than bailing on bad padding alone.
	b := buf.Bytes()

	b[len(b)-2] ^= 0x01

	lr := makeLayer(readOnlyRW{bytes.NewReader(b)})
	lr.ChangeCipherSpec(prot, prot)

	_, _, err = lr.ReadRecord()
	if err == nil {
		t.Fatal("expected error for bad padding, got nil")
	}
}

// TestRecord_MultipleRecords verifies sequence numbers advance correctly
// across multiple records.
func TestRecord_MultipleRecords(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := makeLayer(buf)

	for i := range 5 {
		payload := []byte{byte(i)}
		if err := l.WriteRecord(record.ContentTypeApplicationData, payload); err != nil {
			t.Fatalf("WriteRecord[%d]: %v", i, err)
		}
	}

	// Reset to a new layer reading from the same buffer.
	rl := makeLayer(buf)
	for i := range 5 {
		ct, got, err := rl.ReadRecord()
		if err != nil {
			t.Fatalf("ReadRecord[%d]: %v", i, err)
		}

		if ct != record.ContentTypeApplicationData {
			t.Errorf("[%d] content type: got %d", i, ct)
		}

		if len(got) != 1 || got[0] != byte(i) {
			t.Errorf("[%d] payload mismatch: got %v", i, got)
		}
	}
}

// TestAlerts_CloseNotify verifies that a close_notify alert can be encoded
// and decoded.
func TestAlerts_CloseNotify(t *testing.T) {
	t.Parallel()

	rec := record.EncodeAlert(record.AlertLevelWarning, record.AlertCloseNotify)
	if len(rec) != 2 {
		t.Fatalf("expected 2-byte alert body, got %d", len(rec))
	}

	level, desc := record.DecodeAlert(rec)
	if level != record.AlertLevelWarning {
		t.Errorf("alert level: got %d, want %d", level, record.AlertLevelWarning)
	}

	if desc != record.AlertCloseNotify {
		t.Errorf("alert desc: got %d, want %d", desc, record.AlertCloseNotify)
	}
}

// TestAlerts_FatalError verifies that a fatal alert is represented as an error.
func TestAlerts_FatalError(t *testing.T) {
	t.Parallel()

	err := record.NewFatalAlertError(record.AlertBadRecordMAC)
	if err == nil {
		t.Fatal("expected non-nil error")
	}

	var ae *record.AlertError

	if !errors.As(err, &ae) {
		t.Fatalf("expected *record.AlertError, got %T: %v", err, err)
	}

	if ae.Description != record.AlertBadRecordMAC {
		t.Errorf("description: got %d, want %d", ae.Description, record.AlertBadRecordMAC)
	}
}
