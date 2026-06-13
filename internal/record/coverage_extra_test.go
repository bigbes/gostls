// coverage_extra_test.go — additional tests to raise branch coverage in
// protection.go, protection_ctromac_gost.go, protection_gost.go, and record.go.
package record_test

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/record"
)

// TestAEADProtector_BadSalt verifies that a salt not exactly 4 bytes returns
// an error (the early-return branch in NewAEADProtector).
func TestAEADProtector_BadSalt(t *testing.T) {
	t.Parallel()

	for _, saltLen := range []int{0, 3, 5, 8} {
		if _, err := record.NewAEADProtector(make([]byte, 16), make([]byte, saltLen)); err == nil {
			t.Errorf("NewAEADProtector: salt len=%d: expected error, got nil", saltLen)
		}
	}
}

// TestAEADProtector_BadKey verifies that an invalid key length is rejected.
// aes.NewCipher accepts 16, 24, or 32 bytes; anything else errors.
func TestAEADProtector_BadKey(t *testing.T) {
	t.Parallel()

	salt := []byte{0x01, 0x02, 0x03, 0x04}

	for _, keyLen := range []int{0, 7, 15, 17} {
		if _, err := record.NewAEADProtector(make([]byte, keyLen), salt); err == nil {
			t.Errorf("NewAEADProtector: key len=%d: expected error, got nil", keyLen)
		}
	}
}

// TestAEADProtector_Open_ShortFragment covers the "fragment too short" branch
// in aeadProtector.Open (fragment < explicitNonceLen+tagSize).
func TestAEADProtector_Open_ShortFragment(t *testing.T) {
	t.Parallel()

	p, err := record.NewAEADProtector(make([]byte, 16), []byte{0, 0, 0, 0})
	if err != nil {
		t.Fatalf("NewAEADProtector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	// tagSize=16, explicitNonce=8 → minimum=24; feed 10 bytes.
	if _, err := p.Open(0, hdr, make([]byte, 10)); err == nil {
		t.Fatal("Open(short fragment): expected error, got nil")
	}
}

// TestAEADProtector_Open_BadTag covers the AEAD.Open authentication-failure
// branch (tampered ciphertext after valid structure).
func TestAEADProtector_Open_BadTag(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xAB}, 16)
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	p, err := record.NewAEADProtector(key, salt)
	if err != nil {
		t.Fatalf("NewAEADProtector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x05}

	sealed, err := p.Seal(0, hdr, []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a bit in the AEAD tag (last byte of the sealed fragment).
	tampered := make([]byte, len(sealed))

	copy(tampered, sealed)

	tampered[len(tampered)-1] ^= 0xFF

	_, openErr := p.Open(0, hdr, tampered)
	if openErr == nil {
		t.Fatal("Open(bad tag): expected error, got nil")
	}

	var ae *record.AlertError

	if !errors.As(openErr, &ae) {
		t.Fatalf("expected *AlertError, got %T: %v", openErr, openErr)
	}
}

// TestCBCHMACProtector_BadEncKey verifies that a bad encryption key causes
// NewCBCHMACProtector to return an error (delegated from newCipher).
func TestCBCHMACProtector_BadEncKey(t *testing.T) {
	t.Parallel()

	// aes.NewCipher rejects a 7-byte key.
	if _, err := record.NewCBCHMACProtector(
		aes.NewCipher, sha256.New, make([]byte, 7), make([]byte, 32),
	); err == nil {
		t.Fatal("NewCBCHMACProtector: bad enc key: expected error, got nil")
	}
}

// TestCBCHMACProtector_Seal_PaddingVariants exercises cbcHMACProtector.Seal
// with plaintext lengths that produce different padding values (covering the
// padLen adjustment branch when (contentLen+1) % blockSize == 0).
func TestCBCHMACProtector_Seal_PaddingVariants(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16) // AES-128, blockSize=16.
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	// Exercise several plaintext lengths around block boundaries.
	// macSize=32, blockSize=16: contentLen = len(plain)+32.
	// padLen = blockSize - (contentLen+1)%blockSize.
	// When contentLen+1 is a multiple of blockSize, the raw padLen is 0 → adjusts to blockSize-1.
	for _, plainLen := range []int{0, 1, 15, 16, 31, 32, 47} {
		plain := make([]byte, plainLen)

		for i := range plain {
			plain[i] = byte(i)
		}

		sealProt, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
		if err != nil {
			t.Fatalf("len=%d NewCBCHMACProtector (seal): %v", plainLen, err)
		}

		openProt, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
		if err != nil {
			t.Fatalf("len=%d NewCBCHMACProtector (open): %v", plainLen, err)
		}

		sealed, err := sealProt.Seal(0, hdr, plain)
		if err != nil {
			t.Fatalf("len=%d Seal: %v", plainLen, err)
		}

		got, err := openProt.Open(0, hdr, sealed)
		if err != nil {
			t.Fatalf("len=%d Open: %v", plainLen, err)
		}

		if !bytes.Equal(got, plain) {
			t.Errorf("len=%d: plaintext mismatch", plainLen)
		}
	}
}

// TestCBCHMACProtector_Open_ShortFragment covers the short-fragment guard in
// cbcHMACProtector.Open: fragment < blockSize+macSize+1 must return error.
func TestCBCHMACProtector_Open_ShortFragment(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	// blockSize=16, macSize=32 → minimum=49. Feed 30 bytes.
	if _, err := prot.Open(0, hdr, make([]byte, 30)); err == nil {
		t.Fatal("Open(short): expected error, got nil")
	}
}

// TestCBCHMACProtector_Open_NonBlockAligned covers the fragment-not-block-aligned
// guard in cbcHMACProtector.Open.
func TestCBCHMACProtector_Open_NonBlockAligned(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	// Feed a length that is ≥ minimum but not a multiple of blockSize=16.
	// Use 49 bytes (= 16+32+1 = minimum, but 49 % 16 = 1 → not aligned).
	if _, err := prot.Open(0, hdr, make([]byte, 49)); err == nil {
		t.Fatal("Open(non-aligned): expected error, got nil")
	}
}

// TestWriteRecord_UnknownContentType verifies that writing with an unknown
// content type returns an error without touching the wire.
func TestWriteRecord_UnknownContentType(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := record.NewLayer(buf)

	if err := l.WriteRecord(0x42, []byte("data")); err == nil {
		t.Fatal("WriteRecord(unknown ct): expected error, got nil")
	}

	if buf.Len() != 0 {
		t.Errorf("WriteRecord(unknown ct): wrote %d bytes to wire, expected 0", buf.Len())
	}
}

// TestWriteRecord_OversizedPayload verifies that payload > 2^14 bytes returns
// an error.
func TestWriteRecord_OversizedPayload(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := record.NewLayer(buf)

	payload := make([]byte, 1<<14+1)

	if err := l.WriteRecord(record.ContentTypeApplicationData, payload); err == nil {
		t.Fatal("WriteRecord(oversized): expected error, got nil")
	}
}

// TestWriteRecord_WriteError verifies that an io.Writer error is propagated.
func TestWriteRecord_WriteError(t *testing.T) {
	t.Parallel()

	rw := &errWriter{err: io.ErrClosedPipe}
	l := record.NewLayer(rw)

	if err := l.WriteRecord(record.ContentTypeHandshake, []byte("data")); err == nil {
		t.Fatal("WriteRecord(write error): expected error, got nil")
	}
}

// errWriter is an io.ReadWriter that always returns an error on Write.
type errWriter struct {
	err error
}

func (e *errWriter) Write(_ []byte) (int, error) { return 0, e.err }
func (e *errWriter) Read(_ []byte) (int, error)  { return 0, e.err }

// secondWriteFailer succeeds on the first Write call (the header) and returns
// an error on all subsequent Write calls (the fragment).
type secondWriteFailer struct {
	calls int
	err   error
}

func (s *secondWriteFailer) Write(p []byte) (int, error) {
	s.calls++

	if s.calls > 1 {
		return 0, s.err
	}

	return len(p), nil
}

func (s *secondWriteFailer) Read(_ []byte) (int, error) { return 0, io.EOF }

// TestWriteRecord_FragmentWriteError verifies that an error on the second wire
// Write (the fragment) is propagated by WriteRecord (record.go line ~151).
func TestWriteRecord_FragmentWriteError(t *testing.T) {
	t.Parallel()

	rw := &secondWriteFailer{err: io.ErrClosedPipe}
	l := record.NewLayer(rw)

	if err := l.WriteRecord(record.ContentTypeHandshake, []byte("data")); err == nil {
		t.Fatal("WriteRecord(fragment write error): expected error, got nil")
	}
}

// sealErrProtector is a Protector whose Seal always returns an error.
type sealErrProtector struct{}

func (sealErrProtector) Seal(_ uint64, _, _ []byte) ([]byte, error) {
	return nil, io.ErrClosedPipe
}

func (sealErrProtector) Open(_ uint64, _, fragment []byte) ([]byte, error) {
	out := make([]byte, len(fragment))

	copy(out, fragment)

	return out, nil
}

// TestWriteRecord_SealError verifies that a Protector.Seal error is propagated
// by WriteRecord (record.go ~line 140).
func TestWriteRecord_SealError(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := record.NewLayer(buf)
	l.ChangeCipherSpec(sealErrProtector{}, nil)

	if err := l.WriteRecord(record.ContentTypeHandshake, []byte("data")); err == nil {
		t.Fatal("WriteRecord(seal error): expected error, got nil")
	}
}

// TestReadRecord_SeqOverflow verifies that ReadRecord returns an error on
// sequence number overflow.
func TestReadRecord_SeqOverflow(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)

	// Write a valid TLS 1.2 record into the buffer manually.
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0xFF} // 5-byte hdr + 1-byte body.

	_, _ = buf.Write(hdr)

	const maxUint64 = ^uint64(0)

	l := record.NewLayerWithSeq(buf, maxUint64)

	_, _, err := l.ReadRecord()
	if err == nil {
		t.Fatal("ReadRecord(seqOverflow): expected error, got nil")
	}

	var re *record.RecordError

	if !errors.As(err, &re) {
		t.Errorf("expected *RecordError, got %T: %v", err, err)
	}
}

// TestReadRecord_BodyReadError verifies that a truncated body (header read OK
// but body read fails) propagates the io error.
func TestReadRecord_BodyReadError(t *testing.T) {
	t.Parallel()

	// Valid TLS 1.2 record header claiming 10 bytes but only 3 bytes of body.
	// content type=handshake(22), version=TLS1.2, length=10.
	data := []byte{0x16, 0x03, 0x03, 0x00, 0x0A, 0xAA, 0xBB, 0xCC} // header + 3 body bytes.

	l := record.NewLayer(readOnlyRW{bytes.NewReader(data)})

	_, _, err := l.ReadRecord()
	if err == nil {
		t.Fatal("ReadRecord(short body): expected error, got nil")
	}
}

// TestCTROMACProtector_Open_ShortFragment verifies that Open returns a fatal
// AlertBadRecordMAC when the fragment is shorter than tagSize for both Kuznyechik
// (tagSize=16) and Magma (tagSize=8).
func TestCTROMACProtector_Open_ShortFragment(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xAA}, 32)
	macKey := bytes.Repeat([]byte{0xBB}, 32)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	t.Run("Kuznyechik_tagSize16", func(t *testing.T) {
		t.Parallel()

		p, err := record.NewKuznyechikCTROMACProtector(encKey, macKey, bytes.Repeat([]byte{0x01}, 8))
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}

		// Feed 10 bytes (< 16=tagSize).
		_, err = p.Open(0, hdr, make([]byte, 10))
		if err == nil {
			t.Fatal("Open(short): expected error, got nil")
		}

		var ae *record.AlertError

		if !errors.As(err, &ae) || ae.Description != record.AlertBadRecordMAC {
			t.Errorf("expected AlertBadRecordMAC, got %v", err)
		}
	})

	t.Run("Magma_tagSize8", func(t *testing.T) {
		t.Parallel()

		p, err := record.NewMagmaCTROMACProtector(encKey, macKey, bytes.Repeat([]byte{0x02}, 4))
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}

		// Feed 4 bytes (< 8=tagSize).
		_, err = p.Open(0, hdr, make([]byte, 4))
		if err == nil {
			t.Fatal("Open(short): expected error, got nil")
		}

		var ae *record.AlertError

		if !errors.As(err, &ae) || ae.Description != record.AlertBadRecordMAC {
			t.Errorf("expected AlertBadRecordMAC, got %v", err)
		}
	})
}

// TestCTROMACProtector_EmptyPlaintext exercises Seal+Open with empty plaintext
// to cover any zero-length branches.
func TestCTROMACProtector_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xCC}, 32)
	macKey := bytes.Repeat([]byte{0xDD}, 32)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	for _, tc := range []struct {
		name string
		iv   []byte
		ctor func(enc, mac, iv []byte) (record.Protector, error)
	}{
		{
			name: "Kuznyechik",
			iv:   bytes.Repeat([]byte{0x01}, 8),
			ctor: record.NewKuznyechikCTROMACProtector,
		},
		{
			name: "Magma",
			iv:   bytes.Repeat([]byte{0x02}, 4),
			ctor: record.NewMagmaCTROMACProtector,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sender, err := tc.ctor(encKey, macKey, tc.iv)
			if err != nil {
				t.Fatalf("sender ctor: %v", err)
			}

			receiver, err := tc.ctor(encKey, macKey, tc.iv)
			if err != nil {
				t.Fatalf("receiver ctor: %v", err)
			}

			sealed, err := sender.Seal(0, hdr, []byte{})
			if err != nil {
				t.Fatalf("Seal(empty): %v", err)
			}

			got, err := receiver.Open(0, hdr, sealed)
			if err != nil {
				t.Fatalf("Open(empty): %v", err)
			}

			if len(got) != 0 {
				t.Errorf("Open(empty): expected 0 bytes, got %d", len(got))
			}
		})
	}
}

// TestGOST28147Protector_Open_ShortFragment covers the len(fragment)<gostMACSize
// branch in gost28147Protector.Open.
func TestGOST28147Protector_Open_ShortFragment(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x11}, 32)
	macKey := bytes.Repeat([]byte{0x22}, 32)
	iv := bytes.Repeat([]byte{0x01}, 8)

	p, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	// gostMACSize=4; feed 3 bytes.
	_, err = p.Open(0, hdr, make([]byte, 3))
	if err == nil {
		t.Fatal("Open(short): expected error, got nil")
	}

	var ae *record.AlertError

	if !errors.As(err, &ae) || ae.Description != record.AlertBadRecordMAC {
		t.Errorf("expected AlertBadRecordMAC, got %v", err)
	}
}

// TestGOST28147Protector_Write_SmallInputPath tests the gostIMIT.Write path
// where data is smaller than one block and stays buffered the entire time,
// covering the "bufLen < gostBlockSize && no remaining" early-return path.
func TestGOST28147Protector_Write_SmallInputPath(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x33}, 32)
	macKey := bytes.Repeat([]byte{0x44}, 32)
	iv := bytes.Repeat([]byte{0x05}, 8)

	// Send many very-short records so the IMIT accumulates state across calls.
	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	for seq := range uint64(8) {
		// Use plaintext lengths 1-3 bytes so IMIT only buffers; never processes a full block.
		plain := make([]byte, int(seq%3)+1)

		for i := range plain {
			plain[i] = byte(seq*3 + uint64(i) + 1)
		}

		sealed, err := sender.Seal(seq, hdr, plain)
		if err != nil {
			t.Fatalf("seq=%d Seal: %v", seq, err)
		}

		got, err := receiver.Open(seq, hdr, sealed)
		if err != nil {
			t.Fatalf("seq=%d Open: %v", seq, err)
		}

		if !bytes.Equal(got, plain) {
			t.Errorf("seq=%d plaintext mismatch", seq)
		}
	}
}

// TestGOST28147Protector_Finalize_StableAcrossRecords verifies that Finalize
// is non-destructive (receiver state unchanged) by confirming that a
// multi-record sequence with varied lengths decrypts successfully.
func TestGOST28147Protector_Finalize_StableAcrossRecords(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x55}, 32)
	macKey := bytes.Repeat([]byte{0x66}, 32)
	iv := bytes.Repeat([]byte{0x07}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	for seq := range uint64(16) {
		plain := make([]byte, int(seq*7)%200+1)

		for i := range plain {
			plain[i] = byte(i ^ int(seq))
		}

		sealed, err := sender.Seal(seq, hdr, plain)
		if err != nil {
			t.Fatalf("seq=%d Seal: %v", seq, err)
		}

		got, err := receiver.Open(seq, hdr, sealed)
		if err != nil {
			t.Fatalf("seq=%d Open: %v", seq, err)
		}

		if !bytes.Equal(got, plain) {
			t.Errorf("seq=%d plaintext mismatch", seq)
		}
	}
}
