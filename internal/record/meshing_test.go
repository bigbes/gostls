package record_test

import (
	"bytes"
	"testing"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/record"
)

// TestGOST_CNT_KeyMeshing_RoundTrip exercises the CryptoPro key meshing path
// (protection_gost.go:meshKey) in both the CNT counter stream (gostCNT.meshKey)
// and the IMIT MAC (gostIMIT.meshKey) by sealing and opening a record whose
// plaintext size (1200 bytes) forces the CNT keystream (1200 B plaintext + 4 B
// MAC = 1204 B encrypted) past the 1024-byte meshing boundary.
//
// The only correctness assertion is that the receiver can decrypt successfully:
// if meshKey produces a different key on sender vs. receiver, Open returns a MAC
// mismatch error.
func TestGOST_CNT_KeyMeshing_RoundTrip(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xAA}, 32)
	macKey := bytes.Repeat([]byte{0xBB}, 32)
	iv := bytes.Repeat([]byte{0x01}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (sender): %v", err)
	}

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (receiver): %v", err)
	}

	// A 1200-byte plaintext: CNT must encrypt 1204 bytes (plain + 4-byte MAC),
	// crossing the 1024-byte meshing boundary.
	plain1200 := make([]byte, 1200)
	for i := range plain1200 {
		plain1200[i] = byte(i)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	sealed, err := sender.Seal(0, hdr, plain1200)
	if err != nil {
		t.Fatalf("Seal (1200-byte record): %v", err)
	}

	got, err := receiver.Open(0, hdr, sealed)
	if err != nil {
		t.Fatalf("Open (1200-byte record): %v — CNT/IMIT meshing mismatch", err)
	}

	if !bytes.Equal(got, plain1200) {
		t.Error("Open (1200-byte record): plaintext mismatch after key meshing")
	}
}

// TestGOST_IMIT_KeyMeshing_MultiRecord drives enough consecutive records that
// the cumulative MAC input (AD + plaintext per record) passes the 1024-byte
// IMIT meshing boundary across record boundaries, exercising gostIMIT.meshKey
// (the per-block path in processBlockMesh).
//
// 15 records of 80 bytes each produce 80*15 + 13*15 = 1395 bytes of IMIT input.
func TestGOST_IMIT_KeyMeshing_MultiRecord(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x33}, 32)
	macKey := bytes.Repeat([]byte{0x44}, 32)
	iv := bytes.Repeat([]byte{0x05}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (sender): %v", err)
	}

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (receiver): %v", err)
	}

	const (
		numRecords  = 15
		payloadSize = 80
	)

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	for seq := range uint64(numRecords) {
		plain := make([]byte, payloadSize)
		for i := range plain {
			plain[i] = byte(seq*uint64(payloadSize) + uint64(i))
		}

		sealed, err := sender.Seal(seq, hdr, plain)
		if err != nil {
			t.Fatalf("Seal seq=%d: %v", seq, err)
		}

		got, err := receiver.Open(seq, hdr, sealed)
		if err != nil {
			t.Fatalf("Open seq=%d: %v — IMIT meshing mismatch", seq, err)
		}

		if !bytes.Equal(got, plain) {
			t.Errorf("seq=%d: plaintext mismatch after IMIT key meshing", seq)
		}
	}
}

// TestGOST_CNT_KeyMeshing_SboxCryptoPro verifies key meshing round-trip also
// works with the CryptoPro-A S-box (suite 0x0081), not just tc26-Z.
func TestGOST_CNT_KeyMeshing_SboxCryptoPro(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x55}, 32)
	macKey := bytes.Repeat([]byte{0x66}, 32)
	iv := bytes.Repeat([]byte{0x07}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxCryptoProA)
	if err != nil {
		t.Fatalf("NewGOST28147Protector CryptoPro-A (sender): %v", err)
	}

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxCryptoProA)
	if err != nil {
		t.Fatalf("NewGOST28147Protector CryptoPro-A (receiver): %v", err)
	}

	// 1100-byte payload crosses the 1024-byte CNT meshing boundary.
	plain := make([]byte, 1100)
	for i := range plain {
		plain[i] = byte(i ^ 0xAB)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	sealed, err := sender.Seal(0, hdr, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := receiver.Open(0, hdr, sealed)
	if err != nil {
		t.Fatalf("Open: %v — CryptoPro-A meshing mismatch", err)
	}

	if !bytes.Equal(got, plain) {
		t.Error("CryptoPro-A round-trip mismatch after key meshing")
	}
}

// TestGOST_BadProtectorKeys verifies that NewGOST28147Protector returns errors
// for wrong key/IV lengths.
func TestGOST_BadProtectorKeys(t *testing.T) {
	t.Parallel()

	goodKey := bytes.Repeat([]byte{0x01}, 32)
	goodIV := bytes.Repeat([]byte{0x02}, 8)

	// Bad enc key length.
	if _, err := record.NewGOST28147Protector(make([]byte, 16), goodKey, goodIV, gost.SboxTC26Z); err == nil {
		t.Error("expected error for 16-byte enc key, got nil")
	}

	// Bad mac key length.
	if _, err := record.NewGOST28147Protector(goodKey, make([]byte, 16), goodIV, gost.SboxTC26Z); err == nil {
		t.Error("expected error for 16-byte mac key, got nil")
	}

	// Bad IV length.
	if _, err := record.NewGOST28147Protector(goodKey, goodKey, make([]byte, 4), gost.SboxTC26Z); err == nil {
		t.Error("expected error for 4-byte IV, got nil")
	}
}

// TestGOST_Open_TooShort verifies that Open rejects fragments shorter than the
// 4-byte MAC.
func TestGOST_Open_TooShort(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x77}, 32)
	macKey := bytes.Repeat([]byte{0x88}, 32)
	iv := bytes.Repeat([]byte{0x09}, 8)

	p, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	// 3 bytes: too short to contain the 4-byte IMIT MAC.
	_, err = p.Open(0, hdr, make([]byte, 3))
	if err == nil {
		t.Error("Open with 3-byte fragment: expected error, got nil")
	}
}
