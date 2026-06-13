package record_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/record"
)

// hdr is a TLS 1.2 application_data record header (type=0x17, version=0x0303).
// The length bytes (hdr[3:5]) are not used by the protectors but are included
// for correctness; the length fields are reconstructed inside Seal/Open from
// the plaintext.
var ctrOMACHdr = []byte{0x17, 0x03, 0x03}

func mustHexCTROMAC(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}

	return b
}

// ── Kuznyechik ────────────────────────────────────────────────────────────────.

// TestKuznyechikCTROMACProtector_RoundTrip verifies Seal+Open round-trip for a
// representative set of sequence numbers covering the Kuznyechik TLSTree level-3
// boundary at seq=64 (2^6). Each Seal/Open pair uses independent protector
// instances (matching real TLS where sender and receiver have separate state).
func TestKuznyechikCTROMACProtector_RoundTrip(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xAA}, 32)
	macKey := bytes.Repeat([]byte{0xBB}, 32)
	iv := bytes.Repeat([]byte{0x01}, 8) // 8 bytes for Kuznyechik.

	seqs := []uint64{0, 1, 63, 64, 65, 255, 4096}
	for _, seq := range seqs {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			sender, err := record.NewKuznyechikCTROMACProtector(encKey, macKey, iv)
			if err != nil {
				t.Fatalf("seq=%d NewKuznyechikCTROMACProtector (sender): %v", seq, err)
			}

			receiver, err := record.NewKuznyechikCTROMACProtector(encKey, macKey, iv)
			if err != nil {
				t.Fatalf("seq=%d NewKuznyechikCTROMACProtector (receiver): %v", seq, err)
			}

			plain := []byte("hello Kuznyechik CTROMAC world!")

			sealed, err := sender.Seal(seq, ctrOMACHdr, plain)
			if err != nil {
				t.Fatalf("seq=%d Seal: %v", seq, err)
			}

			// Output must be len(plain) + 16 (Kuznyechik OMAC tag).
			if len(sealed) != len(plain)+16 {
				t.Fatalf("seq=%d Seal length: want %d, got %d", seq, len(plain)+16, len(sealed))
			}

			got, err := receiver.Open(seq, ctrOMACHdr, sealed)
			if err != nil {
				t.Fatalf("seq=%d Open: %v", seq, err)
			}

			if !bytes.Equal(got, plain) {
				t.Errorf("seq=%d Open plaintext mismatch: got %x, want %x", seq, got, plain)
			}
		})
	}
}

// TestKuznyechikCTROMACProtector_EngineEtalons ports the exact TLS etalons from
// tmp/engine/test_tlstree.c.
//
// The C test computes the OMAC over seq||hdr||plain using the TLSTree-derived
// MAC key for the current sequence number, then encrypts plain||mac using the
// TLSTree-derived ENC key and adjusted IV for that same record.
//
// Source:
//   - mac0_etl / enc0_etl
//   - mac63_etl / enc63_etl_head / enc63_etl_tail
func TestKuznyechikCTROMACProtector_EngineEtalons(t *testing.T) {
	t.Parallel()

	encKey := make([]byte, 32)
	macKey := bytes.Repeat([]byte{0xFF}, 32)
	iv := make([]byte, 8)

	macTree := gost.NewTLSTreeKuznyechikCTROMAC(macKey)

	sender, err := record.NewKuznyechikCTROMACProtector(encKey, macKey, iv)
	if err != nil {
		t.Fatalf("NewKuznyechikCTROMACProtector: %v", err)
	}

	cases := []struct {
		name       string
		seq        uint64
		hdr        []byte
		plain      []byte
		wantMAC    []byte
		wantSealed []byte
		wantHead   []byte
		wantTail   []byte
	}{
		{
			name:       "seq0",
			seq:        0,
			hdr:        []byte{0x17, 0x03, 0x03, 0x00, 0x0F},
			plain:      make([]byte, 15),
			wantMAC:    mustHexCTROMAC(t, "755309cbc73bb949c50ebb86160a0fee"),
			wantSealed: mustHexCTROMAC(t, "f317a71d3ace433b01d4e7d4ef61ae00d53b41527a261edfc2ba7857c1932d"),
		},
		{
			name:     "seq63",
			seq:      63,
			hdr:      []byte{0x17, 0x03, 0x03, 0x10, 0x00},
			plain:    make([]byte, 4096),
			wantMAC:  mustHexCTROMAC(t, "0a3bfd430fcdd8d85c96468681784f7d"),
			wantHead: mustHexCTROMAC(t, "6a1838b0a0d5a04d1f2964896d085fb7da84d776c39f5cdc3720b7b559ef139d"),
			wantTail: mustHexCTROMAC(t,
				"0a81299b3598195dd45168a63850a76e"+
					"1a4f1e6dd5ef72593fae765571ec37e7"+
					"17f5b86285bb5bfd83b66ab763865208"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Match the engine's MAC etalon directly using our TLSTree + OMAC.
			macBlock := gost.NewKuznyechikCipher(macTree.Derive(tc.seq))

			omac, err := gost.NewOMAC(macBlock, 16)
			if err != nil {
				t.Fatalf("NewOMAC: %v", err)
			}

			var seqBytes [8]byte

			binary.BigEndian.PutUint64(seqBytes[:], tc.seq)
			omac.Write(seqBytes[:]) //nolint: errcheck
			omac.Write(tc.hdr)      //nolint: errcheck
			omac.Write(tc.plain)    //nolint: errcheck

			if got := omac.Sum(nil); !bytes.Equal(got, tc.wantMAC) {
				t.Fatalf("OMAC mismatch:\n got  %x\n want %x", got, tc.wantMAC)
			}

			sealed, err := sender.Seal(tc.seq, ctrOMACHdr, tc.plain)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			if tc.wantSealed != nil && !bytes.Equal(sealed, tc.wantSealed) {
				t.Fatalf("sealed mismatch:\n got  %x\n want %x", sealed, tc.wantSealed)
			}

			if tc.wantHead != nil && !bytes.Equal(sealed[:len(tc.wantHead)], tc.wantHead) {
				t.Fatalf("sealed head mismatch:\n got  %x\n want %x", sealed[:len(tc.wantHead)], tc.wantHead)
			}

			if tc.wantTail != nil {
				got := sealed[len(sealed)-len(tc.wantTail):]
				if !bytes.Equal(got, tc.wantTail) {
					t.Fatalf("sealed tail mismatch:\n got  %x\n want %x", got, tc.wantTail)
				}
			}
		})
	}
}

// ── Magma ─────────────────────────────────────────────────────────────────────.

// TestMagmaCTROMACProtector_RoundTrip verifies Seal+Open round-trip for a
// representative set of sequence numbers covering the Magma TLSTree level-3
// boundary at seq=4096 (2^12).
func TestMagmaCTROMACProtector_RoundTrip(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xCC}, 32)
	macKey := bytes.Repeat([]byte{0xDD}, 32)
	iv := bytes.Repeat([]byte{0x02}, 4) // 4 bytes for Magma.

	seqs := []uint64{0, 1, 4095, 4096, 4097}
	for _, seq := range seqs {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			sender, err := record.NewMagmaCTROMACProtector(encKey, macKey, iv)
			if err != nil {
				t.Fatalf("seq=%d NewMagmaCTROMACProtector (sender): %v", seq, err)
			}

			receiver, err := record.NewMagmaCTROMACProtector(encKey, macKey, iv)
			if err != nil {
				t.Fatalf("seq=%d NewMagmaCTROMACProtector (receiver): %v", seq, err)
			}

			plain := []byte("hello Magma CTROMAC world!")

			sealed, err := sender.Seal(seq, ctrOMACHdr, plain)
			if err != nil {
				t.Fatalf("seq=%d Seal: %v", seq, err)
			}

			if len(sealed) != len(plain)+8 {
				t.Fatalf("seq=%d Seal length: want %d, got %d", seq, len(plain)+8, len(sealed))
			}

			got, err := receiver.Open(seq, ctrOMACHdr, sealed)
			if err != nil {
				t.Fatalf("seq=%d Open: %v", seq, err)
			}

			if !bytes.Equal(got, plain) {
				t.Errorf("seq=%d Open plaintext mismatch: got %x, want %x", seq, got, plain)
			}
		})
	}
}

// ── MAC mismatch ──────────────────────────────────────────────────────────────.

// TestCTROMACProtector_MACMismatch verifies that flipping one ciphertext byte
// causes Open to return a fatal AlertBadRecordMAC error for both variants.
func TestCTROMACProtector_MACMismatch(t *testing.T) {
	t.Parallel()

	type ctorFn func(encKey, macKey, iv []byte) (record.Protector, error)

	cases := []struct {
		name string
		ctor ctorFn
		iv   []byte
	}{
		{
			name: "Kuznyechik",
			ctor: record.NewKuznyechikCTROMACProtector,
			iv:   bytes.Repeat([]byte{0x10}, 8),
		},
		{
			name: "Magma",
			ctor: record.NewMagmaCTROMACProtector,
			iv:   bytes.Repeat([]byte{0x20}, 4),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encKey := bytes.Repeat([]byte{0x11}, 32)
			macKey := bytes.Repeat([]byte{0x22}, 32)

			sender, err := tc.ctor(encKey, macKey, tc.iv)
			if err != nil {
				t.Fatalf("constructor (sender): %v", err)
			}

			receiver, err := tc.ctor(encKey, macKey, tc.iv)
			if err != nil {
				t.Fatalf("constructor (receiver): %v", err)
			}

			plain := []byte("mac mismatch test payload")
			seq := uint64(7)

			sealed, err := sender.Seal(seq, ctrOMACHdr, plain)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			tampered := make([]byte, len(sealed))
			copy(tampered, sealed)

			tampered[0] ^= 0xFF

			_, err = receiver.Open(seq, ctrOMACHdr, tampered)
			if err == nil {
				t.Fatal("Open with tampered ciphertext: expected error, got nil")
			}

			var alertErr *record.AlertError

			if !errors.As(err, &alertErr) {
				t.Fatalf("expected *record.AlertError, got %T: %v", err, err)
			}

			if alertErr.Description != record.AlertBadRecordMAC {
				t.Errorf("expected AlertBadRecordMAC (%d), got %d", record.AlertBadRecordMAC, alertErr.Description)
			}
		})
	}
}

// ── Bad IV length ─────────────────────────────────────────────────────────────.

func TestCTROMACProtector_BadIVLen(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xAA}, 32)
	macKey := bytes.Repeat([]byte{0xBB}, 32)

	for _, badLen := range []int{7, 9} {
		iv := make([]byte, badLen)
		if _, err := record.NewKuznyechikCTROMACProtector(encKey, macKey, iv); err == nil {
			t.Errorf("NewKuznyechikCTROMACProtector iv len=%d: expected error, got nil", badLen)
		}
	}

	for _, badLen := range []int{3, 5} {
		iv := make([]byte, badLen)
		if _, err := record.NewMagmaCTROMACProtector(encKey, macKey, iv); err == nil {
			t.Errorf("NewMagmaCTROMACProtector iv len=%d: expected error, got nil", badLen)
		}
	}
}

// ── Bad key length ────────────────────────────────────────────────────────────.

func TestCTROMACProtector_BadKeyLen(t *testing.T) {
	t.Parallel()

	goodKey := bytes.Repeat([]byte{0x01}, 32)
	kuzIV := bytes.Repeat([]byte{0x01}, 8)
	magIV := bytes.Repeat([]byte{0x01}, 4)

	for _, badLen := range []int{31, 33} {
		badKey := make([]byte, badLen)
		if _, err := record.NewKuznyechikCTROMACProtector(badKey, goodKey, kuzIV); err == nil {
			t.Errorf("NewKuznyechikCTROMACProtector bad enc key len=%d: expected error, got nil", badLen)
		}

		if _, err := record.NewKuznyechikCTROMACProtector(goodKey, badKey, kuzIV); err == nil {
			t.Errorf("NewKuznyechikCTROMACProtector bad mac key len=%d: expected error, got nil", badLen)
		}

		if _, err := record.NewMagmaCTROMACProtector(badKey, goodKey, magIV); err == nil {
			t.Errorf("NewMagmaCTROMACProtector bad enc key len=%d: expected error, got nil", badLen)
		}

		if _, err := record.NewMagmaCTROMACProtector(goodKey, badKey, magIV); err == nil {
			t.Errorf("NewMagmaCTROMACProtector bad mac key len=%d: expected error, got nil", badLen)
		}
	}
}
