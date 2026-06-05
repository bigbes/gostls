package record_test

import (
	"bytes"
	"testing"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/record"
)

// TestGOST_Protection_GOST28147_RoundTrip verifies Seal+Open round-trip with the
// TLS wire format Encrypt(plaintext || MAC). Uses separate send/recv protectors
// as in a real TLS session (each has its own CTR state).
func TestGOST_Protection_GOST28147_RoundTrip(t *testing.T) {
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

	seq := uint64(0)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	plain := []byte("hello GOST world")

	sealed, err := sender.Seal(seq, hdr, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != len(plain)+4 {
		t.Fatalf("Seal length: want %d, got %d", len(plain)+4, len(sealed))
	}

	got, err := receiver.Open(seq, hdr, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("Open: got %x, want %x", got, plain)
	}
}

func TestGOST_Protection_TamperedMAC(t *testing.T) {
	encKey := bytes.Repeat([]byte{0xCC}, 32)
	macKey := bytes.Repeat([]byte{0xDD}, 32)
	iv := bytes.Repeat([]byte{0x02}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (sender): %v", err)
	}
	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (receiver): %v", err)
	}

	seq := uint64(1)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	plain := []byte("tamper test data")

	sealed, err := sender.Seal(seq, hdr, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = receiver.Open(seq, hdr, tampered)
	if err == nil {
		t.Fatal("Open with tampered MAC: expected error, got nil")
	}
}

func TestGOST_Protection_TamperedCiphertext(t *testing.T) {
	encKey := bytes.Repeat([]byte{0xEE}, 32)
	macKey := bytes.Repeat([]byte{0xFF}, 32)
	iv := bytes.Repeat([]byte{0x03}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (sender): %v", err)
	}
	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (receiver): %v", err)
	}

	seq := uint64(2)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	plain := []byte("ciphertext tamper test")

	sealed, err := sender.Seal(seq, hdr, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[0] ^= 0x01

	_, err = receiver.Open(seq, hdr, tampered)
	if err == nil {
		t.Fatal("Open with tampered ciphertext: expected error, got nil")
	}
}

func TestGOST_Protection_MultiRecord(t *testing.T) {
	encKey := bytes.Repeat([]byte{0x11}, 32)
	macKey := bytes.Repeat([]byte{0x22}, 32)
	iv := bytes.Repeat([]byte{0x04}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (sender): %v", err)
	}
	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	if err != nil {
		t.Fatalf("NewGOST28147Protector (receiver): %v", err)
	}

	// Send multiple records and verify CTR state carries across them.
	for seq := uint64(0); seq < 5; seq++ {
		plain := make([]byte, 100)
		for i := range plain {
			plain[i] = byte(seq*100 + uint64(i))
		}
		hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

		sealed, err := sender.Seal(seq, hdr, plain)
		if err != nil {
			t.Fatalf("Seal seq=%d: %v", seq, err)
		}

		got, err := receiver.Open(seq, hdr, sealed)
		if err != nil {
			t.Fatalf("Open seq=%d: %v", seq, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("Open seq=%d: plaintext mismatch", seq)
		}
	}
}
