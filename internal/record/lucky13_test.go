package record_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/bigbes/gostls/internal/record"
)

// TestCBCHMACProtector_Open_OversizedPaddingByte exercises the constant-time
// content-length clamp in the Lucky13-hardened Open path. A record whose
// decrypted last byte claims more padding than the buffer holds makes the
// content length underflow; the implementation must clamp it to zero in
// constant time and reject the record cleanly (bad_record_mac) — never panic or
// index out of range. Before the fix this fed a negative argument to
// crypto/subtle.ConstantTimeLessOrEq (documented undefined behavior).
func TestCBCHMACProtector_Open_OversizedPaddingByte(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x01}, 16) // AES-128.
	macKey := bytes.Repeat([]byte{0x02}, 32) // HMAC-SHA256.

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00} // app-data, TLS 1.2.

	// Plaintext blocks ending in 0xff: the decrypted last byte claims 255 (+1)
	// bytes of padding, far exceeding len(plain)-macSize.
	const blockSize = aes.BlockSize

	plain := bytes.Repeat([]byte{0xff}, blockSize*4)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	iv := make([]byte, blockSize)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)

	fragment := append(append([]byte{}, iv...), ct...)

	// Must not panic and must reject with bad_record_mac.
	_, err = prot.Open(0, hdr, fragment)
	if err == nil {
		t.Fatal("Open(oversized padding byte): expected error, got nil")
	}

	var ae *record.AlertError

	if !errors.As(err, &ae) || ae.Description != record.AlertBadRecordMAC {
		t.Errorf("Open(oversized padding byte): expected AlertBadRecordMAC, got %v", err)
	}
}
