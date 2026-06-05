package record

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// chacha20Poly1305Protector implements TLS 1.2 ChaCha20-Poly1305 per RFC 7905.
//
// Nonce construction (RFC 7905 §2):
//
//	pad_left(seq, 12) = 0x00 0x00 0x00 0x00 || seq_num_be64
//	nonce             = write_IV XOR pad_left(seq, 12)
//
// write_IV is 12 bytes, taken from the TLS key expansion block; no wire bytes
// are prepended to the record fragment (ExplicitIVLen = 0).
//
// AEAD additional data matches TLS 1.2 §6.2.3.3:
//
//	ad = seq_num (8) || type (1) || version (2) || plaintext_length (2)
type chacha20Poly1305Protector struct {
	aead cipher.AEAD
	iv   [12]byte
}

// NewChaCha20Poly1305Protector creates a ChaCha20-Poly1305 protector for TLS 1.2.
// key must be 32 bytes (ChaCha20 key). iv must be 12 bytes (implicit write_IV).
func NewChaCha20Poly1305Protector(key, iv []byte) (Protector, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fatalRecordError("ChaCha20-Poly1305 key must be 32 bytes")
	}
	if len(iv) != chacha20poly1305.NonceSize {
		return nil, fatalRecordError("ChaCha20-Poly1305 iv must be 12 bytes")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	p := &chacha20Poly1305Protector{aead: aead}
	copy(p.iv[:], iv)
	return p, nil
}

// buildNonce returns iv XOR left-padded seq (12 bytes).
func (p *chacha20Poly1305Protector) buildNonce(seq uint64) []byte {
	nonce := make([]byte, 12)
	// Left-pad seq: 4 zero bytes, then big-endian uint64.
	binary.BigEndian.PutUint64(nonce[4:], seq)
	for i := range 12 {
		nonce[i] ^= p.iv[i]
	}
	return nonce
}

// Seal implements Protector. No explicit nonce is prepended; the returned bytes
// are just the ciphertext+tag.
func (p *chacha20Poly1305Protector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	nonce := p.buildNonce(seq)
	ad := buildAD(seq, hdr, len(plain))
	return p.aead.Seal(nil, nonce, plain, ad), nil
}

// Open implements Protector. fragment is the raw ciphertext+tag as received.
func (p *chacha20Poly1305Protector) Open(seq uint64, hdr, fragment []byte) ([]byte, error) {
	tagSize := p.aead.Overhead()
	if len(fragment) < tagSize {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}
	plainLen := len(fragment) - tagSize
	nonce := p.buildNonce(seq)
	ad := buildAD(seq, hdr, plainLen)
	plain, err := p.aead.Open(nil, nonce, fragment, ad)
	if err != nil {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}
	return plain, nil
}
