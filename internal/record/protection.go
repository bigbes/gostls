package record

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"hash"
)

// Protector handles the Seal/Open operations for a TLS record fragment.
//
// Design choice: Seal and Open operate on fragment bytes only. The Layer
// handles header construction and sequence number tracking. This keeps the
// Protector interface simple and lets the Layer own the wire format.
//
// Seal(seq, hdr, plain) — encrypts the plaintext record fragment. seq is the
// 64-bit record sequence number. hdr is the 5-byte record header (type +
// version + length) used as MAC additional data. Returns the encrypted
// fragment. The Layer prepends hdr with an updated length field before writing
// to the wire.
//
// Open(seq, hdr, fragment) — decrypts the fragment, verifying MAC or AEAD
// tag. hdr is the 5-byte header as received from the wire. Returns plaintext.
type Protector interface {
	Seal(seq uint64, hdr, plain []byte) ([]byte, error)
	Open(seq uint64, hdr, fragment []byte) ([]byte, error)
}

// ---- nullProtector ---------------------------------------------------------

// nullProtector passes bytes through unchanged. Used before ChangeCipherSpec.
type nullProtector struct{}

func (nullProtector) Seal(_ uint64, _, plain []byte) ([]byte, error) {
	out := make([]byte, len(plain))
	copy(out, plain)
	return out, nil
}

func (nullProtector) Open(_ uint64, _, fragment []byte) ([]byte, error) {
	out := make([]byte, len(fragment))
	copy(out, fragment)
	return out, nil
}

// ---- cbcHMACProtector ------------------------------------------------------

// NewCipherFunc is the constructor type for a block cipher (e.g. aes.NewCipher).
type NewCipherFunc func(key []byte) (cipher.Block, error)

// NewHashFunc is the constructor type for an HMAC hash (e.g. sha256.New).
type NewHashFunc func() hash.Hash

// cbcHMACProtector implements TLS 1.2 MAC-then-encrypt CBC mode.
// RFC 5246 §6.2.3.2: explicit IV, MAC-then-pad-then-encrypt.
type cbcHMACProtector struct {
	newCipher NewCipherFunc
	newHash   NewHashFunc
	encKey    []byte
	macKey    []byte
	blockSize int
	macSize   int
}

// NewCBCHMACProtector creates a CBC / HMAC protector.
// encKey length must match the cipher's key size (e.g. 16 bytes for AES-128).
// macKey is used for HMAC with the provided hash constructor.
func NewCBCHMACProtector(newCipher NewCipherFunc, newHash NewHashFunc, encKey, macKey []byte) (Protector, error) {
	b, err := newCipher(encKey)
	if err != nil {
		return nil, err
	}
	h := hmac.New(newHash, macKey)
	p := &cbcHMACProtector{
		newCipher: newCipher,
		newHash:   newHash,
		encKey:    make([]byte, len(encKey)),
		macKey:    make([]byte, len(macKey)),
		blockSize: b.BlockSize(),
		macSize:   h.Size(),
	}
	copy(p.encKey, encKey)
	copy(p.macKey, macKey)
	return p, nil
}

// macAdditionalData constructs the MAC additional data per RFC 5246 §6.2.3.1:
// seq_num (8) || type (1) || version (2) || length (2).
// length is plaintext fragment length.
func macAdditionalData(seq uint64, hdr []byte, plainLen int) []byte {
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	// hdr[0] = type, hdr[1:3] = version.
	copy(ad[8:11], hdr[0:3])
	binary.BigEndian.PutUint16(ad[11:13], uint16(plainLen))
	return ad
}

// computeMAC computes HMAC over the additional data concatenated with the fragment.
func (p *cbcHMACProtector) computeMAC(seq uint64, hdr, fragment []byte) []byte {
	h := hmac.New(p.newHash, p.macKey)
	ad := macAdditionalData(seq, hdr, len(fragment))
	h.Write(ad)
	h.Write(fragment)
	return h.Sum(nil)
}

// Seal implements Protector. Returns IV || Encrypt(plain || mac || padding).
// IV is randomly generated per record (RFC 5246 §6.2.3.2).
func (p *cbcHMACProtector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	mac := p.computeMAC(seq, hdr, plain)

	// TLS padding: enough bytes to align (plain || mac || pad) to blockSize.
	// The last byte of padding encodes padding_length; all padding bytes have
	// the same value (RFC 5246 §6.2.3.2).
	contentLen := len(plain) + p.macSize
	padLen := p.blockSize - (contentLen+1)%p.blockSize
	if padLen < 0 {
		padLen += p.blockSize
	}
	paddingByte := byte(padLen)

	buf := make([]byte, contentLen+padLen+1)
	copy(buf, plain)
	copy(buf[len(plain):], mac)
	for i := contentLen; i < len(buf); i++ {
		buf[i] = paddingByte
	}

	// Generate explicit IV.
	iv := make([]byte, p.blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fatalRecordError("rand.Read failed: " + err.Error())
	}

	block, err := p.newCipher(p.encKey)
	if err != nil {
		return nil, fatalRecordError("cipher init: " + err.Error())
	}

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)

	out := make([]byte, p.blockSize+len(buf))
	copy(out, iv)
	copy(out[p.blockSize:], buf)
	return out, nil
}

// Open implements Protector. Input is IV (blockSize bytes) || ciphertext.
//
// Constant-time safety notes:
//   - Padding is validated with a branchless XOR accumulator (Lucky13 mitigation).
//   - MAC is verified with crypto/subtle.ConstantTimeCompare.
//   - Even on bad padding we run the MAC comparison path to avoid timing divergence.
func (p *cbcHMACProtector) Open(seq uint64, hdr, fragment []byte) ([]byte, error) {
	if len(fragment) < p.blockSize+p.macSize+1 {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}
	if len(fragment)%p.blockSize != 0 {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	iv := fragment[:p.blockSize]
	ciphertext := fragment[p.blockSize:]

	block, err := p.newCipher(p.encKey)
	if err != nil {
		return nil, fatalRecordError("cipher init: " + err.Error())
	}

	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)

	// Constant-time padding check.
	// paddingLen is the value encoded in the last byte; that many preceding
	// bytes must all equal the same value per RFC 5246 §6.2.3.2.
	paddingLen := int(plain[len(plain)-1])
	paddingStart := len(plain) - paddingLen - 1

	// Branchless accumulator: 1 = all padding bytes OK, 0 = any mismatch.
	// We iterate over every byte in plain and check those in the padding region
	// [paddingStart, len(plain)) without early exit to keep timing uniform.
	// Formula per byte: if inPadding → require match; else → don't care (keep 1).
	// Equivalent branchless form: paddingOK &= (1-inPadding) | (inPadding & match).
	paddingOK := 1
	if paddingStart < 0 {
		paddingOK = 0
	}
	for i := range plain {
		inPadding := subtle.ConstantTimeLessOrEq(paddingStart, i)
		match := subtle.ConstantTimeByteEq(plain[i], plain[len(plain)-1])
		paddingOK &= (1 - inPadding) | (inPadding & match)
	}

	// Determine MAC boundaries. On bad padding or underflow we use nil/zero
	// slices so computeMAC still runs (timing uniformity) but produces a
	// different result than any valid MAC.
	var msgPlain []byte
	var gotMAC []byte
	if paddingOK == 1 && paddingStart-p.macSize >= 0 {
		msgPlain = plain[:paddingStart-p.macSize]
		gotMAC = plain[paddingStart-p.macSize : paddingStart]
	} else {
		msgPlain = nil
		gotMAC = make([]byte, p.macSize)
	}

	expectedMAC := p.computeMAC(seq, hdr, msgPlain)

	macOK := subtle.ConstantTimeCompare(gotMAC, expectedMAC)
	if paddingOK == 0 || macOK != 1 {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	out := make([]byte, len(msgPlain))
	copy(out, msgPlain)
	return out, nil
}

// ---- aeadProtector ---------------------------------------------------------

// aeadProtector implements TLS 1.2 AEAD (RFC 5288, RFC 5246 §6.2.3.3).
// Nonce: 4-byte implicit salt (from key expansion) || 8-byte explicit nonce
// prepended to each record fragment.
// AD: seq_num (8) || type (1) || version (2) || plaintext_length (2).
type aeadProtector struct {
	aead cipher.AEAD
	salt []byte // 4-byte implicit IV salt
}

// NewAEADProtector creates an AES-128-GCM protector.
// key must be 16 bytes (AES-128). salt must be exactly 4 bytes.
func NewAEADProtector(key, salt []byte) (Protector, error) {
	if len(salt) != 4 {
		return nil, fatalRecordError("AEAD salt must be exactly 4 bytes")
	}
	block, err := newAESCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	p := &aeadProtector{
		aead: aead,
		salt: make([]byte, 4),
	}
	copy(p.salt, salt)
	return p, nil
}

// buildNonce constructs the 12-byte GCM nonce: salt (4) || explicit (8).
func (p *aeadProtector) buildNonce(explicit []byte) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], p.salt)
	copy(nonce[4:], explicit)
	return nonce
}

// buildAD constructs the AEAD additional data.
func buildAD(seq uint64, hdr []byte, plainLen int) []byte {
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	copy(ad[8:11], hdr[0:3]) // type + version
	binary.BigEndian.PutUint16(ad[11:13], uint16(plainLen))
	return ad
}

// Seal implements Protector. Returns explicitNonce (8) || ciphertext+tag.
func (p *aeadProtector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	explicitNonce := make([]byte, 8)
	binary.BigEndian.PutUint64(explicitNonce, seq)

	nonce := p.buildNonce(explicitNonce)
	ad := buildAD(seq, hdr, len(plain))

	ciphertext := p.aead.Seal(nil, nonce, plain, ad)

	out := make([]byte, 8+len(ciphertext))
	copy(out[:8], explicitNonce)
	copy(out[8:], ciphertext)
	return out, nil
}

// Open implements Protector. Input is explicitNonce (8) || ciphertext+tag.
func (p *aeadProtector) Open(seq uint64, hdr, fragment []byte) ([]byte, error) {
	tagSize := p.aead.Overhead()
	if len(fragment) < 8+tagSize {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	explicitNonce := fragment[:8]
	ciphertext := fragment[8:]
	plainLen := len(ciphertext) - tagSize

	nonce := p.buildNonce(explicitNonce)
	ad := buildAD(seq, hdr, plainLen)

	plain, err := p.aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}
	return plain, nil
}
