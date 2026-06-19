package record

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"hash"
)

// macADLen is the length of the MAC additional data:
// seq_num (8) || type (1) || version (2) || length (2) = 13.
const macADLen = 13

// aeadSaltLen is the length of the implicit IV salt for AEAD (GCM) suites.
const aeadSaltLen = 4

// aeadNonceLen is the total GCM nonce length: salt (4) || explicit (8) = 12.
const aeadNonceLen = 12

// aeadExplicitNonceLen is the wire length of the explicit nonce prepended to
// each AEAD-encrypted record fragment.
const aeadExplicitNonceLen = 8

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

// ---- nullProtector ---------------------------------------------------------.

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

// ---- cbcHMACProtector ------------------------------------------------------.

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
	ad := make([]byte, macADLen)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	// hdr[0] = type, hdr[1:3] = version.
	copy(ad[8:11], hdr[0:3])
	binary.BigEndian.PutUint16(ad[11:13], uint16(plainLen))

	return ad
}

// Seal implements Protector. Returns IV || Encrypt(plain || mac || padding).
// IV is randomly generated per record (RFC 5246 §6.2.3.2).
func (p *cbcHMACProtector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	mac := p.computeMAC(seq, hdr, plain, nil)

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
// Padding removal and MAC verification are constant-time with respect to the
// secret padding length; see the body for the Lucky13 mitigation.
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

	// Constant-time padding removal and MAC verification (Lucky13 mitigation,
	// mirroring crypto/tls). The padding length is secret, so the work below is
	// independent of it:
	//   - extractCBCPadding scans a fixed-size region and returns a 0xff/0x00
	//     "good" mask without branching on the length;
	//   - the bytes past the content+MAC (the padding) are fed to the HMAC as
	//     post-digest "extra", so the number of hash-compression rounds, and
	//     thus the MAC time, does not depend on the padding length;
	//   - the MAC comparison and the padding check are combined into one
	//     constant-time decision, so a padding failure is indistinguishable
	//     from a MAC failure.
	toRemove, paddingGood := extractCBCPadding(plain)

	// Content length, clamped to >= 0 in constant time so the slices below stay
	// in range even on bad padding (toRemove can exceed len(plain)-macSize).
	rawN := len(plain) - p.macSize - toRemove
	n := subtle.ConstantTimeSelect(int(uint32(rawN)>>cbcSignShift32), 0, rawN)

	gotMAC := plain[n : n+p.macSize]
	expectedMAC := p.computeMAC(seq, hdr, plain[:n], plain[n+p.macSize:])

	if subtle.ConstantTimeCompare(gotMAC, expectedMAC)&int(paddingGood) != 1 {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	out := make([]byte, n)
	copy(out, plain[:n])

	return out, nil
}

// computeMAC computes HMAC over the additional data concatenated with fragment.
// The returned MAC covers only fragment; extra, when non-nil, is written into
// the HMAC *after* the digest is finalized, adding hash-compression rounds
// without changing the result. The decrypt path passes the secret-length
// padding region as extra so the total number of bytes hashed — and thus the
// MAC computation time — is independent of the padding length (Lucky13
// mitigation; mirrors crypto/tls tls10MAC).
func (p *cbcHMACProtector) computeMAC(seq uint64, hdr, fragment, extra []byte) []byte {
	h := hmac.New(p.newHash, p.macKey)
	ad := macAdditionalData(seq, hdr, len(fragment))
	h.Write(ad)
	h.Write(fragment)

	res := h.Sum(nil)
	if extra != nil {
		h.Write(extra)
	}

	return res
}

// Constant-time bit-twiddling parameters for CBC padding validation.
const (
	// cbcMaxPaddingScan is the number of trailing bytes scanned when validating
	// CBC padding: at most 255 padding bytes plus the length byte
	// (RFC 5246 §6.2.3.2).
	cbcMaxPaddingScan = 256
	// cbcSignShift32 extracts an int32 sign bit as a full 0x00/0xFF byte mask.
	cbcSignShift32 = 31
	// cbcSignShift8 broadcasts a byte's most-significant bit across all 8 bits.
	cbcSignShift8 = 7
)

// extractCBCPadding returns, in constant time, the number of trailing bytes to
// remove (the padding bytes plus the length byte) and a mask equal to 0xff iff
// the padding is well-formed per RFC 5246 §6.2.3.2. It mirrors the constant-time
// padding check in crypto/tls (extractPadding): a fixed-size region is always
// scanned, so neither the work done nor the control flow reveals the padding
// length.
func extractCBCPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// good is 0xff iff paddingLen <= len(payload)-1 (the MSB of t is then 0).
	good = byte(int32(^t) >> cbcSignShift32)

	// The padded length is public, so this bound is computed in the clear.
	toCheck := min(cbcMaxPaddingScan, len(payload))

	for i := range toCheck {
		t := uint(paddingLen) - uint(i)
		// mask is 0xff iff i <= paddingLen.
		mask := byte(int32(^t) >> cbcSignShift32)
		b := payload[len(payload)-1-i]

		good &^= mask&paddingLen ^ mask&b
	}

	// Collapse the bits of good to all-ones or all-zeros: require every bit set.
	good &= good << 4 //nolint:mnd // bit-fold step (4,2,1) to AND all 8 bits together
	good &= good << 2 //nolint:mnd // bit-fold step
	good &= good << 1

	good = uint8(int8(good) >> cbcSignShift8)

	return int(paddingLen) + 1, good
}

// ---- aeadProtector ---------------------------------------------------------.

// aeadProtector implements TLS 1.2 AEAD (RFC 5288, RFC 5246 §6.2.3.3).
// Nonce: 4-byte implicit salt (from key expansion) || 8-byte explicit nonce
// prepended to each record fragment.
// AD: seq_num (8) || type (1) || version (2) || plaintext_length (2).
type aeadProtector struct {
	aead cipher.AEAD
	salt []byte // 4-byte implicit IV salt.
}

// NewAEADProtector creates an AES-128-GCM protector.
// key must be 16 bytes (AES-128). salt must be exactly 4 bytes.
func NewAEADProtector(key, salt []byte) (Protector, error) {
	if len(salt) != aeadSaltLen {
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
		salt: make([]byte, aeadSaltLen),
	}
	copy(p.salt, salt)

	return p, nil
}

// buildAD constructs the AEAD additional data.
func buildAD(seq uint64, hdr []byte, plainLen int) []byte {
	ad := make([]byte, macADLen)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	copy(ad[8:11], hdr[0:3]) // type + version.
	binary.BigEndian.PutUint16(ad[11:13], uint16(plainLen))

	return ad
}

// Seal implements Protector. Returns explicitNonce (8) || ciphertext+tag.
func (p *aeadProtector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	explicitNonce := make([]byte, aeadExplicitNonceLen)
	binary.BigEndian.PutUint64(explicitNonce, seq)

	nonce := p.buildNonce(explicitNonce)
	ad := buildAD(seq, hdr, len(plain))

	ciphertext := p.aead.Seal(nil, nonce, plain, ad)

	out := make([]byte, aeadExplicitNonceLen+len(ciphertext))
	copy(out[:aeadExplicitNonceLen], explicitNonce)
	copy(out[aeadExplicitNonceLen:], ciphertext)

	return out, nil
}

// Open implements Protector. Input is explicitNonce (8) || ciphertext+tag.
func (p *aeadProtector) Open(seq uint64, hdr, fragment []byte) ([]byte, error) {
	tagSize := p.aead.Overhead()
	if len(fragment) < aeadExplicitNonceLen+tagSize {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	explicitNonce := fragment[:aeadExplicitNonceLen]
	ciphertext := fragment[aeadExplicitNonceLen:]
	plainLen := len(ciphertext) - tagSize

	nonce := p.buildNonce(explicitNonce)
	ad := buildAD(seq, hdr, plainLen)

	plain, err := p.aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	return plain, nil
}

// buildNonce constructs the 12-byte GCM nonce: salt (4) || explicit (8).
func (p *aeadProtector) buildNonce(explicit []byte) []byte {
	nonce := make([]byte, aeadNonceLen)
	copy(nonce[:aeadSaltLen], p.salt)
	copy(nonce[aeadSaltLen:], explicit)

	return nonce
}
