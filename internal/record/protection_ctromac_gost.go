package record

// protection_ctromac_gost.go implements the TLS 1.2 record-layer Protector for
// RFC 9367 CTR+OMAC cipher suites:
//   - TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC (0xC100)
//   - TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC       (0xC101)
//
// Wire format: ciphertext(len(plain)) || tag(tagSize). No explicit per-record
// IV on the wire. Per-record keys are derived via TLSTree; per-record CTR
// counter is derived from the static orig_iv and the record sequence number.
//
// Per-record IV construction:
//
//   Kuznyechik (128-bit block, gost_grasshopper_cipher.c:1115-1162):
//     orig_iv is 8 bytes from the key block. Counter is 16 bytes:
//     adjusted_iv[0..8] = orig_iv[0..8] + seq[0..8] (big-endian add, carry),
//     adjusted_iv[8..16] = 0x00 * 8.
//
//   Magma (64-bit block, gost_crypt.c:1285-1330):
//     orig_iv is 4 bytes from the key block. Counter is 8 bytes:
//     adjusted_iv[0..4] = orig_iv[0..4] + seq[4..8] (big-endian add, carry),
//     adjusted_iv[4..8] = 0x00 * 4. Engine loop:
//     for (j=3; j>=0; j--) adjusted_iv[j] += seq[j+4] + carry.
//
// OMAC AD layout (both variants, same as 0xFF85 ETM path, arg=0):
//   seq(8)_BE || hdr[0]_type(1) || hdr[1..3]_version(2) || len(plain)_BE(2) || plain.

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	gost "github.com/bigbes/gostcrypto"
)

const (
	kuznyechikKeySize = 32 // Kuznyechik key size
	magmaKeySize      = 32 // Magma key size
)

// ctrOMACProtector implements Protector for Kuznyechik-CTR-OMAC and
// Magma-CTR-OMAC (RFC 9367 §4.3 and §4.4). No state is shared between records:
// each Seal/Open derives fresh enc and mac keys via TLSTree and constructs a
// fresh CTR and OMAC instance.
//
// acpkmSection is the intra-record ACPKM rekey section for the encryption
// CTR: 4096 bytes for Kuznyechik (gost_grasshopper_cipher.c:334) and 1024
// bytes for Magma (gost_crypt.c:517). OMAC has no intra-record rekeying —
// TLS uses the plain kuznyechik-mac / magma-mac digest (gost_omac.c).
type ctrOMACProtector struct {
	newBlock     func(key []byte) cipher.Block // bound to kuznyechik or magma
	blockSize    int                           // 8 (Magma) or 16 (Kuznyechik)
	tagSize      int                           // 8 (Magma) or 16 (Kuznyechik)
	origIV       []byte                        // 4 bytes (Magma) or 8 bytes (Kuznyechik); copied from constructor arg
	encTree      *gost.TLSTree
	macTree      *gost.TLSTree
	acpkmSection int // 4096 (Kuznyechik) or 1024 (Magma); 0 disables
}

// NewKuznyechikCTROMACProtector creates a per-direction ctrOMACProtector for
// TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC (RFC 9367 §4.3).
//
// encKey and macKey are the per-direction 32-byte enc/MAC keys from the TLS
// key block. iv is the 8-byte fixed IV from the key block (doubles as origIV
// for per-record CTR counter construction). OpenSSL's TLS stack places both
// a 32-byte MAC key and a 32-byte enc key in the key block for this suite
// (ssl/ssl_ciph.c `ssl_mac_secret_size[SSL_MD_KUZNYECHIKOMAC_IDX] = 32`), so
// we take them directly — no KDFTree split here. Per-record diversification
// is TLSTREE on each key, matching tmp/engine/test_tlstree.c:114-146.
func NewKuznyechikCTROMACProtector(encKey, macKey, iv []byte) (Protector, error) {
	if len(encKey) != kuznyechikKeySize {
		return nil, fatalRecordError(fmt.Sprintf(
			"KuznyechikCTROMAC enc key must be %d bytes, got %d", kuznyechikKeySize, len(encKey)))
	}
	if len(macKey) != kuznyechikKeySize {
		return nil, fatalRecordError(fmt.Sprintf(
			"KuznyechikCTROMAC mac key must be %d bytes, got %d", kuznyechikKeySize, len(macKey)))
	}
	if len(iv) != 8 {
		return nil, fatalRecordError(fmt.Sprintf(
			"KuznyechikCTROMAC iv must be 8 bytes, got %d", len(iv)))
	}

	origIV := make([]byte, 8)
	copy(origIV, iv)

	return &ctrOMACProtector{
		newBlock: func(key []byte) cipher.Block {
			return gost.NewKuznyechikCipher(key)
		},
		blockSize:    gost.KuznyechikBlockSize, // 16
		tagSize:      gost.KuznyechikBlockSize, // 16 — OMAC tag = full block (gost_omac.c:48-56)
		origIV:       origIV,
		encTree:      gost.NewTLSTreeKuznyechikCTROMAC(encKey),
		macTree:      gost.NewTLSTreeKuznyechikCTROMAC(macKey),
		acpkmSection: 4096, // gost_grasshopper_cipher.c:334 — c->section_size = 4096
	}, nil
}

// NewMagmaCTROMACProtector creates a per-direction ctrOMACProtector for
// TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC (RFC 9367 §4.4).
//
// encKey and macKey are 32 bytes each; iv is 4 bytes. See the Kuznyechik
// variant for rationale on the MAC key coming from the TLS key block rather
// than a KDFTree split.
func NewMagmaCTROMACProtector(encKey, macKey, iv []byte) (Protector, error) {
	if len(encKey) != magmaKeySize {
		return nil, fatalRecordError(fmt.Sprintf(
			"MagmaCTROMAC enc key must be %d bytes, got %d", magmaKeySize, len(encKey)))
	}
	if len(macKey) != magmaKeySize {
		return nil, fatalRecordError(fmt.Sprintf(
			"MagmaCTROMAC mac key must be %d bytes, got %d", magmaKeySize, len(macKey)))
	}
	if len(iv) != 4 {
		return nil, fatalRecordError(fmt.Sprintf(
			"MagmaCTROMAC iv must be 4 bytes, got %d", len(iv)))
	}

	origIV := make([]byte, 4)
	copy(origIV, iv)

	return &ctrOMACProtector{
		newBlock: func(key []byte) cipher.Block {
			return gost.NewMagmaCipher(key)
		},
		blockSize:    gost.MagmaBlockSize, // 8
		tagSize:      gost.MagmaBlockSize, // 8 — OMAC tag = full block (gost_omac.c:48-56)
		origIV:       origIV,
		encTree:      gost.NewTLSTreeMagmaCTROMAC(encKey),
		macTree:      gost.NewTLSTreeMagmaCTROMAC(macKey),
		acpkmSection: 1024, // gost_crypt.c:517 — c->key_meshing = 1024 for magma_ctr_acpkm
	}, nil
}

// adjustIV returns the CTR counter for the given record sequence number.
//
// For Kuznyechik (origIVLen=8, seqOffset=0):
//
//	out[0..8] = orig_iv[0..8] + seq[0..8]  (big-endian carry add)
//	out[8..16] = 0x00 * 8
//
// For Magma (origIVLen=4, seqOffset=4):
//
//	out[0..4] = orig_iv[0..4] + seq[4..8]  (big-endian carry add)
//	out[4..8] = 0x00 * 4
//
// References:
//   - Kuznyechik: tmp/engine/gost_grasshopper_cipher.c:1147-1156
//   - Magma:      tmp/engine/gost_crypt.c:1309-1318
func (p *ctrOMACProtector) adjustIV(seq uint64) []byte {
	out := make([]byte, p.blockSize)
	copy(out, p.origIV) // [0..origIVLen] = origIV, high bytes already 0

	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)

	// For Kuznyechik: origIVLen=8, seqStart=0  → add seqBytes[0..8] into out[0..8].
	// For Magma:      origIVLen=4, seqStart=4  → add seqBytes[4..8] into out[0..4].
	origIVLen := len(p.origIV)
	seqStart := 8 - origIVLen
	carry := 0
	for j := origIVLen - 1; j >= 0; j-- {
		v := int(out[j]) + int(seqBytes[seqStart+j]) + carry
		carry = v >> 8
		out[j] = byte(v & 0xff)
	}
	return out
}

// Seal computes OMAC over `seq(8) || hdr(5) || plaintext`, then CTR-encrypts
// `plaintext || MAC` as a single continuous stream. Mirrors the reference
// sequence in tmp/engine/test_tlstree.c:119-146: EVP_DigestSignUpdate is fed
// the 8-byte seq, the 5-byte record header, and the plaintext before
// EVP_DigestSignFinal; the cipher then encrypts plaintext and the MAC tag in
// two EVP_Cipher calls that share one CTR keystream.
//
// Wire format: CTR(plaintext) || CTR(MAC).
//
// hdr MUST be the 5-byte TLS record header (type || version || length).
// Callers in `record.Layer` pass the header template with the correct
// plaintext length already set.
func (p *ctrOMACProtector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	encKey := p.encTree.Derive(seq)
	macKey := p.macTree.Derive(seq)

	macBlock := p.newBlock(macKey)

	omac, err := gost.NewOMAC(macBlock, p.tagSize)
	if err != nil {
		return nil, fatalRecordError("ctrOMACProtector Seal OMAC init: " + err.Error())
	}
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	macHdr := macHeaderForOMAC(hdr, len(plain))
	omac.Write(seqBytes[:]) //nolint: errcheck
	omac.Write(macHdr[:])   //nolint: errcheck
	omac.Write(plain)       //nolint: errcheck
	tag := omac.Sum(nil)

	iv := p.adjustIV(seq)
	ctr, err := gost.NewCTRACPKM(p.newBlock, encKey, iv, p.acpkmSection)
	if err != nil {
		return nil, fatalRecordError("ctrOMACProtector Seal CTR init: " + err.Error())
	}

	buf := make([]byte, len(plain)+p.tagSize)
	copy(buf[:len(plain)], plain)
	copy(buf[len(plain):], tag)
	ctr.XORKeyStream(buf, buf)
	return buf, nil
}

// macHeaderForOMAC rebuilds the 5-byte TLS record header with the plaintext
// length in the final two bytes. The caller-supplied hdr carries a placeholder
// length (the record Layer only finalises the length after Seal returns the
// encrypted fragment), so we overwrite it here with the plaintext length —
// which is what the engine test (test_tlstree.c:53-55 `rec0_header`) uses.
func macHeaderForOMAC(hdr []byte, plainLen int) [5]byte {
	var out [5]byte
	out[0] = hdr[0]
	out[1] = hdr[1]
	out[2] = hdr[2]
	binary.BigEndian.PutUint16(out[3:5], uint16(plainLen))
	return out
}

// Open CTR-decrypts the full fragment (ciphertext + encrypted MAC tag),
// recomputes OMAC over the decrypted plaintext, and constant-time compares
// against the decrypted MAC tag.
//
// fragment must be at least tagSize bytes.
// hdr MUST be the 5-byte TLS record header (type || version || length). The
// length field is expected to hold the plaintext length; the record Layer
// recomputes the ciphertext length separately after Open returns.
func (p *ctrOMACProtector) Open(seq uint64, hdr, fragment []byte) ([]byte, error) {
	if len(fragment) < p.tagSize {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	encKey := p.encTree.Derive(seq)
	macKey := p.macTree.Derive(seq)

	macBlock := p.newBlock(macKey)

	iv := p.adjustIV(seq)
	ctr, err := gost.NewCTRACPKM(p.newBlock, encKey, iv, p.acpkmSection)
	if err != nil {
		return nil, fatalRecordError("ctrOMACProtector Open CTR init: " + err.Error())
	}

	buf := make([]byte, len(fragment))
	ctr.XORKeyStream(buf, fragment)

	plainEnd := len(buf) - p.tagSize
	plain := buf[:plainEnd]
	gotTag := buf[plainEnd:]

	omac, err := gost.NewOMAC(macBlock, p.tagSize)
	if err != nil {
		return nil, fatalRecordError("ctrOMACProtector Open OMAC init: " + err.Error())
	}
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	macHdr := macHeaderForOMAC(hdr, plainEnd)
	omac.Write(seqBytes[:]) //nolint: errcheck
	omac.Write(macHdr[:])   //nolint: errcheck
	omac.Write(plain)       //nolint: errcheck
	expectedTag := omac.Sum(nil)

	if subtle.ConstantTimeCompare(gotTag, expectedTag) != 1 {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}
	return plain, nil
}
