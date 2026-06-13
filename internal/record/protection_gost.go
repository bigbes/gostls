package record

// protection_gost.go implements the TLS 1.2 record-layer Protector for
// GOST 28147-89 in CNT (counter stream) mode with GOST 28147-89 IMIT MAC.
//
// Wire format (Seal output): Encrypt(plaintext || MAC).
//
// The MAC is cumulative: the GOST IMIT MAC internal state (prev buffer)
// carries across records. This matches OpenSSL's stream_mac=1 behavior where
// tls1_mac reuses the same EVP_MD_CTX for every record without resetting.
// After gost_imit_final outputs the tag, the internal c->buffer retains the
// final MAC block state, so the next record's gost_imit_update XORs new data
// into that state — making each record's MAC depend on all preceding records.
//
// The CNT cipher state is also persistent across records — the counter is NOT
// reset for each record, matching gost-engine's EVP_CIPHER_CTX behavior.
//
// Both the CNT mode and IMIT MAC are reimplemented here using only gogost's
// block cipher because gogost's CTR and MAC types have bugs that prevent
// streaming use across multiple calls.
//
// References:
//   - RFC 5830 §6.2 — GOST 28147-89 counter mode (C1, C2 constants)
//   - RFC 5246 §6.2.3.1 — GenericStreamCipher MAC computation
//   - OpenSSL ssl/record/methods/tls1_meth.c:tls1_mac — stream_mac path
//   - gost-engine gost_crypt.c:gost_cnt_next, gost_imit_update/final
//   - gost-engine gost89.c:mac_block — 16-round CBC-MAC block step

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	gost "github.com/bigbes/gostcrypto"
)

const (
	gostBlockSize = gost.GOST28147BlockSize // 8
	gostMACSize   = 4
	gostKeySize   = gost.GOST28147KeySize // 32

	// Bit-shift constants for little-endian 32-bit word packing in nextGamma.
	// GOST 28147-89 CNT counter words are encoded in little-endian byte order
	// (RFC 5830 §6.2, gost-engine gost_cnt_next).
	shift8  = 8
	shift16 = 16
	shift24 = 24
)

// ── CNT (counter stream) mode ────────────────────────────────────────────────.

type gostCNT struct {
	cipher *gost.GOST28147Cipher
	sbox   *gost.Sbox
	iv     [gostBlockSize]byte
	buf    [gostBlockSize]byte
	num    int
	count  int
}

func newGostCNT(cipher *gost.GOST28147Cipher, sbox *gost.Sbox, iv []byte) *gostCNT {
	s := &gostCNT{cipher: cipher, sbox: sbox}
	copy(s.iv[:], iv)

	return s
}

func (s *gostCNT) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); {
		if s.num == 0 {
			s.nextGamma()
		}

		for s.num < gostBlockSize && i < len(src) {
			dst[i] = src[i] ^ s.buf[s.num]
			s.num++

			i++
		}

		if s.num == gostBlockSize {
			s.num = 0
		}
	}
}

// meshKey performs CryptoPro key meshing with IV update, matching
// gost-engine's cryptopro_key_meshing called with a non-NULL iv
// (gost89.c:750-766). A new cipher key is derived by ECB-decrypting
// the meshing constant with the current cipher, then the IV is
// re-encrypted under the new key.
func (s *gostCNT) meshKey() {
	var newKey [gostKeySize]byte

	for j := range 4 {
		s.cipher.Decrypt(
			newKey[j*gostBlockSize:(j+1)*gostBlockSize],
			cryptoProKeyMeshingKey[j*gostBlockSize:(j+1)*gostBlockSize],
		)
	}

	s.cipher = gost.NewGOST28147Cipher(newKey[:], s.sbox)

	var newIV [gostBlockSize]byte

	s.cipher.Encrypt(newIV[:], s.iv[:])

	s.iv = newIV
}

func (s *gostCNT) nextGamma() {
	// Key meshing triggers before any encryption at count==1024.
	// The meshed iv (re-encrypted under the new key inside meshKey) is used
	// directly on this step — count is NOT reset to 0, otherwise the
	// initial-block path would re-encrypt the already-meshed iv.
	if s.count == meshThreshold {
		s.meshKey()
	}

	var buf1 [gostBlockSize]byte

	if s.count == 0 {
		s.cipher.Encrypt(buf1[:], s.iv[:])
	} else {
		copy(buf1[:], s.iv[:])
	}

	g := uint32(buf1[0]) | uint32(buf1[1])<<shift8 | uint32(buf1[2])<<shift16 | uint32(buf1[3])<<shift24

	g += 0x01010101

	buf1[0] = byte(g)
	buf1[1] = byte(g >> shift8)
	buf1[2] = byte(g >> shift16)
	buf1[3] = byte(g >> shift24)

	g2 := uint32(buf1[4]) | uint32(buf1[5])<<shift8 | uint32(buf1[6])<<shift16 | uint32(buf1[7])<<shift24
	g2old := g2

	g2 += 0x01010104

	if g2old > g2 {
		g2++
	}

	buf1[4] = byte(g2)
	buf1[5] = byte(g2 >> shift8)
	buf1[6] = byte(g2 >> shift16)
	buf1[7] = byte(g2 >> shift24)
	copy(s.iv[:], buf1[:])
	s.cipher.Encrypt(s.buf[:], buf1[:])

	s.count = s.count%meshThreshold + gostBlockSize
}

// ── IMIT (CBC-MAC) with persistent state ─────────────────────────────────────.

// meshThreshold is the number of bytes processed before CryptoPro key
// meshing triggers. Matches gost-engine's mac_block_mesh assertion:
//
//	assert(c->count % 8 == 0 && c->count <= 1024)
const meshThreshold = 1024

// cryptoProKeyMeshingKey is the 32-byte constant from RFC 4357 §2.3.2.
// Source: tmp/engine/gost89.c:240-245.
var cryptoProKeyMeshingKey = [gostKeySize]byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

// gostIMIT implements GOST 28147-89 IMIT MAC as a streaming MAC whose state
// persists across Finalize calls. Uses gogost's MAC for the 16-round SeqMAC
// block encrypt step (since Cipher.Encrypt uses 32 rounds, not 16).
//
// Implements CryptoPro key meshing (RFC 4357 §2.3.2): every 1024 bytes of
// processed full blocks, the cipher key is replaced by ECB-decrypting
// cryptoProKeyMeshingKey with the current key. Mirrors gost-engine's
// mac_block_mesh (gost_crypt.c:1510-1524).
type gostIMIT struct {
	cipher *gost.GOST28147Cipher
	sbox   *gost.Sbox
	prev   [gostBlockSize]byte // CBC-MAC chaining state (persistent).
	buf    [gostBlockSize]byte // partial block buffer.
	bufLen int                 // bytes pending in buf.
	count  int                 // bytes processed in full blocks (mod-1024 + 8 per block).
}

func newGostIMIT(cipher *gost.GOST28147Cipher, sbox *gost.Sbox) *gostIMIT {
	return &gostIMIT{cipher: cipher, sbox: sbox}
}

// Write feeds data into the IMIT MAC. Mirrors gost-engine's gost_imit_update
// (gost_crypt.c:1526-1557): full blocks are processed while more than 8 bytes
// remain; the trailing 1–8 bytes are buffered (bufLen may be 8 — a full block
// is deferred until Final or the next Write). This matters because it shifts
// the count and therefore key-meshing boundaries relative to eager processing.
func (m *gostIMIT) Write(data []byte) {
	i := 0
	// Complete any existing buffered bytes.
	if m.bufLen > 0 {
		for m.bufLen < gostBlockSize && i < len(data) {
			m.buf[m.bufLen] = data[i]
			m.bufLen++

			i++
		}

		if m.bufLen < gostBlockSize {
			return
		}

		// bufLen == 8: only process if more data follows.
		remaining := len(data) - i
		if remaining > 0 {
			m.processBlockMesh(m.buf[:])

			m.bufLen = 0
		} else {
			// Defer this full block — it will be processed by next Write or Finalize.
			return
		}
	}

	// Process full blocks while more than 8 bytes remain (bytes > 8, not >=).
	for len(data)-i > gostBlockSize {
		m.processBlockMesh(data[i : i+gostBlockSize])

		i += gostBlockSize
	}

	// Buffer trailing 1..8 bytes.
	if i < len(data) {
		m.bufLen = copy(m.buf[:], data[i:])
	}
}

// Finalize outputs the 4-byte IMIT tag without mutating the receiver.
//
// OpenSSL's EVP_DigestSignFinal copies the digest context, finalizes the
// copy, and frees it — leaving the original context unchanged. With
// stream_mac=1 (TLS1_STREAM_MAC), tls1_mac uses the persistent context
// directly, so after Final the original still holds whatever partial
// block and chaining state resulted from the last Update call.
//
// We replicate this: snapshot prev/buf/count, run the final-padding
// logic on the snapshot, and return the tag. The receiver's state is
// unchanged — the next record's Write picks up exactly where the
// previous Write left off.
func (m *gostIMIT) Finalize() []byte {
	// Snapshot mutable state.
	prev := m.prev
	buf := m.buf
	bufLen := m.bufLen
	count := m.count

	// processBlock-on-snapshot: XOR + 16-round SeqMAC, updating prev.
	// Key meshing is handled here too; since we're snapshotting, we use
	// the current cipher (which may have been meshed during Write).
	processSnap := func(block []byte) {
		// Note: key meshing in Finalize's copy is extremely unlikely
		// (would require the partial block to land exactly at 1024),
		// but we handle it for correctness.
		cipher := m.cipher

		if count == meshThreshold {
			// We can't mutate m.cipher, so derive the meshed key locally.
			var newKey [gostKeySize]byte

			for j := range 4 {
				cipher.Decrypt(
					newKey[j*gostBlockSize:(j+1)*gostBlockSize],
					cryptoProKeyMeshingKey[j*gostBlockSize:(j+1)*gostBlockSize],
				)
			}

			cipher = gost.NewGOST28147Cipher(newKey[:], m.sbox)
		}

		var xored [gostBlockSize]byte

		for i := range gostBlockSize {
			xored[i] = prev[i] ^ block[i]
		}

		prev = m.macBlockEncrypt(cipher, xored)
		count = count%meshThreshold + gostBlockSize
	}

	// gost-engine finalization order: MAC the (zero-padded) data block first,
	// then — when no full block preceded it (count == 0, i.e. total MAC input
	// <= 8 bytes) — a TRAILING all-zero block (gost_crypt.c:1566-1577). The
	// trailing block never fires on the TLS path (the framing prefix makes the
	// MAC input >= 13 bytes, so count > 0), but feeding the data block before
	// the zero block matches the engine for short inputs too.
	if bufLen > 0 {
		var last [gostBlockSize]byte

		copy(last[:], buf[:bufLen])
		processSnap(last[:])
	}

	if count == 0 && bufLen > 0 {
		var zero [gostBlockSize]byte

		processSnap(zero[:])
	}

	tag := make([]byte, gostMACSize)
	copy(tag, prev[:gostMACSize])

	return tag
}

// macBlockEncrypt performs the 16-round SeqMAC encrypt of an 8-byte block via
// the cipher's SeqMACBlock primitive (the 16-round schedule, distinct from the
// 32-round Encrypt).
func (m *gostIMIT) macBlockEncrypt(cipher *gost.GOST28147Cipher, block [gostBlockSize]byte) [gostBlockSize]byte {
	result := cipher.SeqMACBlock(block[:])

	var out [gostBlockSize]byte

	copy(out[:], result)

	return out
}

// meshKey performs CryptoPro key meshing: ECB-decrypt the meshing constant
// with the current cipher, producing a new 32-byte key. Returns a new Cipher.
// Mirrors gost-engine's cryptopro_key_meshing (gost89.c:750-766) with iv=NULL.
func (m *gostIMIT) meshKey() {
	var newKey [gostKeySize]byte

	for j := range 4 {
		m.cipher.Decrypt(
			newKey[j*gostBlockSize:(j+1)*gostBlockSize],
			cryptoProKeyMeshingKey[j*gostBlockSize:(j+1)*gostBlockSize],
		)
	}

	m.cipher = gost.NewGOST28147Cipher(newKey[:], m.sbox)
}

// processBlockMesh applies key meshing (when threshold is reached), then
// XORs the 8-byte block with prev and 16-round-encrypts the result.
// Mirrors gost-engine's mac_block_mesh (gost_crypt.c:1510-1524).
func (m *gostIMIT) processBlockMesh(block []byte) {
	if m.count == meshThreshold {
		m.meshKey()
	}

	var xored [gostBlockSize]byte

	for i := range gostBlockSize {
		xored[i] = m.prev[i] ^ block[i]
	}

	m.prev = m.macBlockEncrypt(m.cipher, xored)
	m.count = m.count%meshThreshold + gostBlockSize
}

// ── Protector ────────────────────────────────────────────────────────────────.

type gost28147Protector struct {
	sbox   *gost.Sbox
	macKey []byte
	cnt    *gostCNT
	imit   *gostIMIT
}

func NewGOST28147Protector(encKey, macKey, iv []byte, sbox *gost.Sbox) (Protector, error) {
	if len(encKey) != gostKeySize {
		return nil, fatalRecordError(fmt.Sprintf(
			"GOST28147 enc key must be %d bytes, got %d", gostKeySize, len(encKey)))
	}

	if len(macKey) != gostKeySize {
		return nil, fatalRecordError(fmt.Sprintf(
			"GOST28147 mac key must be %d bytes, got %d", gostKeySize, len(macKey)))
	}

	if len(iv) != gostBlockSize {
		return nil, fatalRecordError(fmt.Sprintf(
			"GOST28147 iv must be %d bytes, got %d", gostBlockSize, len(iv)))
	}

	ek := make([]byte, gostKeySize)
	copy(ek, encKey)

	mk := make([]byte, gostKeySize)
	copy(mk, macKey)

	encCipher := gost.NewGOST28147Cipher(ek, sbox)
	cnt := newGostCNT(encCipher, sbox, iv)

	macCipher := gost.NewGOST28147Cipher(mk, sbox)
	imit := newGostIMIT(macCipher, sbox)

	return &gost28147Protector{
		sbox:   sbox,
		macKey: mk,
		cnt:    cnt,
		imit:   imit,
	}, nil
}

func (p *gost28147Protector) Seal(seq uint64, hdr, plain []byte) ([]byte, error) {
	mac := p.computeGOSTMAC(seq, hdr, plain)
	buf := make([]byte, len(plain)+gostMACSize)
	copy(buf, plain)
	copy(buf[len(plain):], mac)
	p.cnt.XORKeyStream(buf, buf)

	return buf, nil
}

func (p *gost28147Protector) Open(seq uint64, hdr, fragment []byte) ([]byte, error) {
	if len(fragment) < gostMACSize {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	buf := make([]byte, len(fragment))
	p.cnt.XORKeyStream(buf, fragment)

	plainEnd := len(buf) - gostMACSize
	plain := buf[:plainEnd]
	gotMAC := buf[plainEnd:]
	expectedMAC := p.computeGOSTMAC(seq, hdr, plain)

	if subtle.ConstantTimeCompare(gotMAC, expectedMAC) != 1 {
		return nil, NewFatalAlertError(AlertBadRecordMAC)
	}

	return plain, nil
}

func (p *gost28147Protector) computeGOSTMAC(seq uint64, hdr, plain []byte) []byte {
	var ad [macADLen]byte

	binary.BigEndian.PutUint64(ad[0:8], seq)
	copy(ad[8:11], hdr[0:3])
	binary.BigEndian.PutUint16(ad[11:13], uint16(len(plain)))
	p.imit.Write(ad[:])
	p.imit.Write(plain)

	return p.imit.Finalize()
}
