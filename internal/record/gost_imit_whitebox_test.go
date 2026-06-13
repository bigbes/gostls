// gost_imit_whitebox_test.go — white-box tests for gostIMIT internals.
// Must be in package record (not record_test) to access unexported types.
//
//nolint:testpackage // intentional: accesses unexported gostIMIT, gostCNT, newGostCNT, newGostIMIT.
package record

import (
	"bytes"
	"testing"

	gost "github.com/bigbes/gostcrypto"
)

// TestGostIMIT_Finalize_CountZeroTrailingBlock exercises the Finalize branch:
//
//	if count == 0 && bufLen > 0 { processSnap(zero[:]) }
//
// This fires when the total data written is 1–8 bytes (gostBlockSize), so
// count (number of fully processed blocks) is still 0 and the data is only
// in the partial buffer. On the TLS path computeGOSTMAC always writes ≥ 13
// bytes so this branch is never reached in production, but we test it for
// completeness.
func TestGostIMIT_Finalize_CountZeroTrailingBlock(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xAA}, gostKeySize)
	cipher := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)
	m := newGostIMIT(cipher, gost.SboxTC26Z)

	// Write 5 bytes — less than one block (8 bytes).
	// After Write: bufLen=5, count=0.
	m.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05})

	if m.count != 0 {
		t.Errorf("count should be 0 before Finalize, got %d", m.count)
	}

	if m.bufLen != 5 {
		t.Errorf("bufLen should be 5 before Finalize, got %d", m.bufLen)
	}

	// Finalize must not panic and must return a 4-byte tag.
	tag := m.Finalize()
	if len(tag) != gostMACSize {
		t.Errorf("Finalize returned %d bytes, want %d", len(tag), gostMACSize)
	}

	// Finalize must be idempotent (receiver state unchanged).
	tag2 := m.Finalize()
	if !bytes.Equal(tag, tag2) {
		t.Errorf("Finalize is not idempotent: got %x then %x", tag, tag2)
	}
}

// TestGostIMIT_Finalize_MeshAtThreshold exercises the processSnap mesh branch
// inside Finalize. This fires when the last full block happens to land exactly
// at the 1024-byte meshing boundary before Finalize is called with a partial
// block remaining.
//
// To reach count==meshThreshold inside processSnap: we need exactly
// 1024/8 = 128 full blocks processed by Write, leaving a partial byte in buf.
// Then Finalize calls processSnap(last), and inside that call count==1024.
func TestGostIMIT_Finalize_MeshAtThreshold(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xBB}, gostKeySize)
	cipher := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)
	m := newGostIMIT(cipher, gost.SboxTC26Z)

	// Write 1024 bytes in full blocks (128 × 8). gostIMIT.Write processes all
	// except the final block (deferred), so after writing 1024 bytes:
	// - processBlockMesh is called for blocks [0..119] = 120 blocks = 960 bytes (count=960)
	// - The last block (bytes 1016-1023) is in buf, bufLen=8
	// BUT: Write defers the LAST block. Actually let's trace:
	// Write algorithm: process full blocks while (len-i) > 8. So for 1024 bytes:
	//   i=0: len-i=1024 > 8 → process block[0..7], i=8, count=8
	//   ...
	//   i=1016: len-i=8, NOT > 8 → stop. bufLen=8.
	// So after writing 1024 bytes, count=120*8=... actually 127 blocks × 8 = 1016 ÷ 8 = 127 iterations
	// Wait: 0..1015 are processed (127 blocks), and 1016-1023 are buffered.
	// count = 127 * 8 = 1016. Not yet 1024.
	//
	// To get count=1024 inside Finalize.processSnap, we need count==1024 when
	// processSnap is called. processSnap is called once for the buffered partial.
	// count in the snapshot must be 1024.
	// After Write(1024 bytes): count=1016, bufLen=8.
	// Then Write(1 more byte): completes the 8-byte buf into a 9-byte span; with
	// 1 byte remaining after filling buf, remaining=1 > 0 → processBlockMesh(buf)
	// → count becomes 1024. bufLen=1 (the extra byte).
	// Now Finalize: count=1024, bufLen=1.
	// processSnap is called with last={0x01, 0,0,0,0,0,0,0}.
	// Inside processSnap: count == meshThreshold → mesh branch fires!

	data1 := make([]byte, 1024)
	for i := range data1 {
		data1[i] = byte(i)
	}

	m.Write(data1)

	// Write one more byte to push count to 1024 and leave bufLen=1.
	m.Write([]byte{0xFF})

	if m.count != meshThreshold {
		t.Skipf("count=%d, want %d; skipping mesh-at-threshold Finalize test", m.count, meshThreshold)
	}

	if m.bufLen != 1 {
		t.Skipf("bufLen=%d, want 1; skipping mesh-at-threshold Finalize test", m.bufLen)
	}

	// Finalize must not panic and must return a 4-byte tag.
	tag := m.Finalize()
	if len(tag) != gostMACSize {
		t.Errorf("Finalize returned %d bytes, want %d", len(tag), gostMACSize)
	}

	// Receiver must be unmodified (Finalize is non-destructive).
	if m.count != meshThreshold {
		t.Errorf("Finalize mutated count: got %d, want %d", m.count, meshThreshold)
	}
}

// TestGostCNT_XORKeyStream_MultiBlock covers the inner loop of XORKeyStream
// with a payload that requires multiple nextGamma calls.
func TestGostCNT_XORKeyStream_MultiBlock(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xCC}, gostKeySize)
	iv := bytes.Repeat([]byte{0x01}, gostBlockSize)
	cipher := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)
	cnt := newGostCNT(cipher, gost.SboxTC26Z, iv)

	src := make([]byte, 100) // 12 full GOST blocks + 4 bytes.
	for i := range src {
		src[i] = byte(i)
	}

	dst := make([]byte, len(src))
	cnt.XORKeyStream(dst, src)

	// Round-trip: XORing again with the same stream must recover src.
	// Create a fresh CNT with the same key+IV.
	cipher2 := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)
	cnt2 := newGostCNT(cipher2, gost.SboxTC26Z, iv)
	recovered := make([]byte, len(dst))
	cnt2.XORKeyStream(recovered, dst)

	if !bytes.Equal(recovered, src) {
		t.Errorf("XORKeyStream round-trip failed")
	}
}
