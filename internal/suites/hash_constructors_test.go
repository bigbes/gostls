//nolint:testpackage // white-box: exercises unexported sha1New and gost28147IMITHashNew
package suites

import (
	"crypto/sha1" //nolint:gosec // testing sha1New which wraps legacy SHA-1 for CBC-SHA suites
	"testing"

	gost "github.com/bigbes/gostcrypto"
)

// TestSha1New verifies that sha1New returns a valid SHA-1 hash.Hash with the
// correct Size, BlockSize, and digest output.
//
// sha1New is used by specHMACSHA1 (registry.go) for legacy CBC-SHA suites —
// any wrong delegation (e.g. to SHA-256) would silently produce wrong MACs.
func TestSha1New(t *testing.T) {
	t.Parallel()

	h := sha1New()
	if h == nil {
		t.Fatal("sha1New returned nil")
	}

	// Size must be sha1.Size (20 bytes).
	if got, want := h.Size(), sha1.Size; got != want { //nolint:gosec
		t.Errorf("sha1New Size: got %d, want %d", got, want)
	}

	// BlockSize must be sha1.BlockSize (64 bytes).
	if got, want := h.BlockSize(), sha1.BlockSize; got != want { //nolint:gosec
		t.Errorf("sha1New BlockSize: got %d, want %d", got, want)
	}

	// Digest must match the standard library's SHA-1.
	input := []byte("sha1 test vector")

	_, _ = h.Write(input)

	got := h.Sum(nil)

	want := sha1.Sum(input) //nolint:gosec

	if string(got) != string(want[:]) {
		t.Errorf("sha1New digest mismatch: got %x, want %x", got, want)
	}
}

// TestSha1New_Reset verifies that Reset clears state so subsequent writes
// produce the same result as a fresh hash.
func TestSha1New_Reset(t *testing.T) {
	t.Parallel()

	input := []byte("reset check")

	h1 := sha1New()

	_, _ = h1.Write(input)

	sum1 := h1.Sum(nil)

	// Write garbage, then reset.
	_, _ = h1.Write([]byte("garbage"))
	h1.Reset()

	_, _ = h1.Write(input)

	sum2 := h1.Sum(nil)

	if string(sum1) != string(sum2) {
		t.Errorf("sha1New Reset: digest differs after reset: %x vs %x", sum1, sum2)
	}
}

// TestGOST28147IMITHashNew verifies that gost28147IMITHashNew returns a
// hash.Hash with the metadata contract required by specGOST28147IMIT:
//   - Size() == 4  (gostIMITMACLen in gost_suites.go)
//   - BlockSize() == 8  (gost.GOST28147BlockSize)
//   - Sum() appends exactly 4 zero bytes (placeholder; real MAC is in protector)
//   - Write accepts any data without error
//   - Reset clears written-byte accounting.
func TestGOST28147IMITHashNew(t *testing.T) {
	t.Parallel()

	h := gost28147IMITHashNew()
	if h == nil {
		t.Fatal("gost28147IMITHashNew returned nil")
	}

	// Size must be 4 (IMIT truncated to 4 bytes per RFC 9189 §4.2).
	if got, want := h.Size(), 4; got != want {
		t.Errorf("gost28147IMITHashNew Size: got %d, want %d", got, want)
	}

	// BlockSize must match GOST 28147-89 block size (8 bytes).
	if got, want := h.BlockSize(), int(gost.GOST28147BlockSize); got != want {
		t.Errorf("gost28147IMITHashNew BlockSize: got %d, want %d", got, want)
	}

	// Write must not error and must not panic for arbitrary data.
	n, err := h.Write([]byte("some data that gets ignored"))
	if err != nil {
		t.Errorf("gost28147IMITHashNew Write: unexpected error: %v", err)
	}

	if n != len("some data that gets ignored") {
		t.Errorf("gost28147IMITHashNew Write: returned n=%d, want %d", n, len("some data that gets ignored"))
	}

	// Sum(nil) must return 4 zero bytes (placeholder contract).
	tag := h.Sum(nil)
	if len(tag) != 4 {
		t.Fatalf("gost28147IMITHashNew Sum(nil): got %d bytes, want 4", len(tag))
	}

	for i, b := range tag {
		if b != 0 {
			t.Errorf("gost28147IMITHashNew Sum(nil)[%d] = 0x%02x, want 0x00", i, b)
		}
	}

	// Sum(prefix) must append 4 zero bytes to the prefix, not overwrite it.
	prefix := []byte{0xFF}
	appended := h.Sum(prefix)

	if len(appended) != 5 {
		t.Fatalf("gost28147IMITHashNew Sum(prefix): got %d bytes, want 5", len(appended))
	}

	if appended[0] != 0xFF {
		t.Errorf("gost28147IMITHashNew Sum(prefix): prefix byte corrupted: got 0x%02x, want 0xFF", appended[0])
	}

	for i, b := range appended[1:] {
		if b != 0 {
			t.Errorf("gost28147IMITHashNew Sum(prefix)[%d+1] = 0x%02x, want 0x00", i, b)
		}
	}

	// Reset must be a no-op (no panic) and the hash must remain usable after.
	h.Reset()

	tag2 := h.Sum(nil)

	if len(tag2) != 4 {
		t.Errorf("gost28147IMITHashNew Sum after Reset: got %d bytes, want 4", len(tag2))
	}
}

// TestGOST28147IMITHashNew_UsedBySpecGOST28147IMIT verifies that the MACSpec
// wired into the GOST 28147 suites actually calls gost28147IMITHashNew and
// that the returned hash has the contract the suite registry expects.
//
// This is an end-to-end guard: if specGOST28147IMIT.Hash were swapped to some
// other constructor this test would catch the divergence via the Size mismatch.
func TestGOST28147IMITHashNew_UsedBySpecGOST28147IMIT(t *testing.T) {
	t.Parallel()

	if specGOST28147IMIT.Hash == nil {
		t.Fatal("specGOST28147IMIT.Hash is nil — GOST IMIT suite misconfigured")
	}

	h := specGOST28147IMIT.Hash()
	if h == nil {
		t.Fatal("specGOST28147IMIT.Hash() returned nil")
	}

	if got, want := h.Size(), specGOST28147IMIT.MACLen; got != want {
		t.Errorf("specGOST28147IMIT.Hash().Size() = %d, want MACLen=%d", got, want)
	}

	if got, want := h.BlockSize(), int(gost.GOST28147BlockSize); got != want {
		t.Errorf("specGOST28147IMIT.Hash().BlockSize() = %d, want %d", got, want)
	}
}
