package handshake_test

// Phase 1 TDD red — tests for the buffer-and-replay Transcript redesign.
//
// On current master, Transcript.Sum takes hash.Hash (an already-instantiated
// hash). The tests below call Sum(sha256.New) — a factory (func() hash.Hash).
// That type mismatch causes a compile error on master; this is the intended
// red signal. Phase 2 rewrites Transcript to match the new API and makes
// these tests green.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/bigbes/gostls/internal/handshake"
)

// fakeHash is a hash.Hash whose BlockSize and Size match SHA-256 (64/32) but
// whose Sum always returns 32 bytes of 0xAA, clearly distinct from any real
// SHA-256 digest. Used by TestTranscript_ShapeCollidingFactoriesProduceDistinctDigests
// to prove that Transcript.Sum dispatches by factory identity, not by shape.
type fakeHash struct{}

func (fakeHash) Write(p []byte) (int, error) { return len(p), nil }
func (fakeHash) Sum(b []byte) []byte         { return append(b, bytes.Repeat([]byte{0xAA}, 32)...) }
func (fakeHash) Reset()                      {}
func (fakeHash) Size() int                   { return 32 }
func (fakeHash) BlockSize() int              { return 64 }

func fakeFactory() hash.Hash { return &fakeHash{} }

// TestTranscript_SumReplaysAllWrittenBytes verifies that after writing three
// chunks, Sum(sha256.New) returns the same digest as hashing the concatenation
// from scratch.
func TestTranscript_SumReplaysAllWrittenBytes(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()

	chunk1 := []byte("handshake message one")
	chunk2 := []byte("second chunk")
	chunk3 := []byte("third chunk bytes")

	tr.Write(chunk1)
	tr.Write(chunk2)
	tr.Write(chunk3)

	all := append(append(append([]byte{}, chunk1...), chunk2...), chunk3...)
	h := sha256.New()
	h.Write(all)

	want := h.Sum(nil)

	got, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum(sha256.New): unexpected error: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("SHA-256 digest mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestTranscript_SumWithFactoryIndependentOfSuite verifies that any two calls
// to Sum with different factories on the same transcript both return correct
// digests, with no order dependency and no Collapse call anywhere.
func TestTranscript_SumWithFactoryIndependentOfSuite(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()

	chunk1 := []byte("alpha bytes")
	chunk2 := []byte("beta bytes")
	chunk3 := []byte("gamma bytes")

	tr.Write(chunk1)
	tr.Write(chunk2)
	tr.Write(chunk3)

	all := append(append(append([]byte{}, chunk1...), chunk2...), chunk3...)

	h256 := sha256.New()
	h256.Write(all)

	want256 := h256.Sum(nil)

	h384 := sha512.New384()
	h384.Write(all)

	want384 := h384.Sum(nil)

	got256, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum(sha256.New): %v", err)
	}

	if !bytes.Equal(got256, want256) {
		t.Errorf("SHA-256 mismatch:\n  got  %x\n  want %x", got256, want256)
	}

	got384, err := tr.Sum(sha512.New384)
	if err != nil {
		t.Fatalf("Sum(sha512.New384): %v", err)
	}

	if !bytes.Equal(got384, want384) {
		t.Errorf("SHA-384 mismatch:\n  got  %x\n  want %x", got384, want384)
	}

	// Calling in reverse order must also be correct — no order dependency.
	got384b, err := tr.Sum(sha512.New384)
	if err != nil {
		t.Fatalf("Sum(sha512.New384) second call: %v", err)
	}

	if !bytes.Equal(got384b, want384) {
		t.Errorf("SHA-384 second call mismatch:\n  got  %x\n  want %x", got384b, want384)
	}
}

// TestTranscript_ShapeCollidingFactoriesProduceDistinctDigests is a regression
// test for the Streebog-256 / SHA-256 footgun. fakeHash has identical
// BlockSize()==64 and Size()==32 to sha256.New — the same shape — but returns
// 32 bytes of 0xAA from Sum. On the old master design, shape-match meant both
// factories would reach the same tracked hash and produce the same digest.
// Under the new buffer-and-replay design, the factory passed to Sum is what
// determines the result: tr.Sum(sha256.New) ≠ tr.Sum(fakeFactory).
func TestTranscript_ShapeCollidingFactoriesProduceDistinctDigests(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()

	tr.Write([]byte("some transcript bytes"))
	tr.Write([]byte("more bytes"))

	got256, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum(sha256.New): %v", err)
	}

	gotFake, err := tr.Sum(fakeFactory)
	if err != nil {
		t.Fatalf("Sum(fakeFactory): %v", err)
	}

	// The fake always returns 0xAA*32; SHA-256 will never produce that.
	wantFake := bytes.Repeat([]byte{0xAA}, 32)
	if !bytes.Equal(gotFake, wantFake) {
		t.Errorf("fakeFactory digest: got %x, want %x", gotFake, wantFake)
	}

	// The two results must differ, proving identity is factory-based not shape-based.
	if bytes.Equal(got256, gotFake) {
		t.Errorf("sha256.New and fakeFactory produced the same digest (%x) — shape-match bug still present", got256)
	}
}

// TestTranscript_SumNilFactoryErrors verifies that Sum(nil) returns a non-nil
// error and does not panic.
func TestTranscript_SumNilFactoryErrors(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()
	tr.Write([]byte("some bytes"))

	result, err := tr.Sum(nil)
	if err == nil {
		t.Fatalf("Sum(nil) returned nil error; want non-nil error. result=%x", result)
	}
}
