package handshake_test

// Coverage-gap tests (black-box) for the handshake package.
//
// This file targets Transcript.Sum edge cases that the existing
// transcript_test.go does not: Sum on a completely empty transcript, Sum
// idempotence across back-to-back calls, and a Write interleaved between two
// Sum calls. The independent oracle in every case is crypto/sha256 over the
// exact byte sequence the transcript is expected to have replayed.

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/bigbes/gostls/internal/handshake"
)

// TestTranscript_SumOnEmptyTranscript verifies that calling Sum before any
// Write returns the digest of the empty input (not an error, not a nil slice).
// Oracle: sha256.Sum256(nil), the SHA-256 of the empty string.
func TestTranscript_SumOnEmptyTranscript(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()

	got, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum on empty transcript: unexpected error: %v", err)
	}

	want := sha256.Sum256(nil)
	if !bytes.Equal(got, want[:]) {
		t.Errorf("empty-transcript digest:\n  got  %x\n  want %x", got, want[:])
	}
}

// TestTranscript_SumIdempotent verifies that two back-to-back Sum calls on the
// same (unmodified) transcript return byte-identical results. The buffer is
// never consumed by Sum, so the replay must be reproducible.
func TestTranscript_SumIdempotent(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()
	tr.Write([]byte("first"))
	tr.Write([]byte("second"))

	first, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum #1: %v", err)
	}

	second, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum #2: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("Sum not idempotent:\n  first  %x\n  second %x", first, second)
	}

	// Cross-check against an independent oracle.
	want := sha256.Sum256([]byte("firstsecond"))
	if !bytes.Equal(first, want[:]) {
		t.Errorf("digest mismatch:\n  got  %x\n  want %x", first, want[:])
	}
}

// TestTranscript_WriteBetweenSums verifies that a Write performed after a Sum
// is reflected in a subsequent Sum: the second digest must cover the newly
// appended bytes and therefore differ from the first.
func TestTranscript_WriteBetweenSums(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()
	tr.Write([]byte("alpha"))

	before, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum before extra Write: %v", err)
	}

	tr.Write([]byte("beta"))

	after, err := tr.Sum(sha256.New)
	if err != nil {
		t.Fatalf("Sum after extra Write: %v", err)
	}

	if bytes.Equal(before, after) {
		t.Fatal("Sum did not reflect the Write performed between the two Sum calls")
	}

	// The second Sum must equal the hash of the full concatenation.
	wantBefore := sha256.Sum256([]byte("alpha"))
	if !bytes.Equal(before, wantBefore[:]) {
		t.Errorf("first digest:\n  got  %x\n  want %x", before, wantBefore[:])
	}

	wantAfter := sha256.Sum256([]byte("alphabeta"))
	if !bytes.Equal(after, wantAfter[:]) {
		t.Errorf("second digest:\n  got  %x\n  want %x", after, wantAfter[:])
	}
}
