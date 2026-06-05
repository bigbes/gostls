package handshake

import (
	"errors"
	"testing"

	"github.com/bigbes/gostcrypto/x509gost"
)

// TestExtractGOSTRoots_Nil returns ErrGOSTRootsRequired for nil.
func TestExtractGOSTRoots_Nil(t *testing.T) {
	if _, err := extractGOSTRoots(nil); !errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("nil: got %v, want ErrGOSTRootsRequired", err)
	}
}

// TestExtractGOSTRoots_EmptySlice also returns ErrGOSTRootsRequired.
func TestExtractGOSTRoots_EmptySlice(t *testing.T) {
	if _, err := extractGOSTRoots([]*x509gost.Certificate{}); !errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("empty slice: got %v, want ErrGOSTRootsRequired", err)
	}
}

// TestExtractGOSTRoots_WrongType returns a typed error naming the bad type.
func TestExtractGOSTRoots_WrongType(t *testing.T) {
	_, err := extractGOSTRoots("not a roots list")
	if err == nil {
		t.Fatal("wrong type: expected error, got nil")
	}
	if errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("wrong type: error should not wrap ErrGOSTRootsRequired: %v", err)
	}
}

// TestExtractGOSTRoots_Valid returns the slice unchanged on success.
func TestExtractGOSTRoots_Valid(t *testing.T) {
	roots := []*x509gost.Certificate{{}}
	got, err := extractGOSTRoots(roots)
	if err != nil {
		t.Fatalf("valid roots: unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("valid roots: len got %d, want 1", len(got))
	}
}
