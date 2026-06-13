//nolint:testpackage // white-box: exercises unexported extractGOSTRoots
package handshake

import (
	"errors"
	"testing"

	"github.com/bigbes/gostcrypto/x509gost"
)

// TestExtractGOSTRoots_Nil returns ErrGOSTRootsRequired for nil.
func TestExtractGOSTRoots_Nil(t *testing.T) {
	t.Parallel()

	if _, err := extractGOSTRoots(nil); !errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("nil: got %v, want ErrGOSTRootsRequired", err)
	}
}

// TestExtractGOSTRoots_EmptySlice also returns ErrGOSTRootsRequired.
func TestExtractGOSTRoots_EmptySlice(t *testing.T) {
	t.Parallel()

	if _, err := extractGOSTRoots([]*x509gost.Certificate{}); !errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("empty slice: got %v, want ErrGOSTRootsRequired", err)
	}
}

// TestExtractGOSTRoots_WrongType returns a typed error naming the bad type.
func TestExtractGOSTRoots_WrongType(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	roots := []*x509gost.Certificate{{}}

	got, err := extractGOSTRoots(roots)
	if err != nil {
		t.Fatalf("valid roots: unexpected error: %v", err)
	}

	if len(got) != 1 {
		t.Errorf("valid roots: len got %d, want 1", len(got))
	}
}

// TestExtractGOSTIntermediates_Nil yields a nil pool and no error: unlike the
// roots, intermediates are optional (a direct leaf-signed-by-root chain).
func TestExtractGOSTIntermediates_Nil(t *testing.T) {
	t.Parallel()

	got, err := extractGOSTIntermediates(nil)
	if err != nil {
		t.Fatalf("nil intermediates: unexpected error: %v", err)
	}

	if got != nil {
		t.Errorf("nil intermediates: got %v, want nil pool", got)
	}
}

// TestExtractGOSTIntermediates_WrongType errors on a non-nil value of the
// wrong concrete type.
func TestExtractGOSTIntermediates_WrongType(t *testing.T) {
	t.Parallel()

	_, err := extractGOSTIntermediates("not an intermediates list")
	if err == nil {
		t.Fatal("wrong type: expected error, got nil")
	}
}

// TestExtractGOSTIntermediates_Valid returns the slice unchanged on success.
func TestExtractGOSTIntermediates_Valid(t *testing.T) {
	t.Parallel()

	intermediates := []*x509gost.Certificate{{}, {}}

	got, err := extractGOSTIntermediates(intermediates)
	if err != nil {
		t.Fatalf("valid intermediates: unexpected error: %v", err)
	}

	if len(got) != 2 {
		t.Errorf("valid intermediates: len got %d, want 2", len(got))
	}
}
