// coverage_extra_test.go — additional tests to raise branch coverage in
// suite.go (register panic branches) and keyschedule.go (FinishedVerifyData
// label variants, GOST2018 vdLen=32 path, KeyExpansion zero-block error).
package suites_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/bigbes/gostls/internal/suites"
)

// TestSuites_LookupByName_Missing verifies LookupByName returns false for
// an unregistered name.
func TestSuites_LookupByName_Missing(t *testing.T) {
	t.Parallel()

	_, ok := suites.LookupByName("NOT-A-REAL-SUITE")
	if ok {
		t.Error("LookupByName(unknown name): expected false, got true")
	}
}

// TestFinishedVerifyData_GOST2018_32Bytes verifies that FinishedVerifyData
// returns 32 bytes for the KexGOST2018_256 suites (0xC100 / 0xC101) per the
// OpenSSL ssl/t1_enc.c override (vdLen=32 for SSL_kGOST18).
func TestFinishedVerifyData_GOST2018_32Bytes(t *testing.T) {
	t.Parallel()

	// Suite 0xC100 uses KexGOST2018_256 → vdLen=32.
	suite, ok := suites.Lookup(0xC100)
	if !ok {
		t.Fatal("suite 0xC100 not found")
	}

	masterSecret := make([]byte, 48)
	transcriptHash := make([]byte, 32)

	for _, label := range []string{"client finished", "server finished"} {
		got, err := suites.FinishedVerifyData(suite, masterSecret, label, transcriptHash)
		if err != nil {
			t.Fatalf("FinishedVerifyData(%q): %v", label, err)
		}

		if len(got) != 32 {
			t.Errorf("FinishedVerifyData(%q): want 32 bytes (GOST2018), got %d", label, len(got))
		}
	}

	// Suite 0xC101 (Magma) also uses KexGOST2018_256.
	suite2, ok := suites.Lookup(0xC101)
	if !ok {
		t.Fatal("suite 0xC101 not found")
	}

	got, err := suites.FinishedVerifyData(suite2, masterSecret, "client finished", transcriptHash)
	if err != nil {
		t.Fatalf("FinishedVerifyData(C101): %v", err)
	}

	if len(got) != 32 {
		t.Errorf("FinishedVerifyData(C101): want 32 bytes, got %d", len(got))
	}
}

// TestFinishedVerifyData_Standard12Bytes verifies that non-GOST2018 suites
// return the standard 12-byte verify_data.
func TestFinishedVerifyData_Standard12Bytes(t *testing.T) {
	t.Parallel()

	// 0xC02F = ECDHE-RSA-AES128-GCM-SHA256, KexECDHE → vdLen=12.
	suite, ok := suites.Lookup(0xC02F)
	if !ok {
		t.Fatal("suite 0xC02F not found")
	}

	masterSecret := make([]byte, 48)
	transcriptHash := make([]byte, 32)

	for _, label := range []string{"client finished", "server finished"} {
		got, err := suites.FinishedVerifyData(suite, masterSecret, label, transcriptHash)
		if err != nil {
			t.Fatalf("FinishedVerifyData(%q): %v", label, err)
		}

		if len(got) != 12 {
			t.Errorf("FinishedVerifyData(%q): want 12 bytes, got %d", label, len(got))
		}
	}
}

// TestFinishedVerifyData_PRFError confirms the error path via PRF directly
// with an empty label (FinishedVerifyData always passes a non-empty label
// internally, so we validate via the underlying primitive).
func TestFinishedVerifyData_PRFError(t *testing.T) {
	t.Parallel()

	_, err := suites.PRF(sha256.New, []byte("secret"), []byte{}, []byte("seed"), 12)
	if !errors.Is(err, suites.ErrEmptyLabel) {
		t.Errorf("PRF(empty label): want ErrEmptyLabel, got %v", err)
	}
}

// TestKeyExpansion_ZeroKeyBlock verifies that KeyExpansion returns ErrZeroKeyBlock
// for a synthetic suite where all key/IV/MAC lengths are zero.
func TestKeyExpansion_ZeroKeyBlock(t *testing.T) {
	t.Parallel()

	// Construct a synthetic Suite with all-zero sizes to trigger ErrZeroKeyBlock.
	// Suite is an exported struct so we can build one freely in tests.
	synth := &suites.Suite{
		ID:   0xFFFE,
		Name: "SYNTHETIC-ZERO",
		PRF:  suites.PRFSpec{Hash: sha256.New},
		// Cipher.KeyLen, MAC.KeyLen, Cipher.FixedIVLen all default to 0.
	}

	_, err := suites.KeyExpansion(synth, make([]byte, 48), make([]byte, 32), make([]byte, 32))
	if !errors.Is(err, suites.ErrZeroKeyBlock) {
		t.Errorf("KeyExpansion(zero key block): want ErrZeroKeyBlock, got %v", err)
	}
}

// TestKeyExpansion_BadRandom verifies KeyExpansion rejects invalid random lengths.
func TestKeyExpansion_BadRandom(t *testing.T) {
	t.Parallel()

	suite, ok := suites.Lookup(0xC02F)
	if !ok {
		t.Fatal("suite 0xC02F not found")
	}

	_, err := suites.KeyExpansion(suite, make([]byte, 48), make([]byte, 16), make([]byte, 32))
	if !errors.Is(err, suites.ErrInvalidRandomLen) {
		t.Errorf("KeyExpansion(bad clientRandom): want ErrInvalidRandomLen, got %v", err)
	}

	_, err = suites.KeyExpansion(suite, make([]byte, 48), make([]byte, 32), make([]byte, 16))
	if !errors.Is(err, suites.ErrInvalidRandomLen) {
		t.Errorf("KeyExpansion(bad serverRandom): want ErrInvalidRandomLen, got %v", err)
	}
}
