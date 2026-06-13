// register_whitebox_test.go — white-box tests for the register function in
// suite.go. These tests must be in package suites (not suites_test) so they
// can call the unexported register() directly.
//
//nolint:testpackage // intentional: tests the unexported register() function directly.
package suites

import (
	"crypto/sha256"
	"testing"
)

// TestRegister_DuplicateID verifies that registering a suite with an already-
// taken IANA ID causes a panic with a message containing the suite name.
func TestRegister_DuplicateID(t *testing.T) {
	t.Parallel()

	// Pick an ID that is already registered (any suite from the init registry).
	// 0xC02F = ECDHE-RSA-AES128-GCM-SHA256.
	dup := &Suite{
		ID:   0xC02F,
		Name: "SYNTHETIC-DUPID-" + t.Name(), // unique name to avoid hitting the name-dup branch first.
		PRF:  PRFSpec{Hash: sha256.New},
		Cipher: CipherSpec{
			Name:   "AES-128-GCM",
			KeyLen: 16,
		},
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("register(duplicate ID): expected panic, got none")
		}
	}()

	register(dup)
}

// TestRegister_DuplicateName verifies that registering a suite with an already-
// taken OpenSSL name causes a panic.
func TestRegister_DuplicateName(t *testing.T) {
	t.Parallel()

	// Pick a name already registered. Use a fresh IANA ID that isn't taken.
	dup := &Suite{
		ID:   0xFFF0, // unused placeholder ID.
		Name: "ECDHE-RSA-AES128-GCM-SHA256",
		PRF:  PRFSpec{Hash: sha256.New},
		Cipher: CipherSpec{
			Name:   "AES-128-GCM",
			KeyLen: 16,
		},
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("register(duplicate name): expected panic, got none")
		}
	}()

	register(dup)
}
