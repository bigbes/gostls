package suites_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bigbes/gostls/internal/suites"
)

// ---- registry tests ---------------------------------------------------------.

// TestSuites_All_DeterministicOrder verifies that All() returns a stable order
// across calls. Ranging over the registry map (the previous implementation)
// randomized the order per call, which silently discarded the client's
// preference expression in the default ClientHello and made the wire output
// non-reproducible.
func TestSuites_All_DeterministicOrder(t *testing.T) {
	t.Parallel()

	first := suites.All()

	for iter := range 50 {
		got := suites.All()
		if len(got) != len(first) {
			t.Fatalf("iter %d: length changed: got %d, want %d", iter, len(got), len(first))
		}

		for i := range got {
			if got[i].ID != first[i].ID {
				t.Fatalf("iter %d: order changed at index %d: got 0x%04x, want 0x%04x",
					iter, i, got[i].ID, first[i].ID)
			}
		}
	}

	// The returned slice must be a copy: mutating it must not affect later calls.
	first[0] = nil

	if suites.All()[0] == nil {
		t.Fatal("All() returned a slice aliasing internal state; mutation leaked")
	}
}

// TestSuites_AllIDsUnique verifies that no two registered suites share an IANA ID.
func TestSuites_AllIDsUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[uint16]string)
	for _, s := range suites.All() {
		if prev, dup := seen[s.ID]; dup {
			t.Errorf("duplicate ID 0x%04X: %q and %q", s.ID, prev, s.Name)
		}

		seen[s.ID] = s.Name
	}
}

// TestSuites_AllNamesUnique verifies that no two registered suites share an OpenSSL name.
func TestSuites_AllNamesUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]uint16)
	for _, s := range suites.All() {
		if prevID, dup := seen[s.Name]; dup {
			t.Errorf("duplicate name %q: IDs 0x%04X and 0x%04X", s.Name, prevID, s.ID)
		}

		seen[s.Name] = s.ID
	}
}

// TestSuites_Count asserts the total registered suite count and the cross-backend
// invariant: exactly one of the two GOST backends is active at a time.
//
// GOST is always compiled in now (clean-room backend by default), so every
// build registers 27 non-GOST suites plus 5 GOST suites = 32:
//   - default / -tags openssl: the 5 pure-Go GOST suites (gost_suites.go).
//   - -tags "openssl openssl_gost_engine": the 5 GOST engine placeholder
//     suites (gost_suites_openssl_engine.go); the pure-Go ones are suppressed.
//
// Either way the count is 32.
// Cross-backend invariant: IsGOSTBuild() XOR IsOpenSSLGostEngineBuild() must hold,
// i.e. exactly one backend is active.
func TestSuites_Count(t *testing.T) {
	t.Parallel()

	const wantCount = 32 // 27 non-GOST + 5 GOST.

	got := len(suites.All())

	if got != wantCount {
		t.Errorf("want %d suites, got %d", wantCount, got)
	}

	// Cross-backend invariant: exactly one GOST backend active.
	if suites.IsGOSTBuild() == suites.IsOpenSSLGostEngineBuild() {
		t.Errorf(
			"cross-backend invariant violated: IsGOSTBuild=%v IsOpenSSLGostEngineBuild=%v — exactly one must be true",
			suites.IsGOSTBuild(), suites.IsOpenSSLGostEngineBuild(),
		)
	}
}

// TestSuites_Lookup verifies round-trip lookup for representative suites:
// one ECDHE-GCM, one DHE-CBC, one RSA-kx-CBC.
func TestSuites_Lookup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id   uint16
		name string
		kx   suites.KexKind
		auth suites.AuthKind
	}{
		// ECDHE-GCM representative.
		{0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", suites.KexECDHE, suites.AuthECDSA},
		// DHE-CBC representative.
		{0x006B, "DHE-RSA-AES256-SHA256", suites.KexDHE, suites.AuthRSA},
		// RSA-kx-CBC representative.
		{0x002F, "AES128-SHA", suites.KexRSA, suites.AuthRSA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, ok := suites.Lookup(tc.id)
			if !ok {
				t.Fatalf("Lookup(0x%04X) returned not found", tc.id)
			}

			if s.ID != tc.id {
				t.Errorf("ID: got 0x%04X, want 0x%04X", s.ID, tc.id)
			}

			if s.Name != tc.name {
				t.Errorf("Name: got %q, want %q", s.Name, tc.name)
			}

			if s.KX != tc.kx {
				t.Errorf("KX: got %v, want %v", s.KX, tc.kx)
			}

			if s.Auth != tc.auth {
				t.Errorf("Auth: got %v, want %v", s.Auth, tc.auth)
			}

			// Also verify LookupByName is consistent.
			s2, ok2 := suites.LookupByName(tc.name)
			if !ok2 {
				t.Fatalf("LookupByName(%q) returned not found", tc.name)
			}

			if s2 != s {
				t.Errorf("LookupByName returned different pointer than Lookup")
			}
		})
	}
}

// TestSuites_Lookup_Missing verifies that Lookup returns false for unknown IDs.
func TestSuites_Lookup_Missing(t *testing.T) {
	t.Parallel()

	_, ok := suites.Lookup(0x0000)
	if ok {
		t.Error("Lookup(0x0000) should return false for unregistered suite")
	}
}

// TestSuites_AEADMetadata spot-checks that AEAD suites have zero MAC fields
// and non-AEAD suites have non-zero MAC fields.
func TestSuites_AEADMetadata(t *testing.T) {
	t.Parallel()

	for _, s := range suites.All() {
		if s.Cipher.AEAD {
			checkAEADSuite(t, s)
		} else {
			checkMACBasedSuite(t, s)
		}

		// Every suite must have a PRF hash.
		if s.PRF.Hash == nil {
			t.Errorf("suite %q: PRF.Hash == nil", s.Name)
		}

		// Every suite must have a non-zero encryption key length.
		if s.Cipher.KeyLen == 0 {
			t.Errorf("suite %q: Cipher.KeyLen = 0", s.Name)
		}
	}
}

func checkAEADSuite(t *testing.T, s *suites.Suite) {
	t.Helper()

	if s.MAC.Hash != nil {
		t.Errorf("suite %q: AEAD but MAC.Hash != nil", s.Name)
	}

	if s.MAC.KeyLen != 0 {
		t.Errorf("suite %q: AEAD but MAC.KeyLen = %d", s.Name, s.MAC.KeyLen)
	}

	if s.Cipher.TagLen == 0 {
		t.Errorf("suite %q: AEAD but TagLen = 0", s.Name)
	}
}

func checkMACBasedSuite(t *testing.T, s *suites.Suite) {
	t.Helper()

	// Kuznyechik-OMAC / Magma-OMAC are block-cipher MACs, not hashes;
	// the record protector uses the block cipher directly, so MAC.Hash
	// is nil by design for these suites.
	blockCipherMAC := s.ID == 0xC100 || s.ID == 0xC101
	if s.MAC.Hash == nil && !blockCipherMAC {
		t.Errorf("suite %q: non-AEAD but MAC.Hash == nil", s.Name)
	}

	if s.MAC.KeyLen == 0 {
		t.Errorf("suite %q: non-AEAD but MAC.KeyLen = 0", s.Name)
	}
}

// ---- PRF tests --------------------------------------------------------------.

// mustHex decodes a hex string or panics. Only used in test initialization.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustHex: " + err.Error())
	}

	return b
}

// TestPRF_RFC_Vectors tests PRF output against vectors computed using Python's
// hmac module (an independent HMAC implementation). Vectors were derived with:
//
//	python3 -c "
//	import hmac, hashlib
//	def prf(h, secret, label, seed, n):
//	    full = label + seed
//	    out, a = b'', full
//	    while len(out) < n:
//	        a = hmac.new(secret, a, h).digest()
//	        out += hmac.new(secret, a + full, h).digest()
//	    return out[:n]
//	"
//
// These vectors verify PRF correctness and catch regressions. They do not
// replace the RFC 5246 compliance check in Phase 10 (OpenSSL cross-check).
func TestPRF_RFC_Vectors(t *testing.T) {
	t.Parallel()

	t.Run("SHA-256/100bytes", func(t *testing.T) {
		t.Parallel()

		// Derived via Python hmac.new(secret, ..., hashlib.sha256).
		secret := mustHex("9bbe436ba940f017b17652849a71db35")
		label := []byte("test label")
		seed := mustHex("a0ba9f936cda311827a6f796ffd5198c")
		// 100-byte SHA-256 PRF vector (see function doc for derivation).
		want := mustHex(
			"e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9" +
				"a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa4" +
				"8082d122ee42c5a72e5a5110fff70187347b66",
		)

		got, err := suites.PRF(sha256.New, secret, label, seed, 100)
		if err != nil {
			t.Fatalf("PRF error: %v", err)
		}

		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("SHA-256 PRF mismatch\n got: %x\nwant: %x", got, want)
		}
	})

	t.Run("SHA-384/148bytes", func(t *testing.T) {
		t.Parallel()

		// Derived via Python hmac.new(secret, ..., hashlib.sha384).
		secret := mustHex("b80b733d6ceefcdc71566ea48e5567df")
		label := []byte("test label")
		seed := mustHex("cd665cf6a8447dd6ff8b27555edb7465")
		// 148-byte SHA-384 PRF vector (see function doc for derivation).
		want := mustHex(
			"7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34" +
				"f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d" +
				"416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236" +
				"a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f",
		)

		got, err := suites.PRF(sha512.New384, secret, label, seed, 148)
		if err != nil {
			t.Fatalf("PRF error: %v", err)
		}

		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("SHA-384 PRF mismatch\n got: %x\nwant: %x", got, want)
		}
	})
}

// TestPRF_EmptyLabel verifies that PRF returns ErrEmptyLabel for an empty label.
func TestPRF_EmptyLabel(t *testing.T) {
	t.Parallel()

	_, err := suites.PRF(sha256.New, []byte("secret"), []byte{}, []byte("seed"), 16)
	if !errors.Is(err, suites.ErrEmptyLabel) {
		t.Errorf("want ErrEmptyLabel, got %v", err)
	}
}

// TestPRF_ZeroLength verifies that PRF returns ErrZeroLength when outLen == 0.
func TestPRF_ZeroLength(t *testing.T) {
	t.Parallel()

	_, err := suites.PRF(sha256.New, []byte("secret"), []byte("label"), []byte("seed"), 0)
	if !errors.Is(err, suites.ErrZeroLength) {
		t.Errorf("want ErrZeroLength, got %v", err)
	}
}

// TestPRF_Deterministic verifies that PRF produces identical output on repeated calls.
func TestPRF_Deterministic(t *testing.T) {
	t.Parallel()

	secret := []byte("some secret material")
	label := []byte("determinism test")
	seed := []byte("seed bytes here")

	a, err := suites.PRF(sha256.New, secret, label, seed, 64)
	if err != nil {
		t.Fatalf("PRF error: %v", err)
	}

	b, err := suites.PRF(sha256.New, secret, label, seed, 64)
	if err != nil {
		t.Fatalf("PRF error: %v", err)
	}

	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Error("PRF is not deterministic: two calls with same inputs produced different output")
	}
}

// ---- key schedule tests -----------------------------------------------------.

// TestKeySchedule_MasterSecret verifies RFC 5246 §8.1 master secret derivation.
//
// Vector derived via Python:
//
//	prf(hashlib.sha256, bytes(48), b"master secret", bytes(64), 48)
//	→ 49cfaee5...4b68 (48 bytes)
func TestKeySchedule_MasterSecret(t *testing.T) {
	t.Parallel()

	suite, ok := suites.Lookup(0xC02F) // ECDHE-RSA-AES128-GCM-SHA256 (SHA-256 PRF).
	if !ok {
		t.Fatal("suite 0xC02F not found")
	}

	preMaster := make([]byte, 48)    // 48 zero bytes.
	clientRandom := make([]byte, 32) // 32 zero bytes.
	serverRandom := make([]byte, 32) // 32 zero bytes.

	// Expected: prf(sha256, zeros(48), "master secret", zeros(32)||zeros(32), 48)
	// Derived independently via Python hmac module.
	want := mustHex("49cfaee55b8692d3bb6dd6ee6b536f2f17afbc8418094763bcb5bed6b005adf888d060e48c5eb2266c73cb1a3d2d4b68")

	got, err := suites.MasterSecret(suite, preMaster, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("MasterSecret error: %v", err)
	}

	if len(got) != 48 {
		t.Fatalf("MasterSecret: want 48 bytes, got %d", len(got))
	}

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("MasterSecret mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestKeySchedule_MasterSecret_SHA384 verifies master secret derivation with SHA-384 PRF.
//
// Vector derived via Python:
//
//	prf(hashlib.sha384, bytes(48), b"master secret", bytes(64), 48)
//	→ 564743f6...9c (48 bytes)
func TestKeySchedule_MasterSecret_SHA384(t *testing.T) {
	t.Parallel()

	suite, ok := suites.Lookup(0xC02C) // ECDHE-ECDSA-AES256-GCM-SHA384 (SHA-384 PRF).
	if !ok {
		t.Fatal("suite 0xC02C not found")
	}

	preMaster := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	want := mustHex("564743f649871bb6db081be216c970f4fe8670a595f3ded1ca706da437fc22c1cf819a87b14cb2a2b888de103081b39c")

	got, err := suites.MasterSecret(suite, preMaster, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("MasterSecret error: %v", err)
	}

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("MasterSecret SHA-384 mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestKeySchedule_MasterSecret_BadRandom verifies that invalid random lengths are rejected.
func TestKeySchedule_MasterSecret_BadRandom(t *testing.T) {
	t.Parallel()

	suite, _ := suites.Lookup(0xC02F)
	_, err := suites.MasterSecret(suite, make([]byte, 48), make([]byte, 16), make([]byte, 32))

	if !errors.Is(err, suites.ErrInvalidRandomLen) {
		t.Errorf("want ErrInvalidRandomLen, got %v", err)
	}
}

// TestKeySchedule_KeyExpansion verifies RFC 5246 §6.3 key expansion for
// AES-128-CBC-SHA256: mac_key_len=32, enc_key_len=16. CBC suites take no IV from
// the key block in TLS 1.2, so the key block = 2*32 + 2*16 = 96 bytes.
//
// Vectors derived via Python (same prf function):
//
//	ms = prf(sha256, zeros(48), "master secret", zeros(64), 48)
//	kb = prf(sha256, ms, "key expansion", zeros(64), 128)  # server||client
func TestKeySchedule_KeyExpansion(t *testing.T) {
	t.Parallel()

	// AES-128-CBC-SHA256: 0xC023 = ECDHE-ECDSA-AES128-SHA256.
	suite, ok := suites.Lookup(0xC023)
	if !ok {
		t.Fatal("suite 0xC023 not found")
	}

	// Derive a master secret with all-zero inputs using SHA-256 PRF.
	masterSecret, err := suites.MasterSecret(suite, make([]byte, 48), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("MasterSecret: %v", err)
	}

	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	km, err := suites.KeyExpansion(suite, masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("KeyExpansion: %v", err)
	}

	// Verify lengths per AES-128-CBC-SHA256 spec.
	if len(km.ClientMACKey) != 32 {
		t.Errorf("ClientMACKey: want 32 bytes, got %d", len(km.ClientMACKey))
	}

	if len(km.ServerMACKey) != 32 {
		t.Errorf("ServerMACKey: want 32 bytes, got %d", len(km.ServerMACKey))
	}

	if len(km.ClientEncKey) != 16 {
		t.Errorf("ClientEncKey: want 16 bytes, got %d", len(km.ClientEncKey))
	}

	if len(km.ServerEncKey) != 16 {
		t.Errorf("ServerEncKey: want 16 bytes, got %d", len(km.ServerEncKey))
	}

	// TLS 1.2 CBC suites take NO IV from the key block (fresh per-record explicit
	// IV, RFC 5246 §6.2.3.2), so KeyExpansion must not carve IV bytes here even
	// though the suite's FixedIVLen is the 16-byte block size.
	if len(km.ClientIV) != 0 {
		t.Errorf("ClientIV: want 0 bytes for a CBC suite, got %d", len(km.ClientIV))
	}

	if len(km.ServerIV) != 0 {
		t.Errorf("ServerIV: want 0 bytes for a CBC suite, got %d", len(km.ServerIV))
	}

	// Verify specific key values derived via Python.
	// kb = prf(sha256, masterSecret, "key expansion", serverRandom||clientRandom, 128)
	// where masterSecret = prf(sha256, zeros(48), "master secret", zeros(64), 48).
	wantClientMAC := mustHex("3a236afda31f99fa44661746887e0ab61f1f783f51c4932f140d1d80b41a23f5")
	wantServerMAC := mustHex("957b91f119fec17c34a2c28c47420adc26b1ec7d9e8cb9c3f54e3977ffb3ef3e")
	wantClientEnc := mustHex("f3b742a63e5fc30407934d0ff858f22f")
	wantServerEnc := mustHex("a224ad1b8bfbfb50d6a3c33a878a1e68")

	if hex.EncodeToString(km.ClientMACKey) != hex.EncodeToString(wantClientMAC) {
		t.Errorf("ClientMACKey\n got: %x\nwant: %x", km.ClientMACKey, wantClientMAC)
	}

	if hex.EncodeToString(km.ServerMACKey) != hex.EncodeToString(wantServerMAC) {
		t.Errorf("ServerMACKey\n got: %x\nwant: %x", km.ServerMACKey, wantServerMAC)
	}

	if hex.EncodeToString(km.ClientEncKey) != hex.EncodeToString(wantClientEnc) {
		t.Errorf("ClientEncKey\n got: %x\nwant: %x", km.ClientEncKey, wantClientEnc)
	}

	if hex.EncodeToString(km.ServerEncKey) != hex.EncodeToString(wantServerEnc) {
		t.Errorf("ServerEncKey\n got: %x\nwant: %x", km.ServerEncKey, wantServerEnc)
	}
}

// TestKeySchedule_KeyExpansion_AEAD verifies key expansion for an AEAD suite
// (AES-128-GCM-SHA256) produces no MAC keys and correct IV lengths.
func TestKeySchedule_KeyExpansion_AEAD(t *testing.T) {
	t.Parallel()

	suite, ok := suites.Lookup(0xC02F) // ECDHE-RSA-AES128-GCM-SHA256.
	if !ok {
		t.Fatal("suite 0xC02F not found")
	}

	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	km, err := suites.KeyExpansion(suite, masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("KeyExpansion: %v", err)
	}

	// AEAD: no MAC keys.
	if km.ClientMACKey != nil {
		t.Errorf("AEAD suite: ClientMACKey should be nil, got %x", km.ClientMACKey)
	}

	if km.ServerMACKey != nil {
		t.Errorf("AEAD suite: ServerMACKey should be nil, got %x", km.ServerMACKey)
	}

	// AES-128: 16-byte encryption keys.
	if len(km.ClientEncKey) != 16 {
		t.Errorf("ClientEncKey: want 16, got %d", len(km.ClientEncKey))
	}

	if len(km.ServerEncKey) != 16 {
		t.Errorf("ServerEncKey: want 16, got %d", len(km.ServerEncKey))
	}

	// AES-GCM: 4-byte implicit salt.
	if len(km.ClientIV) != 4 {
		t.Errorf("ClientIV: want 4, got %d", len(km.ClientIV))
	}

	if len(km.ServerIV) != 4 {
		t.Errorf("ServerIV: want 4, got %d", len(km.ServerIV))
	}
}

// TestKeySchedule_FinishedVerifyData verifies RFC 5246 §7.4.9 Finished verify_data.
//
// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]
//
// Vectors derived via Python:
//
//	transcript_hash = sha256(b"handshake messages bytes for testing")
//	client_vd = prf(sha256, ms, b"client finished", transcript_hash, 12)
//	server_vd = prf(sha256, ms, b"server finished", transcript_hash, 12)
func TestKeySchedule_FinishedVerifyData(t *testing.T) {
	t.Parallel()

	suite, ok := suites.Lookup(0xC02F) // ECDHE-RSA-AES128-GCM-SHA256 (SHA-256 PRF).
	if !ok {
		t.Fatal("suite 0xC02F not found")
	}

	masterSecret, err := suites.MasterSecret(suite, make([]byte, 48), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("MasterSecret: %v", err)
	}

	// Transcript hash = SHA-256("handshake messages bytes for testing").
	transcriptHash := mustHex("60dbf0cc6c177fc0903aea17a01b4a474c8caa4f6af134be4b15e9333b7d89c8")

	t.Run("client finished", func(t *testing.T) {
		t.Parallel()

		want := mustHex("58166d0f5b9370200f2261d9")

		got, err := suites.FinishedVerifyData(suite, masterSecret, "client finished", transcriptHash)
		if err != nil {
			t.Fatalf("FinishedVerifyData: %v", err)
		}

		if len(got) != 12 {
			t.Fatalf("want 12 bytes, got %d", len(got))
		}

		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("client finished verify_data\n got: %x\nwant: %x", got, want)
		}
	})

	t.Run("server finished", func(t *testing.T) {
		t.Parallel()

		want := mustHex("1154ff755eb448c656409aec")

		got, err := suites.FinishedVerifyData(suite, masterSecret, "server finished", transcriptHash)
		if err != nil {
			t.Fatalf("FinishedVerifyData: %v", err)
		}

		if len(got) != 12 {
			t.Fatalf("want 12 bytes, got %d", len(got))
		}

		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("server finished verify_data\n got: %x\nwant: %x", got, want)
		}
	})
}

// TestKeySchedule_Finished_ConstantTimeEqual verifies that EqualVerifyData
// uses constant-time comparison.
//
// Constant-time guarantee: EqualVerifyData delegates to crypto/subtle.ConstantTimeCompare,
// which runs in O(n) time regardless of the position of the first differing byte.
// This test verifies the correctness of the boolean result; timing guarantees are
// provided by crypto/subtle and are not testable from pure Go.
func TestKeySchedule_Finished_ConstantTimeEqual(t *testing.T) {
	t.Parallel()

	a := []byte{0x58, 0x16, 0x6d, 0x0f, 0x5b, 0x93, 0x70, 0x20, 0x0f, 0x22, 0x61, 0xd9}
	b := []byte{0x58, 0x16, 0x6d, 0x0f, 0x5b, 0x93, 0x70, 0x20, 0x0f, 0x22, 0x61, 0xd9}
	c := []byte{0x11, 0x54, 0xff, 0x75, 0x5e, 0xb4, 0x48, 0xc6, 0x56, 0x40, 0x9a, 0xec}

	if !suites.EqualVerifyData(a, b) {
		t.Error("EqualVerifyData(a, a): want true, got false")
	}

	if suites.EqualVerifyData(a, c) {
		t.Error("EqualVerifyData(a, c): want false, got true")
	}

	// EqualVerifyData with different-length slices must return false.
	if suites.EqualVerifyData(a, a[:6]) {
		t.Error("EqualVerifyData(a, a[:6]): want false, got true")
	}
}
