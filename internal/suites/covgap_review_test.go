// covgap_review_test.go — added coverage for the TLS 1.2 PRF / key schedule
// and the GOST suite-ID registration invariant.
//
// Oracle strategy (why not the stdlib's published vectors):
//
// The task asked to lift the known-answer vectors from the Go standard
// library's crypto/tls/prf_test.go. Those published vectors
// (testKeysFromTests) are all tagged VersionTLS10 and exercise prf10 — the
// TLS 1.0/1.1 PRF, which is P_MD5 XOR P_SHA1 (RFC 2246 §5). suites.PRF
// implements the *TLS 1.2* single-hash PRF, P_hash(secret, label||seed)
// (RFC 5246 §5). The TLS 1.0 vectors therefore do NOT reproduce with
// suites.PRF, and the stdlib's TLS 1.2 PRF (crypto/internal/fips140/tls12.PRF,
// reached via prf12) is unexported and not lift-able.
//
// So the independent oracle used here is the stdlib's own reference P_hash /
// PRF *algorithm* — the code in GOROOT/src/crypto/tls/prf.go (pHash at
// prf.go:29-48, RFC 5246 §5) — reimplemented below as stdlibPHash /
// stdlibPRF12. It is a genuinely independent implementation of the same RFC:
// it reuses a single HMAC instance with Reset() and advances A(i) as a
// separate step, whereas suites' pHash allocates a fresh HMAC per call and
// builds A(i)||seed with append. A transcription bug (seed ordering, A(i)
// chaining, truncation) in either would surface as a differential mismatch.
// This is the classic differential oracle, run over randomized inputs and
// over every PRF hash the package uses (SHA-256, SHA-384, and both GOST
// hashes), rather than a single hard-coded vector.
package suites_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"math/rand"
	"testing"

	"github.com/bigbes/gostls/internal/suites"
)

// ---- independent stdlib-derived PRF oracle ----------------------------------.

// stdlibPHash is an independent reimplementation of P_hash from the Go standard
// library's crypto/tls/prf.go (RFC 5246 §5 / RFC 4346 §5). It is deliberately
// structured like the stdlib (single reused HMAC, Reset() between blocks, A(i)
// advanced as its own step) — distinct from suites' pHash — so the two serve as
// mutual cross-checks.
func stdlibPHash(result, secret, seed []byte, h func() hash.Hash) {
	hm := hmac.New(h, secret)
	hm.Write(seed)

	a := hm.Sum(nil)

	j := 0
	for j < len(result) {
		hm.Reset()
		hm.Write(a)
		hm.Write(seed)

		b := hm.Sum(nil)
		copy(result[j:], b)

		j += len(b)

		hm.Reset()
		hm.Write(a)

		a = hm.Sum(nil)
	}
}

// stdlibPRF12 is the TLS 1.2 PRF (RFC 5246 §5): P_hash(secret, label || seed),
// mirroring the stdlib prf12 seed assembly.
func stdlibPRF12(h func() hash.Hash, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	stdlibPHash(result, secret, labelAndSeed, h)

	return result
}

// ---- PRF differential vs stdlib algorithm (task items 1 + 2) ----------------.

// TestPRF_Differential_StdlibOracle cross-checks suites.PRF against the
// independent stdlib-reference TLS 1.2 PRF (stdlibPRF12) over randomized inputs
// for both PRF hashes the package uses. Deterministic: the RNG is seeded with a
// fixed constant, so the exact input set is reproducible run-to-run.
func TestPRF_Differential_StdlibOracle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		h    func() hash.Hash
	}{
		{"SHA-256", sha256.New},
		{"SHA-384", sha512.New384},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rng := rand.New(rand.NewSource(0x5eed10)) //nolint:gosec // determinism, not security.

			for iter := range 200 {
				secret := randBytes(rng, 1+rng.Intn(64))
				label := randLabel(rng)
				seed := randBytes(rng, rng.Intn(80))
				outLen := 1 + rng.Intn(200)

				got, err := suites.PRF(tc.h, secret, []byte(label), seed, outLen)
				if err != nil {
					t.Fatalf("iter %d: suites.PRF error: %v", iter, err)
				}

				want := stdlibPRF12(tc.h, secret, label, seed, outLen)

				if hex.EncodeToString(got) != hex.EncodeToString(want) {
					t.Fatalf("iter %d: PRF mismatch (%s)\n secret=%x label=%q seed=%x len=%d\n got:  %x\n want: %x",
						iter, tc.name, secret, label, seed, outLen, got, want)
				}
			}
		})
	}
}

// TestKeySchedule_Differential_StdlibOracle cross-checks suites.MasterSecret and
// suites.KeyExpansion against the stdlib-reference PRF for one AEAD suite, one
// AEAD-SHA384 suite, and one CBC suite (task item 2). The expected per-suite
// MAC/key/IV byte counts are stated independently from RFC 5246/5288 (CBC takes
// NO IV from the TLS 1.2 key block; AES-GCM takes a 4-byte fixed nonce), not
// read back from the code under test — so this validates the key-block carving
// and the master/key-expansion seed ordering.
func TestKeySchedule_Differential_StdlibOracle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id     uint16
		name   string
		h      func() hash.Hash
		macLen int
		keyLen int
		ivLen  int // key-block IV bytes: 0 for TLS 1.2 CBC, 4 for AES-GCM.
	}{
		// AEAD, SHA-256 PRF: ECDHE-RSA-AES128-GCM-SHA256.
		{0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", sha256.New, 0, 16, 4},
		// AEAD, SHA-384 PRF: ECDHE-ECDSA-AES256-GCM-SHA384.
		{0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", sha512.New384, 0, 32, 4},
		// CBC, SHA-256 PRF: ECDHE-ECDSA-AES128-SHA256 (no key-block IV in TLS 1.2).
		{0xC023, "ECDHE-ECDSA-AES128-SHA256", sha256.New, 32, 16, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			suite, ok := suites.Lookup(tc.id)
			if !ok {
				t.Fatalf("Lookup(0x%04X): not found", tc.id)
			}

			rng := rand.New(rand.NewSource(int64(tc.id))) //nolint:gosec // determinism.

			for iter := range 50 {
				preMaster := randBytes(rng, 48)
				clientRandom := randBytes(rng, 32)
				serverRandom := randBytes(rng, 32)

				// --- master secret: seed = clientRandom || serverRandom ---.
				wantMaster := stdlibPRF12(tc.h, preMaster, "master secret",
					concat(clientRandom, serverRandom), 48)

				gotMaster, err := suites.MasterSecret(suite, preMaster, clientRandom, serverRandom)
				if err != nil {
					t.Fatalf("iter %d: MasterSecret error: %v", iter, err)
				}

				if hex.EncodeToString(gotMaster) != hex.EncodeToString(wantMaster) {
					t.Fatalf("iter %d: MasterSecret mismatch\n got:  %x\n want: %x",
						iter, gotMaster, wantMaster)
				}

				// --- key expansion: seed = serverRandom || clientRandom ---.
				total := 2*tc.macLen + 2*tc.keyLen + 2*tc.ivLen
				block := stdlibPRF12(tc.h, gotMaster, "key expansion",
					concat(serverRandom, clientRandom), total)

				off := 0
				wantCMac := block[off : off+tc.macLen]

				off += tc.macLen

				wantSMac := block[off : off+tc.macLen]

				off += tc.macLen

				wantCKey := block[off : off+tc.keyLen]

				off += tc.keyLen

				wantSKey := block[off : off+tc.keyLen]

				off += tc.keyLen

				wantCIV := block[off : off+tc.ivLen]

				off += tc.ivLen

				wantSIV := block[off : off+tc.ivLen]

				km, err := suites.KeyExpansion(suite, gotMaster, clientRandom, serverRandom)
				if err != nil {
					t.Fatalf("iter %d: KeyExpansion error: %v", iter, err)
				}

				checkKeyField(t, iter, "ClientMACKey", km.ClientMACKey, wantCMac, tc.macLen)
				checkKeyField(t, iter, "ServerMACKey", km.ServerMACKey, wantSMac, tc.macLen)
				checkKeyField(t, iter, "ClientEncKey", km.ClientEncKey, wantCKey, tc.keyLen)
				checkKeyField(t, iter, "ServerEncKey", km.ServerEncKey, wantSKey, tc.keyLen)
				checkKeyField(t, iter, "ClientIV", km.ClientIV, wantCIV, tc.ivLen)
				checkKeyField(t, iter, "ServerIV", km.ServerIV, wantSIV, tc.ivLen)
			}
		})
	}
}

// checkKeyField compares a derived key-material field against the oracle. When
// the expected length is 0 (e.g. AEAD MAC keys, CBC IVs) the production field
// must be empty/nil.
func checkKeyField(t *testing.T, iter int, name string, got, want []byte, wantLen int) {
	t.Helper()

	if wantLen == 0 {
		if len(got) != 0 {
			t.Fatalf("iter %d: %s: want empty (len 0), got %x", iter, name, got)
		}

		return
	}

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("iter %d: %s mismatch\n got:  %x\n want: %x", iter, name, got, want)
	}
}

// ---- GOST PRF differential (task item 3) ------------------------------------.

// TestGOST_PRF_Differential_StdlibConstruction cross-checks the P_hash
// construction used by the GOST suites (Streebog-256-HMAC and
// GOSTR3411-94-HMAC) against the independent stdlib-reference P_hash driven by
// the same hash factory. This validates the PRF chaining/truncation over the
// GOST hash constructors; it does NOT assert a published GOST TLS-PRF KAT (see
// the deferred note in the task result: no independent published vector is
// reachable without importing gogost, which the license boundary forbids).
func TestGOST_PRF_Differential_StdlibConstruction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id   uint16
		name string
	}{
		{0x0081, "GOSTR3411-94-HMAC (GOST2001-GOST89-GOST89)"},
		{0xFF85, "Streebog-256-HMAC (GOST2012-GOST8912-GOST8912)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			suite, ok := suites.Lookup(tc.id)
			if !ok {
				t.Fatalf("Lookup(0x%04X): not found", tc.id)
			}

			if suite.PRF.Hash == nil {
				t.Fatalf("suite 0x%04X: PRF.Hash is nil", tc.id)
			}

			rng := rand.New(rand.NewSource(int64(tc.id) ^ 0x901234)) //nolint:gosec // determinism.

			for iter := range 40 {
				secret := randBytes(rng, 1+rng.Intn(48))
				label := randLabel(rng)
				seed := randBytes(rng, rng.Intn(72))
				outLen := 1 + rng.Intn(96)

				got, err := suites.PRF(suite.PRF.Hash, secret, []byte(label), seed, outLen)
				if err != nil {
					t.Fatalf("iter %d: suites.PRF error: %v", iter, err)
				}

				want := stdlibPRF12(suite.PRF.Hash, secret, label, seed, outLen)

				if hex.EncodeToString(got) != hex.EncodeToString(want) {
					t.Fatalf("iter %d: GOST PRF construction mismatch (%s)\n got:  %x\n want: %x",
						iter, tc.name, got, want)
				}
			}
		})
	}
}

// TestGOST_PRF_TypicalLengths_Deterministic exercises the exact output lengths
// the handshake requests from the GOST PRF (48-byte master secret, 12- and
// 32-byte Finished verify_data) and asserts determinism + length. Complements
// the differential test above with the real request sizes.
func TestGOST_PRF_TypicalLengths_Deterministic(t *testing.T) {
	t.Parallel()

	for _, id := range []uint16{0x0081, 0xFF85, 0xC100, 0xC101} {
		suite, ok := suites.Lookup(id)
		if !ok {
			t.Fatalf("Lookup(0x%04X): not found", id)
		}

		secret := []byte("premaster-ish material for gost prf")
		seed := []byte("client random || server random placeholder seed")

		for _, outLen := range []int{12, 32, 48} {
			a, err := suites.PRF(suite.PRF.Hash, secret, []byte("master secret"), seed, outLen)
			if err != nil {
				t.Fatalf("0x%04X len %d: PRF error: %v", id, outLen, err)
			}

			b, err := suites.PRF(suite.PRF.Hash, secret, []byte("master secret"), seed, outLen)
			if err != nil {
				t.Fatalf("0x%04X len %d: PRF error: %v", id, outLen, err)
			}

			if len(a) != outLen {
				t.Errorf("0x%04X: want %d bytes, got %d", id, outLen, len(a))
			}

			if hex.EncodeToString(a) != hex.EncodeToString(b) {
				t.Errorf("0x%04X len %d: PRF not deterministic", id, outLen)
			}
		}
	}
}

// ---- GOST suite-ID registration invariant (task item 4) ---------------------.

// TestGOSTSuiteIDs_RegisteredInDefaultBuild documents and guards that the five
// pure-Go GOST suite IANA IDs are all registered and resolvable via Lookup in
// the DEFAULT build (no -tags openssl_gost_engine).
//
// Build invariant (not directly testable from a default-build test, hence this
// note): the -tags openssl_gost_engine build MUST own these SAME five IDs via
// gost_suites_openssl_engine.go, and gost_suites.go (which registers them here)
// is excluded there by its `//go:build !openssl_gost_engine` constraint. The
// two backends are therefore mutually exclusive over this ID set —
// IsGOSTBuild() XOR IsOpenSSLGostEngineBuild() must hold, asserted below.
func TestGOSTSuiteIDs_RegisteredInDefaultBuild(t *testing.T) {
	t.Parallel()

	// The canonical pure-Go GOST suite ID set.
	gostIDs := []uint16{0x0081, 0xFF85, 0xC102, 0xC100, 0xC101}

	for _, id := range gostIDs {
		s, ok := suites.Lookup(id)
		if !ok {
			t.Errorf("Lookup(0x%04X): GOST suite not registered in default build", id)
			continue
		}

		if s.ID != id {
			t.Errorf("Lookup(0x%04X): returned suite with mismatched ID 0x%04X", id, s.ID)
		}

		if s.PRF.Hash == nil {
			t.Errorf("suite 0x%04X: PRF.Hash is nil", id)
		}
	}

	// Default build is the pure-Go clean-room GOST backend, never the engine.
	if !suites.IsGOSTBuild() {
		t.Error("default build: IsGOSTBuild() = false, want true")
	}

	if suites.IsOpenSSLGostEngineBuild() {
		t.Error("default build: IsOpenSSLGostEngineBuild() = true, want false")
	}

	// Exactly one backend owns the ID set.
	if suites.IsGOSTBuild() == suites.IsOpenSSLGostEngineBuild() {
		t.Errorf("cross-backend invariant violated: IsGOSTBuild=%v IsOpenSSLGostEngineBuild=%v",
			suites.IsGOSTBuild(), suites.IsOpenSSLGostEngineBuild())
	}
}

// ---- helpers ----------------------------------------------------------------.

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)

	_, _ = rng.Read(b)

	return b
}

// randLabel returns a non-empty label (PRF requires a non-empty label).
func randLabel(rng *rand.Rand) string {
	labels := []string{
		"master secret", "key expansion", "client finished",
		"server finished", "test label", "x",
	}

	return labels[rng.Intn(len(labels))]
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))

	out = append(out, a...)
	out = append(out, b...)

	return out
}
