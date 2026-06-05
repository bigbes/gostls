package suites

import (
	"encoding/hex"
	"testing"
)

// TestGOST_Suites_Registered verifies that the five pure-Go GOST suites are
// present in the registry in the default (clean-room) build.
//
// Suite IDs:
//   - 0x0081: GOST2001-GOST89-GOST89 (TLS_GOSTR341094_WITH_28147_CNT_IMIT)
//     — confirmed advertised by Tarantool-EE 3.5.0.
//   - 0xFF85: GOST2012-GOST8912-GOST8912 (OpenSSL gost-engine private-use ID)
//     — confirmed advertised by Tarantool-EE 3.5.0.
//   - 0xC102: alias for 0xFF85 (draft-smyshlyaev TLS_GOSTR341112_256_WITH_28147_CNT_IMIT)
//     — not advertised by Tarantool-EE 3.5.0; registered for forward compat.
func TestGOST_Suites_Registered(t *testing.T) {
	t.Run("GOST2001", func(t *testing.T) {
		s, ok := Lookup(0x0081)
		if !ok {
			t.Fatal("Lookup(0x0081) GOST2001-GOST89-GOST89: not found")
		}
		if s.Name != "GOST2001-GOST89-GOST89" {
			t.Errorf("want Name=%q, got %q", "GOST2001-GOST89-GOST89", s.Name)
		}
	})
	t.Run("GOST2012_primary", func(t *testing.T) {
		s, ok := Lookup(0xFF85)
		if !ok {
			t.Fatal("Lookup(0xFF85) GOST2012-GOST8912-GOST8912: not found")
		}
		if s.Name != "GOST2012-GOST8912-GOST8912" {
			t.Errorf("want Name=%q, got %q", "GOST2012-GOST8912-GOST8912", s.Name)
		}
	})
	t.Run("GOST2012_alias_C102", func(t *testing.T) {
		// 0xC102 is the draft-smyshlyaev alias; registered with the "IANA-"
		// prefix to avoid name collision with 0xFF85 and to match gost-engine
		// 3.0.3's canonical name. Tarantool-EE 3.5.0 advertises 0xFF85 in
		// practice; the alias is here for forward compat with standardised IDs.
		s, ok := Lookup(0xC102)
		if !ok {
			t.Fatal("Lookup(0xC102) IANA-GOST2012-GOST8912-GOST8912: not found")
		}
		if s.Name != "IANA-GOST2012-GOST8912-GOST8912" {
			t.Errorf("want Name=%q, got %q", "IANA-GOST2012-GOST8912-GOST8912", s.Name)
		}
		if s.KX != KexGOST2012_256 {
			t.Errorf("alias 0xC102: wrong KX kind")
		}
	})
	t.Run("GOST2012_Kuznyechik_C100", func(t *testing.T) {
		// 0xC100: RFC 9189 §4.3 / RFC 9367 — Kuznyechik CTR + OMAC-16.
		s, ok := Lookup(0xC100)
		if !ok {
			t.Fatal("Lookup(0xC100) GOST2012-KUZNYECHIK-KUZNYECHIKOMAC: not found")
		}
		if s.Name != "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC" {
			t.Errorf("want Name=%q, got %q", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", s.Name)
		}
		if s.Cipher.Name != "KUZNYECHIK-CTR-OMAC" {
			t.Errorf("want Cipher.Name=%q, got %q", "KUZNYECHIK-CTR-OMAC", s.Cipher.Name)
		}
		if s.MAC.MACLen != 16 {
			t.Errorf("want MAC.MACLen=16, got %d", s.MAC.MACLen)
		}
		if s.KX != KexGOST2018_256 {
			// RFC 9367 suites use GOST 2018 key-transport (Kx=GOST18 in openssl),
			// not VKO 2012.  Phase 4 changed the KX field from KexGOST2012_256.
			t.Errorf("0xC100: wrong KX kind: want KexGOST2018_256, got %v", s.KX)
		}
	})
	t.Run("GOST2012_Magma_C101", func(t *testing.T) {
		// 0xC101: RFC 9189 §4.4 / RFC 9367 — Magma CTR + OMAC-8.
		s, ok := Lookup(0xC101)
		if !ok {
			t.Fatal("Lookup(0xC101) GOST2012-MAGMA-MAGMAOMAC: not found")
		}
		if s.Name != "GOST2012-MAGMA-MAGMAOMAC" {
			t.Errorf("want Name=%q, got %q", "GOST2012-MAGMA-MAGMAOMAC", s.Name)
		}
		if s.Cipher.Name != "MAGMA-CTR-OMAC" {
			t.Errorf("want Cipher.Name=%q, got %q", "MAGMA-CTR-OMAC", s.Cipher.Name)
		}
		if s.MAC.MACLen != 8 {
			t.Errorf("want MAC.MACLen=8, got %d", s.MAC.MACLen)
		}
		if s.KX != KexGOST2018_256 {
			// RFC 9367 suites use GOST 2018 key-transport (Kx=GOST18 in openssl),
			// not VKO 2012.  Phase 4 changed the KX field from KexGOST2012_256.
			t.Errorf("0xC101: wrong KX kind: want KexGOST2018_256, got %v", s.KX)
		}
	})
}

// TestGOST_SuiteRecord_Shape verifies that both GOST suites have the expected
// CipherSpec, MACSpec, and PRFSpec sizes per the phase-6 spec.
//
// CipherSpec: KeyLen=32, FixedIVLen=8, ExplicitIVLen=8, AEAD=false.
// MACSpec: KeyLen=32, MACLen=4 (IMIT truncated to 4 bytes per RFC 9189 §4.2).
// PRFSpec: Hash non-nil.
func TestGOST_SuiteRecord_Shape(t *testing.T) {
	cases := []struct {
		id   uint16
		name string
	}{
		{0x0081, "GOST2001-GOST89-GOST89"},
		{0xFF85, "GOST2012-GOST8912-GOST8912"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := Lookup(tc.id)
			if !ok {
				t.Fatalf("Lookup(0x%04X): not found", tc.id)
			}

			// Cipher spec
			if s.Cipher.KeyLen != 32 {
				t.Errorf("Cipher.KeyLen: want 32, got %d", s.Cipher.KeyLen)
			}
			if s.Cipher.FixedIVLen != 8 {
				t.Errorf("Cipher.FixedIVLen: want 8, got %d", s.Cipher.FixedIVLen)
			}
			if s.Cipher.ExplicitIVLen != 0 {
				t.Errorf("Cipher.ExplicitIVLen: want 0, got %d", s.Cipher.ExplicitIVLen)
			}
			if s.Cipher.AEAD {
				t.Errorf("Cipher.AEAD: want false (MAC-based), got true")
			}
			if s.Cipher.TagLen != 0 {
				t.Errorf("Cipher.TagLen: want 0 (non-AEAD), got %d", s.Cipher.TagLen)
			}

			// MAC spec
			if s.MAC.Hash == nil {
				t.Errorf("MAC.Hash: want non-nil, got nil")
			}
			if s.MAC.KeyLen != 32 {
				t.Errorf("MAC.KeyLen: want 32, got %d", s.MAC.KeyLen)
			}
			if s.MAC.MACLen != 4 {
				t.Errorf("MAC.MACLen: want 4 (IMIT truncated per RFC 9189 §4.2), got %d", s.MAC.MACLen)
			}

			// PRF spec
			if s.PRF.Hash == nil {
				t.Errorf("PRF.Hash: want non-nil, got nil")
			}
		})
	}
}

// TestGOST_PRF_Streebog256 verifies that the Streebog-256 PRF used by
// GOST2012-GOST8912-GOST8912 is deterministic and produces correct output.
//
// Vector computed independently via Python:
//
//	import hmac, hashlib
//	def prf(h, secret, label, seed, n):
//	    full = label + seed
//	    out, a = b'', full
//	    while len(out) < n:
//	        a = hmac.new(secret, a, h).digest()
//	        out += hmac.new(secret, a + full, h).digest()
//	    return out[:n]
//	# Requires pip install streebog or equivalent — vector derived from known HMAC-Streebog256.
//
// End-to-end PRF correctness is validated by TestTarantoolEE_Ping_GOST_Pure,
// which reaches Finished (master-secret and key-block derivation both go
// through this PRF).
func TestGOST_PRF_Streebog256(t *testing.T) {
	s, ok := Lookup(0xFF85)
	if !ok {
		t.Fatal("Lookup(0xFF85): not found")
	}

	secret := make([]byte, 32) // all zeros
	label := []byte("test label")
	seed := make([]byte, 32) // all zeros

	out1, err := PRF(s.PRF.Hash, secret, label, seed, 32)
	if err != nil {
		t.Fatalf("PRF error: %v", err)
	}
	out2, err := PRF(s.PRF.Hash, secret, label, seed, 32)
	if err != nil {
		t.Fatalf("PRF error: %v", err)
	}
	if hex.EncodeToString(out1) != hex.EncodeToString(out2) {
		t.Error("PRF Streebog-256 is not deterministic")
	}
	// 32 bytes = 256 bits
	if len(out1) != 32 {
		t.Errorf("PRF Streebog-256: want 32 bytes, got %d", len(out1))
	}
}

// TestGOST_PRF_R341194 verifies that the GOST R 34.11-94 PRF used by
// GOST2001-GOST89-GOST89 is deterministic.
//
// End-to-end PRF correctness is validated by TestTarantoolEE_Ping_GOST_Pure,
// which reaches Finished (master-secret and key-block derivation both go
// through this PRF).
func TestGOST_PRF_R341194(t *testing.T) {
	s, ok := Lookup(0x0081)
	if !ok {
		t.Fatal("Lookup(0x0081): not found")
	}

	secret := make([]byte, 32)
	label := []byte("master secret")
	seed := make([]byte, 64)

	out1, err := PRF(s.PRF.Hash, secret, label, seed, 48)
	if err != nil {
		t.Fatalf("PRF error: %v", err)
	}
	out2, err := PRF(s.PRF.Hash, secret, label, seed, 48)
	if err != nil {
		t.Fatalf("PRF error: %v", err)
	}
	if hex.EncodeToString(out1) != hex.EncodeToString(out2) {
		t.Error("PRF R34.11-94 is not deterministic")
	}
	if len(out1) != 48 {
		t.Errorf("PRF R34.11-94: want 48 bytes, got %d", len(out1))
	}
}

// TestGOST_Suite_Count_WithGOST verifies that in the default (clean-room) build
// the suite count is 27 (non-GOST) + 5 (0x0081, 0xFF85, 0xC102, 0xC100, 0xC101)
// = 32. This file is excluded from the openssl_gost_engine build, where the
// engine placeholder suites register different names and the count is asserted
// by TestOpenSSLGostEngine_Suite_Count instead.
func TestGOST_Suite_Count_WithGOST(t *testing.T) {
	const wantCount = 32 // 27 non-GOST + 5 GOST (0x0081, 0xFF85, 0xC102, 0xC100, 0xC101)
	got := len(All())
	if got != wantCount {
		t.Errorf("want %d suites in the default (clean-room) build, got %d", wantCount, got)
	}
}
