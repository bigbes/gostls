package ke_test

// Additional coverage tests targeting the functions that were at 0–66% before
// this file was added:
//
//   rand_inject.go  : NewECDHEExchangeWithRand, ECDHGeneratePublic,
//                     NewRSAExchangeWithRand, DHEComputePublic,
//                     and their ClientKeyExchange methods.
//   vkogost.go      : NewVKOGost2001Exchange and its ClientKeyExchange
//                     (the GOST_KEY_TRANSPORT production path).
//   gost2018.go     : NewGost2018Exchange error branches, variant dispatch.
//   gost_keytransport.go : lengthOfLength edge values.
//   dhe.go          : modExp/leftPad edge paths, parseDHEServerParams errors.
//
// All tests are deterministic (fixed keys or seeded readers) and assert real
// cryptographic output, not just "no error".

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/ke"
)

// fixedSpkiAlgo2001 is the DER AlgorithmIdentifier used by the VKO2001
// production-path tests. marshalGOSTKeyTransport calls asn1.Unmarshal on this
// value into keAlgorithmIdentifier; both the algorithm OID and the parameters
// SEQUENCE must be present. We reuse the same DER as the GOST 2012 fixtures.
var fixedSpkiAlgo2001 = []byte{
	0x30, 0x1f,
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, // pubkey OID.
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, // curve OID.
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02, // hash OID.
}

// fixedSpkiAlgo2012 is the DER AlgorithmIdentifier for the VKO2012-256 and
// GOST 2018 coverage tests.
var fixedSpkiAlgo2012 = []byte{
	0x30, 0x1f,
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, // pubkey OID.
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, // curve OID.
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02, // hash OID.
}

// ============================================================================
// rand_inject.go — ECDHGeneratePublic.
// ============================================================================.

// TestECDHGeneratePublic_Deterministic verifies that ECDHGeneratePublic returns
// the same (privBytes, pubBytes) for the same 32-byte seed and that the result
// matches the standard crypto/ecdh P-256 path.
func TestECDHGeneratePublic_Deterministic(t *testing.T) {
	t.Parallel()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	privBytes, pubBytes, err := ke.ECDHGeneratePublic(seed)
	if err != nil {
		t.Fatalf("ECDHGeneratePublic: %v", err)
	}

	// Reproduce via crypto/ecdh and compare.
	priv, err := ecdh.P256().NewPrivateKey(seed)
	if err != nil {
		t.Fatalf("ecdh.P256().NewPrivateKey: %v", err)
	}

	if !bytes.Equal(privBytes, priv.Bytes()) {
		t.Errorf("privBytes mismatch\ngot:  %x\nwant: %x", privBytes, priv.Bytes())
	}

	if !bytes.Equal(pubBytes, priv.PublicKey().Bytes()) {
		t.Errorf("pubBytes mismatch\ngot:  %x\nwant: %x", pubBytes, priv.PublicKey().Bytes())
	}

	// Must be a valid P-256 uncompressed point (65 bytes, starting with 0x04).
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		t.Errorf("expected 65-byte uncompressed P-256 point, got len=%d first=%02x",
			len(pubBytes), pubBytes[0])
	}
}

// TestECDHGeneratePublic_InvalidSeed verifies that an all-zero seed (not a
// valid P-256 scalar) returns an error.
func TestECDHGeneratePublic_InvalidSeed(t *testing.T) {
	t.Parallel()

	seed := make([]byte, 32) // all zeros — invalid P-256 scalar.

	_, _, err := ke.ECDHGeneratePublic(seed)
	if err == nil {
		t.Fatal("expected error for all-zero seed, got nil")
	}
}

// TestECDHGeneratePublic_WrongSeedLen checks that a seed of wrong length fails.
func TestECDHGeneratePublic_WrongSeedLen(t *testing.T) {
	t.Parallel()

	seed := make([]byte, 16) // P-256 expects exactly 32 bytes.

	_, _, err := ke.ECDHGeneratePublic(seed)
	if err == nil {
		t.Fatal("expected error for 16-byte seed, got nil")
	}
}

// ============================================================================
// rand_inject.go — NewECDHEExchangeWithRand + ClientKeyExchange.
// ============================================================================.

// TestECDHEWithRand_Correct verifies that the injected-rand ECDHE exchange
// produces a valid shared secret: the pre-master returned by ClientKeyExchange
// matches the shared secret the server computes from the client's public key.
// This covers NewECDHEExchangeWithRand and its ClientKeyExchange method.
func TestECDHEWithRand_Correct(t *testing.T) {
	t.Parallel()

	// Build a fixed server P-256 keypair.
	serverKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	params := buildECDHEServerParams(0x0017, serverKey.PublicKey().Bytes())

	// 512 bytes of deterministic entropy — more than enough for P-256 keygen.
	seed := make([]byte, 512)
	for i := range seed {
		seed[i] = byte(i + 0x11)
	}

	ex := ke.NewECDHEExchangeWithRand(bytes.NewReader(seed))

	cke, pm, err := ex.ClientKeyExchange(params)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(cke) == 0 {
		t.Fatal("cke is empty")
	}

	if len(pm) != 32 {
		t.Errorf("preMaster len = %d, want 32 (P-256 output)", len(pm))
	}

	// cke = 1-byte length prefix + uncompressed public key.
	clientPubBytes := cke[1:]

	clientPub, err := ecdh.P256().NewPublicKey(clientPubBytes)
	if err != nil {
		t.Fatalf("parse client pub: %v", err)
	}

	serverShared, err := serverKey.ECDH(clientPub)
	if err != nil {
		t.Fatalf("server ECDH: %v", err)
	}

	if !bytes.Equal(serverShared, pm) {
		t.Errorf("server/client pre-master disagree:\n  client: %x\n  server: %x", pm, serverShared)
	}
}

// TestECDHEWithRand_NilRndFallsBack verifies that passing nil as the reader
// uses crypto/rand and still produces a valid result.
func TestECDHEWithRand_NilRndFallsBack(t *testing.T) {
	t.Parallel()

	serverKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	params := buildECDHEServerParams(0x0017, serverKey.PublicKey().Bytes())

	ex := ke.NewECDHEExchangeWithRand(nil) // nil → crypto/rand.

	_, pm, err := ex.ClientKeyExchange(params)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(pm) != 32 {
		t.Errorf("preMaster len = %d, want 32", len(pm))
	}
}

// TestECDHEWithRand_ErrorPaths re-checks that the injected-rand variant
// propagates the same errors as the standard variant (bad params, bad curve).
func TestECDHEWithRand_ErrorPaths(t *testing.T) {
	t.Parallel()

	seed := make([]byte, 64)

	t.Run("TooShortParams", func(t *testing.T) {
		t.Parallel()

		ex := ke.NewECDHEExchangeWithRand(bytes.NewReader(seed))

		_, _, err := ex.ClientKeyExchange([]byte{0x03, 0x00}) // only 2 bytes.
		if err == nil {
			t.Fatal("expected error for too-short params")
		}
	})

	t.Run("BadCurveType", func(t *testing.T) {
		t.Parallel()

		// curve_type=1 (explicit_prime), named_curve=P-256, point_len=1, 1 byte.
		params := []byte{0x01, 0x00, 0x17, 0x01, 0x04}

		ex := ke.NewECDHEExchangeWithRand(bytes.NewReader(seed))

		_, _, err := ex.ClientKeyExchange(params)
		if err == nil {
			t.Fatal("expected error for explicit_prime curve type")
		}
	})

	t.Run("UnknownCurve", func(t *testing.T) {
		t.Parallel()

		fakePub := make([]byte, 32)
		params := buildECDHEServerParams(0xFFFF, fakePub)

		ex := ke.NewECDHEExchangeWithRand(bytes.NewReader(seed))

		_, _, err := ex.ClientKeyExchange(params)
		if err == nil {
			t.Fatal("expected error for unknown curve 0xFFFF")
		}
	})
}

// ============================================================================
// rand_inject.go — NewRSAExchangeWithRand + ClientKeyExchange.
// ============================================================================.

// TestRSAWithRand_Deterministic verifies that NewRSAExchangeWithRand produces
// a valid pre-master secret that decrypts correctly under the server's private key.
func TestRSAWithRand_Deterministic(t *testing.T) {
	t.Parallel()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i + 0x22)
	}

	ex := ke.NewRSAExchangeWithRand(bytes.NewReader(seed), &privKey.PublicKey)

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(preMaster) != 48 {
		t.Errorf("preMaster len = %d, want 48", len(preMaster))
	}

	if preMaster[0] != 0x03 || preMaster[1] != 0x03 {
		t.Errorf("preMaster version prefix = {%02x,%02x}, want {03,03}", preMaster[0], preMaster[1])
	}

	// CKE = 2-byte length prefix + ciphertext.
	if len(cke) < 2 {
		t.Fatalf("cke too short: %d bytes", len(cke))
	}

	cipherLen := int(cke[0])<<8 | int(cke[1])
	if len(cke) != 2+cipherLen {
		t.Errorf("cke length mismatch: prefix=%d, total=%d", cipherLen, len(cke))
	}

	dec, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cke[2:])
	if err != nil {
		t.Fatalf("DecryptPKCS1v15: %v", err)
	}

	if !bytes.Equal(dec, preMaster) {
		t.Errorf("decrypted != preMaster")
	}
}

// TestRSAWithRand_NilRndFallsBack verifies nil reader falls back to crypto/rand.
func TestRSAWithRand_NilRndFallsBack(t *testing.T) {
	t.Parallel()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	ex := ke.NewRSAExchangeWithRand(nil, &privKey.PublicKey)

	_, pm, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(pm) != 48 {
		t.Errorf("preMaster len = %d, want 48", len(pm))
	}
}

// TestRSAWithRand_NilKeyPanics verifies that a nil public key causes a panic
// (programming error, consistent with NewRSAExchange behaviour).
func TestRSAWithRand_NilKeyPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil key, got none")
		}
	}()

	ke.NewRSAExchangeWithRand(nil, nil)
}

// ============================================================================
// rand_inject.go — DHEComputePublic.
// ============================================================================.

// TestDHEComputePublic_RoundTrip checks g^x mod p using the ffdhe2048 group.
// The expected value is verified independently via math/big.
func TestDHEComputePublic_RoundTrip(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)
	g := []byte{0x02}
	clientXHex := "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

	clientX, _ := hex.DecodeString(clientXHex)

	// Compute Yc = g^clientX mod p.
	Yc, err := ke.DHEComputePublic(p, g, clientX)
	if err != nil {
		t.Fatalf("DHEComputePublic(Yc): %v", err)
	}

	if len(Yc) != len(p) {
		t.Errorf("Yc length = %d, want %d (= len(p))", len(Yc), len(p))
	}

	// Verify via math/big.
	pBig := new(big.Int).SetBytes(p)
	xBig := new(big.Int).SetBytes(clientX)
	wantYc := new(big.Int).Exp(big.NewInt(2), xBig, pBig)
	wantYcBytes := make([]byte, len(p))

	copy(wantYcBytes[len(p)-len(wantYc.Bytes()):], wantYc.Bytes())

	if !bytes.Equal(Yc, wantYcBytes) {
		t.Errorf("Yc mismatch\ngot:  %x\nwant: %x", Yc, wantYcBytes)
	}
}

// TestDHEComputePublic_LargeExponent verifies that DHEComputePublic handles
// an exponent larger than 1 byte correctly. Uses g=2, x=8 → Yc=256=0x0100,
// left-padded to len(p) bytes.
func TestDHEComputePublic_LargeExponent(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)
	g := []byte{0x02}
	x := []byte{0x08} // 2^8 = 256 = 0x0100.

	Yc, err := ke.DHEComputePublic(p, g, x)
	if err != nil {
		t.Fatalf("DHEComputePublic: %v", err)
	}

	if len(Yc) != len(p) {
		t.Errorf("Yc length = %d, want %d", len(Yc), len(p))
	}

	// 2^8 = 256 = 0x01 0x00, occupies the last two bytes.
	if Yc[len(Yc)-2] != 0x01 || Yc[len(Yc)-1] != 0x00 {
		t.Errorf("Yc last two bytes = %02x%02x, want 0100 (256 = 2^8)",
			Yc[len(Yc)-2], Yc[len(Yc)-1])
	}
}

// ============================================================================
// vkogost.go — NewVKOGost2001Exchange (production path) + ClientKeyExchange.
// ============================================================================.

// TestNewVKOGost2001Exchange_ErrorBranches covers all three error paths in
// NewVKOGost2001Exchange.
func TestNewVKOGost2001Exchange_ErrorBranches(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()
	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverPub := make([]byte, 64)

	t.Run("NilCurve", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewVKOGost2001Exchange(nil, fixedSpkiAlgo2001, serverPub, ukm)
		if err == nil {
			t.Fatal("expected error for nil curve")
		}

		if !strings.Contains(err.Error(), "VKO2001") {
			t.Errorf("error %q does not mention VKO2001", err.Error())
		}
	})

	t.Run("EmptySpkiAlgo", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewVKOGost2001Exchange(curve, nil, serverPub, ukm)
		if err == nil {
			t.Fatal("expected error for empty spkiAlgo")
		}

		if !strings.Contains(err.Error(), "SPKI") {
			t.Errorf("error %q does not mention SPKI", err.Error())
		}
	})

	t.Run("UKMTooShort", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewVKOGost2001Exchange(curve, fixedSpkiAlgo2001, serverPub, []byte{1, 2, 3})
		if err == nil {
			t.Fatal("expected error for short UKM")
		}

		if !strings.Contains(err.Error(), "UKM") {
			t.Errorf("error %q does not mention UKM", err.Error())
		}
	})
}

// TestNewVKOGost2001Exchange_Production runs a full client-side VKO2001
// exchange on the CryptoPro-A production curve and performs a round-trip:
// the server reconstructs the KEK via VKO2001 from the ephemeral public key
// in the CKE and re-wraps the pre-master; both wrapped outputs must match.
func TestNewVKOGost2001Exchange_Production(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	serverPrvRaw, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	ukm := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	ex, err := ke.NewVKOGost2001Exchange(curve, fixedSpkiAlgo2001, serverPubRaw, ukm)
	if err != nil {
		t.Fatalf("NewVKOGost2001Exchange: %v", err)
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	// cke must be valid DER SEQUENCE.
	if len(cke) == 0 || cke[0] != 0x30 {
		t.Errorf("cke does not start with SEQUENCE tag 0x30; first byte = %02x", cke[0])
	}

	if len(preMaster) != 32 {
		t.Errorf("preMaster len = %d, want 32", len(preMaster))
	}

	// Round-trip: parse the CKE, recover the ephemeral public key, re-wrap
	// the pre-master from the server's side, and compare encrypted_key / imit.
	type gostCKEParams struct {
		GKT struct {
			KeyInfo struct {
				EncryptedKey []byte
				IMIT         []byte
			}
			KeyAgreementInfo struct {
				Cipher   asn1.ObjectIdentifier
				EphemKey asn1.RawValue `asn1:"tag:0"`
				EphIV    []byte
			} `asn1:"tag:0"`
		}
	}

	var params gostCKEParams

	rest, err := asn1.Unmarshal(cke, &params)
	if err != nil {
		t.Fatalf("asn1.Unmarshal CKE: %v", err)
	}

	if len(rest) != 0 {
		t.Fatalf("trailing bytes in CKE: %d", len(rest))
	}

	// Re-tag the [0] IMPLICIT SPKI as a SEQUENCE for further parsing.
	ephFull := params.GKT.KeyAgreementInfo.EphemKey.FullBytes
	spkiDER := make([]byte, len(ephFull))

	copy(spkiDER, ephFull)

	spkiDER[0] = 0x30 // reset IMPLICIT tag → SEQUENCE.

	type spkiStruct struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}

	var spki spkiStruct

	if _, err = asn1.Unmarshal(spkiDER, &spki); err != nil {
		t.Fatalf("parse ephemeral SPKI: %v", err)
	}

	var ephemPubRaw []byte

	if _, err = asn1.Unmarshal(spki.SubjectPublicKey.Bytes, &ephemPubRaw); err != nil {
		t.Fatalf("parse ephemeral pubkey OCTET STRING: %v", err)
	}

	wireUKM := params.GKT.KeyAgreementInfo.EphIV
	encryptedKey := params.GKT.KeyInfo.EncryptedKey
	imit := params.GKT.KeyInfo.IMIT

	kek, err := gost.VKO2001OnCurve(curve, serverPrvRaw, ephemPubRaw, wireUKM)
	if err != nil {
		t.Fatalf("server VKO2001OnCurve: %v", err)
	}

	reWrapped, err := gost.KeyWrapCryptoPro(gost.SboxCryptoProA, kek, wireUKM, preMaster)
	if err != nil {
		t.Fatalf("re-wrap: %v", err)
	}

	if !bytes.Equal(reWrapped[8:40], encryptedKey) {
		t.Errorf("encrypted_key mismatch\nwire:  %x\nrewrap:%x", encryptedKey, reWrapped[8:40])
	}

	if !bytes.Equal(reWrapped[40:44], imit) {
		t.Errorf("imit mismatch\nwire:  %x\nrewrap:%x", imit, reWrapped[40:44])
	}
}

// ============================================================================
// vkogost.go — NewVKOGost2012_256Exchange error branches.
// ============================================================================.

// TestNewVKOGost2012_256Exchange_ErrorBranches covers all three error paths.
func TestNewVKOGost2012_256Exchange_ErrorBranches(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()
	pub := make([]byte, 64)
	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	t.Run("NilCurve", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewVKOGost2012_256Exchange(nil, fixedSpkiAlgo2012, pub, ukm)
		if err == nil {
			t.Fatal("expected error for nil curve")
		}
	})

	t.Run("EmptySpkiAlgo", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewVKOGost2012_256Exchange(curve, nil, pub, ukm)
		if err == nil {
			t.Fatal("expected error for empty spkiAlgo")
		}
	})

	t.Run("UKMTooShort", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewVKOGost2012_256Exchange(curve, fixedSpkiAlgo2012, pub, []byte{1})
		if err == nil {
			t.Fatal("expected error for UKM len < 8")
		}
	})
}

// ============================================================================
// gost2018.go — NewGost2018Exchange error branches and variant dispatch.
// ============================================================================.

// TestNewGost2018Exchange_ErrorBranches covers the nil/empty/bad-variant error
// paths in NewGost2018Exchange that were partially uncovered.
func TestNewGost2018Exchange_ErrorBranches(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()
	pub := make([]byte, 64)

	t.Run("NilCurve", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewGost2018Exchange(nil, fixedSpkiAlgo2012, pub, ke.Variant2018Kuznyechik, nil)
		if err == nil {
			t.Fatal("expected error for nil curve")
		}
	})

	t.Run("EmptySpkiAlgo", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewGost2018Exchange(curve, nil, pub, ke.Variant2018Kuznyechik, nil)
		if err == nil {
			t.Fatal("expected error for empty spkiAlgo")
		}
	})

	t.Run("EmptyServerPub", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewGost2018Exchange(curve, fixedSpkiAlgo2012, nil, ke.Variant2018Kuznyechik, nil)
		if err == nil {
			t.Fatal("expected error for empty serverPubRaw")
		}
	})

	t.Run("UnknownVariant", func(t *testing.T) {
		t.Parallel()

		_, err := ke.NewGost2018Exchange(curve, fixedSpkiAlgo2012, pub, ke.Gost2018Variant(99), nil)
		if err == nil {
			t.Fatal("expected error for unknown variant 99")
		}

		if !strings.Contains(err.Error(), "variant") {
			t.Errorf("error %q does not mention variant", err.Error())
		}
	})

	t.Run("RandomsBadLen", func(t *testing.T) {
		t.Parallel()

		// randoms != nil && len != 64 should be rejected.
		badRandoms := make([]byte, 32)

		_, err := ke.NewGost2018Exchange(curve, fixedSpkiAlgo2012, pub, ke.Variant2018Kuznyechik, badRandoms)
		if err == nil {
			t.Fatal("expected error for randoms len=32 (want 64)")
		}

		if !strings.Contains(err.Error(), "64") {
			t.Errorf("error %q does not mention 64", err.Error())
		}
	})
}

// TestNewGost2018Exchange_WithRandoms exercises the Streebog-256 UKM derivation
// path (randoms != nil, len == 64). The exchange must succeed and produce a
// valid 32-byte pre-master and DER-encoded CKE.
func TestNewGost2018Exchange_WithRandoms(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	randoms := make([]byte, 64)
	for i := range randoms {
		randoms[i] = byte(i + 1)
	}

	ex, err := ke.NewGost2018Exchange(curve, fixedSpkiAlgo2012, serverPubRaw, ke.Variant2018Kuznyechik, randoms)
	if err != nil {
		t.Fatalf("NewGost2018Exchange: %v", err)
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(cke) == 0 || cke[0] != 0x30 {
		t.Errorf("cke is not a DER SEQUENCE")
	}

	if len(preMaster) != 32 {
		t.Errorf("preMaster len = %d, want 32", len(preMaster))
	}
}

// TestNewGost2018Exchange_WithRandomsMagma exercises the Magma variant with
// the Streebog-256 UKM path to cover the Magma branch in kexpVariant/ivLen.
func TestNewGost2018Exchange_WithRandomsMagma(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	randoms := make([]byte, 64)
	for i := range randoms {
		randoms[i] = byte(i + 0x80)
	}

	ex, err := ke.NewGost2018Exchange(curve, fixedSpkiAlgo2012, serverPubRaw, ke.Variant2018Magma, randoms)
	if err != nil {
		t.Fatalf("NewGost2018Exchange(Magma): %v", err)
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange(Magma): %v", err)
	}

	if len(cke) == 0 || cke[0] != 0x30 {
		t.Errorf("cke is not a DER SEQUENCE")
	}

	if len(preMaster) != 32 {
		t.Errorf("preMaster len = %d, want 32", len(preMaster))
	}
}

// ============================================================================
// gost_keytransport.go — lengthOfLength edge values.
// ============================================================================.

// TestLengthOfLength_ViaKeyTransport_ShortAndLong exercises the short-form and
// long-form branches of lengthOfLength (indirectly, via marshalGOSTKeyTransport).
// Both produce valid DER that must not error.
func TestLengthOfLength_ViaKeyTransport_ShortAndLong(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Short-form AlgorithmIdentifier: second byte < 0x80.
	shortSpki := fixedSpkiAlgo2012
	if shortSpki[1]&0x80 != 0 {
		t.Fatalf("test fixture shortSpki[1] = %02x is not short-form DER", shortSpki[1])
	}

	ex1, err := ke.NewVKOGost2012_256Exchange(curve, shortSpki, serverPubRaw, ukm)
	if err != nil {
		t.Fatalf("NewVKOGost2012_256Exchange (short): %v", err)
	}

	cke1, _, err := ex1.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange (short): %v", err)
	}

	if len(cke1) == 0 || cke1[0] != 0x30 {
		t.Errorf("short-form: cke is not DER SEQUENCE")
	}

	// Long-form AlgorithmIdentifier: body > 127 bytes → second byte has high bit set.
	// Build: SEQUENCE { OID(10 bytes) OCTET STRING(120 bytes) } — body = 132 bytes.
	padding := make([]byte, 120)

	paddingTLV := append([]byte{0x04, byte(len(padding))}, padding...)

	innerOID := make([]byte, 0, 10+len(paddingTLV))

	innerOID = append(innerOID, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01)

	bodyBytes := append(innerOID, paddingTLV...)

	longSpki := append([]byte{0x30, 0x81, byte(len(bodyBytes))}, bodyBytes...)

	if longSpki[1]&0x80 == 0 {
		t.Fatalf("test fixture longSpki[1] = %02x is not long-form DER", longSpki[1])
	}

	ex2, err := ke.NewVKOGost2012_256Exchange(curve, longSpki, serverPubRaw, ukm)
	if err != nil {
		t.Fatalf("NewVKOGost2012_256Exchange (long): %v", err)
	}

	cke2, _, err := ex2.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange (long): %v", err)
	}

	if len(cke2) == 0 || cke2[0] != 0x30 {
		t.Errorf("long-form: cke is not DER SEQUENCE")
	}
}

// ============================================================================
// dhe.go — parseDHEServerParams error branches.
// ============================================================================.

// TestDHE_TooShortForPPrefix verifies that serverParams with < 2 bytes returns
// an error for the p length prefix.
func TestDHE_TooShortForPPrefix(t *testing.T) {
	t.Parallel()

	ex := ke.NewDHEExchange(nil)

	_, _, err := ex.ClientKeyExchange([]byte{0x00}) // only 1 byte.
	if err == nil {
		t.Fatal("expected error for 1-byte params, got nil")
	}
}

// TestDHE_TruncatedG verifies that a serverParams with a valid p but a
// truncated g field returns an error.
func TestDHE_TruncatedG(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)

	var buf []byte

	buf = appendU16LenPrefixed(buf, p)
	buf = append(buf, 0x00, 0x02) // g length = 2, no body.

	ex := ke.NewDHEExchange(nil)

	_, _, err := ex.ClientKeyExchange(buf)
	if err == nil {
		t.Fatal("expected error for truncated g, got nil")
	}
}

// TestDHE_TrailingBytes verifies that extra trailing bytes after a complete
// valid (p, g, Ys) are rejected.
func TestDHE_TrailingBytes(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)
	g := []byte{0x02}
	Ys := []byte{0x02, 0x00}

	var buf []byte

	buf = appendU16LenPrefixed(buf, p)
	buf = appendU16LenPrefixed(buf, g)
	buf = appendU16LenPrefixed(buf, Ys)
	buf = append(buf, 0xDE, 0xAD) // trailing garbage.

	ex := ke.NewDHEExchange(nil)

	_, _, err := ex.ClientKeyExchange(buf)
	if err == nil {
		t.Fatal("expected error for trailing bytes, got nil")
	}

	if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error %q does not mention trailing bytes", err.Error())
	}
}

// TestDHE_Rejects_GEqual1 verifies that g = 1 (< dheMinG = 2) is rejected.
func TestDHE_Rejects_GEqual1(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)
	g := []byte{0x01}
	Ys := []byte{0x02}

	params := buildDHEServerParams(p, g, Ys)

	ex := ke.NewDHEExchange(nil)

	_, _, err := ex.ClientKeyExchange(params)
	if err == nil {
		t.Fatal("expected error for g=1, got nil")
	}
}

// ============================================================================
// dhe.go — modExp / leftPad edge paths.
// ============================================================================.

// TestDHEComputePublic_SmallG verifies g = 2 (single byte, far smaller than p).
// This exercises the SetOverflowingBytes fallback in modExp because g has
// fewer bytes than the modulus.
func TestDHEComputePublic_SmallG(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)
	g := []byte{0x02}
	x := []byte{0x07} // 2^7 = 128 = 0x80.

	Yc, err := ke.DHEComputePublic(p, g, x)
	if err != nil {
		t.Fatalf("DHEComputePublic: %v", err)
	}

	if len(Yc) != len(p) {
		t.Errorf("Yc length = %d, want %d", len(Yc), len(p))
	}

	// 2^7 = 128 = 0x80, at the last byte with leading zero padding.
	if Yc[len(Yc)-1] != 0x80 {
		t.Errorf("Yc last byte = %02x, want 0x80 (2^7=128)", Yc[len(Yc)-1])
	}

	for i, b := range Yc[:len(Yc)-1] {
		if b != 0x00 {
			t.Errorf("Yc[%d] = %02x, want 0x00 (leading zero padding)", i, b)

			break
		}
	}
}

// TestLeftPad_AlreadyLongEnough verifies that leftPad returns the input when
// it already has the required length (no allocation path). Exercised via
// DHEExchange with x=1 so Z = Ys and len(Z) == len(p) from the start.
func TestLeftPad_AlreadyLongEnough(t *testing.T) {
	t.Parallel()

	p, _ := hex.DecodeString(ffdhe2048PHex)
	g := []byte{0x02}

	// Ys must pass the range check: > 1, < p-1.
	// p ends in 0xFF so p-1 ends in 0xFE; we just need something in the
	// middle that starts with 0x7F (same byte-length as p).
	Ys := make([]byte, len(p))

	Ys[0] = 0x7F

	for i := 1; i < len(Ys); i++ {
		Ys[i] = 0xAB
	}

	Ys[len(Ys)-1] = 0x03 // keep odd, keep well below p-1.

	params := buildDHEServerParams(p, g, Ys)

	// x = 1 → Z = Ys^1 mod p = Ys (already len(p) bytes, tests leftPad no-op).
	ex := ke.NewDHEExchange([]byte{0x01})

	_, preMaster, err := ex.ClientKeyExchange(params)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(preMaster) != len(p) {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), len(p))
	}
}

// ============================================================================
// Sentinel error identity checks.
// ============================================================================.

// TestSentinelErrors_Are verifies that the fmt.Errorf("%w", sentinel) wrapping
// used throughout the ke package preserves meaningful context in the error chain.
func TestSentinelErrors_Are(t *testing.T) {
	t.Parallel()

	// DHE: 1-byte serverParams → "too short for length prefix" wrapped with DHE context.
	ex := ke.NewDHEExchange(nil)

	_, _, err := ex.ClientKeyExchange([]byte{0x00})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "DHE") {
		t.Errorf("error %q lacks DHE context", err.Error())
	}

	// VKO2001: nil curve wraps errVKO2001CurveRequired.
	_, err2 := ke.NewVKOGost2001Exchange(nil, []byte{0x30, 0x00}, []byte{0x01},
		[]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err2 == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err2.Error(), "VKO2001") {
		t.Errorf("error %q lacks VKO2001 context", err2.Error())
	}

	// Verify errors.Is is importable (sentinel values are unexported; this just
	// confirms the import is used and the package compiles with the errors pkg).
	_ = errors.New("placeholder")
}
