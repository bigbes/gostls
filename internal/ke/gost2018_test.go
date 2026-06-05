package ke

// Tests for Gost2018Exchange.
//
// TestGost2018Exchange_PinnedRand — deterministic output for a fixed random
//   source. Expected bytes were derived by running this implementation once
//   with the same fixed seed and recording the output, then confirmed
//   reproducible across multiple runs. A companion KEXSymmetry test proves
//   that the same output round-trips correctly.
//   TODO(phase5): replace self-derived expected bytes with gost-engine oracle
//   output once a live integration test confirms the orchestration is correct.
//
// TestGost2018Exchange_KEXSymmetry — server-side unwrap verifies that the
//   pre-master secret recovered from the CKE matches what the client returned.
//   This is the primary correctness proof for the kexp15 wrap/unwrap path.

import (
	"bytes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"testing"

	gost "github.com/bigbes/gostcrypto"
)

// fixedSPKIAlgo2018 is the DER-encoded AlgorithmIdentifier for GOST R
// 34.10-2012 256-bit (OID 1.2.643.7.1.1.1.1) with
// CryptoPro-A curve (1.2.643.2.2.35.1) and Streebog-256 hash
// (1.2.643.7.1.1.2.2). Same value as fixedSpkiAlgo2012_256 in the
// pskeytransport test; declared here separately to keep the test self-contained.
var fixedSPKIAlgo2018 = []byte{
	0x30, 0x1f,
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, // pubkey OID
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, // curve OID
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02, // hash OID
}

// gost2018Unwrap is a test-only server-side key-unwrap helper. It mirrors
// pkey_gost2018_decrypt (tmp/engine/gost_ec_keyx.c) to recover the pre-master
// secret from a PSKeyTransport_gost DER blob.
//
// Algorithm:
//  1. Parse PSKeyTransport_gost DER → psexp, ephemeral SPKI, ukm.
//  2. Extract ephemeral public key bytes from SPKI BIT STRING → OCTET STRING.
//  3. KEG2012_256(curve, ephemPubRaw, serverPrivRaw, ukm) → expkeys[64].
//  4. Unkexp15: CTR-decrypt psexp[:keyLen] with expkeys[32:] / iv to recover
//     sharedKey; verify OMAC tag psexp[keyLen:] under expkeys[:32].
//
// sharedKeyLen is 32 for both Kuznyechik and Magma (pre-master is always 32 B).
func gost2018Unwrap(
	ckeDER []byte,
	serverPrivRaw []byte,
	curve *gost.Curve,
	variant Gost2018Variant,
) (preMaster []byte, err error) {
	// Step 1: parse PSKeyTransport_gost.
	type psKeyTransportParse struct {
		PsExp    []byte
		EphemKey asn1.RawValue
		UKM      []byte `asn1:"optional"`
	}
	var pkt psKeyTransportParse
	rest, err := asn1.Unmarshal(ckeDER, &pkt)
	if err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: parse PSKeyTransport_gost: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("gost2018Unwrap: trailing bytes: %d", len(rest))
	}

	ukm := pkt.UKM
	psexp := pkt.PsExp

	// Step 2: extract ephemeral public key from SPKI.
	// EphemKey is a raw SEQUENCE; we unmarshal it into keSPKI.
	var spki keSPKI
	rest2, err := asn1.Unmarshal(pkt.EphemKey.FullBytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: parse ephemeral SPKI: %w", err)
	}
	if len(rest2) != 0 {
		return nil, fmt.Errorf("gost2018Unwrap: trailing bytes in SPKI: %d", len(rest2))
	}

	// BIT STRING body is an OCTET STRING wrapping the raw key bytes.
	var ephemPubRaw []byte
	if _, err = asn1.Unmarshal(spki.SubjectPublicKey.Bytes, &ephemPubRaw); err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: parse ephemeral pubkey OCTET STRING: %w", err)
	}

	// Step 3: KEG2012_256 from server's perspective.
	expkeys, err := gost.KEG2012_256(curve, ephemPubRaw, serverPrivRaw, ukm)
	if err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: KEG2012_256: %w", err)
	}

	// Step 4: unkexp15 — reverse of gost_kexp15.
	// psexp = CTR(cipherKey, iv_full).XORKeyStream(sharedKey || mac)
	// Decrypt: CTR(cipherKey, iv_full).XORKeyStream(psexp) → sharedKey || mac
	// Then verify: OMAC(macKey, iv || sharedKey)[:macLen] == mac.

	// Determine parameters for the variant.
	type kexpP struct {
		blockSize, ivLen, macLen int
		newBlock                 func(key []byte) cipher.Block
	}
	var p kexpP
	switch variant {
	case Variant2018Kuznyechik:
		p = kexpP{
			blockSize: 16, ivLen: 8, macLen: 16,
			newBlock: func(key []byte) cipher.Block { return gost.NewKuznyechikCipher(key) },
		}
	case Variant2018Magma:
		p = kexpP{
			blockSize: 8, ivLen: 4, macLen: 8,
			newBlock: func(key []byte) cipher.Block { return gost.NewMagmaCipher(key) },
		}
	default:
		return nil, fmt.Errorf("gost2018Unwrap: unknown variant %d", variant)
	}

	cipherKey := expkeys[32:]
	macKey := expkeys[:32]

	// iv = ukm[24 : 24+ivLen], padded to blockSize.
	iv := ukm[24 : 24+p.ivLen]
	ivFull := make([]byte, p.blockSize)
	copy(ivFull, iv)

	// CTR decrypt psexp → plaintext (sharedKey || mac).
	ctrBlock := p.newBlock(cipherKey)
	ctr, err := gost.NewCTR(ctrBlock, ivFull)
	if err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: NewCTR: %w", err)
	}
	plaintext := make([]byte, len(psexp))
	ctr.XORKeyStream(plaintext, psexp)

	keyLen := len(psexp) - p.macLen
	if keyLen < 0 {
		return nil, fmt.Errorf("gost2018Unwrap: psexp too short (%d bytes)", len(psexp))
	}
	recoveredKey := plaintext[:keyLen]
	gotTag := plaintext[keyLen:]

	// Verify OMAC tag: OMAC(macKey, iv || sharedKey)[:macLen].
	macBlock := p.newBlock(macKey)
	omac, err := gost.NewOMAC(macBlock, p.macLen)
	if err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: NewOMAC: %w", err)
	}
	if _, err = omac.Write(iv); err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: OMAC.Write(iv): %w", err)
	}
	if _, err = omac.Write(recoveredKey); err != nil {
		return nil, fmt.Errorf("gost2018Unwrap: OMAC.Write(key): %w", err)
	}
	wantTag := omac.Sum(nil)

	if !bytes.Equal(gotTag, wantTag) {
		return nil, fmt.Errorf("gost2018Unwrap: OMAC tag mismatch: got %x want %x", gotTag, wantTag)
	}

	return recoveredKey, nil
}

// newTestExchangeForVariant builds a Gost2018Exchange with the rng field set to
// a deterministic seed reader. Exported only for this test file.
func newTestExchangeForVariant(
	curve *gost.Curve,
	spkiAlgo, serverPubRaw []byte,
	variant Gost2018Variant,
	rngSeed []byte,
) (*Gost2018Exchange, error) {
	ex, err := NewGost2018Exchange(curve, spkiAlgo, serverPubRaw, variant, nil)
	if err != nil {
		return nil, err
	}
	ex.rng = bytes.NewReader(rngSeed)
	return ex, nil
}

// TestGost2018Exchange_PinnedRand verifies that the exchange produces a
// deterministic (cke, preMaster) pair for a fixed RNG seed.
//
// Expected bytes were produced by running this implementation once with the
// given seed and recording the output. Stability of the output proves the
// orchestration (ukm, preMaster, ephemKeygen, KEG, kexp15, marshalPSKeyTransport)
// is deterministic and has not regressed.
//
// TODO(phase5): cross-validate against a gost-engine oracle once the live
// integration test in Phase 5 is passing.
func TestGost2018Exchange_PinnedRand(t *testing.T) {
	curve := gost.GOST2001CryptoProAParamSetCurve()

	// Fixed server keypair derived from a seeded RNG.
	serverSeed := make([]byte, 64)
	for i := range serverSeed {
		serverSeed[i] = byte(i + 0x40)
	}
	serverPrivRaw, serverPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(serverSeed))
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	// Client RNG seed: 128 bytes provides plenty of material for
	// ukm(32) + preMaster(32) + ephemPriv(32) = 96 bytes of draws.
	clientSeed := make([]byte, 128)
	for i := range clientSeed {
		clientSeed[i] = byte(i + 0x20)
	}

	ex, err := newTestExchangeForVariant(curve, fixedSPKIAlgo2018, serverPubRaw, Variant2018Kuznyechik, clientSeed)
	if err != nil {
		t.Fatalf("NewGost2018Exchange: %v", err)
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	// wantCKE and wantPreMaster were recorded on the first run with these
	// inputs and confirmed reproducible across multiple runs.
	// TODO(phase5): cross-validate against a gost-engine oracle once Phase 5
	// live integration test confirms the orchestration is correct.
	wantCKE, _ := hex.DecodeString(
		"3081bc04305fb5b30b50b75cbe8e685d4d98f632bde03e0814efa8ede425a52e636" +
			"7eae5943d77e2551f8d7171d6187e438ebaecab3066301f06082a85030701010101" +
			"301306072a85030202230106082a85030701010202034300044039f7226c4ec250aa" +
			"058869a35324a65cd1a46a0610f2a97697b16ea8cb567caac7bd74b4c404b674d0b" +
			"8abddd239d0f41e30b2ef8e5a822633676c53832543e10420202122232425262728" +
			"292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	wantPreMaster, _ := hex.DecodeString(
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")

	if !bytes.Equal(cke, wantCKE) {
		t.Errorf("cke mismatch:\n  got:  %x\n  want: %x", cke, wantCKE)
	}
	if !bytes.Equal(preMaster, wantPreMaster) {
		t.Errorf("preMaster mismatch:\n  got:  %x\n  want: %x", preMaster, wantPreMaster)
	}

	// Sanity: CKE must be valid DER (outer SEQUENCE).
	if len(cke) == 0 || cke[0] != 0x30 {
		t.Errorf("cke does not start with SEQUENCE tag 0x30: %02x...", cke[0])
	}
	// Pre-master must be 32 bytes.
	if len(preMaster) != 32 {
		t.Errorf("preMaster length = %d, want 32", len(preMaster))
	}

	// Round-trip verification: unwrap using the server's private key.
	recovered, err := gost2018Unwrap(cke, serverPrivRaw, curve, Variant2018Kuznyechik)
	if err != nil {
		t.Fatalf("gost2018Unwrap: %v", err)
	}
	if !bytes.Equal(recovered, preMaster) {
		t.Errorf("round-trip failed:\n  recovered: %x\n  original:  %x", recovered, preMaster)
	}
}

// TestGost2018Exchange_KEXSymmetry sets up a synthetic server keypair, runs
// ClientKeyExchange, then independently unwraps the CKE via gost2018Unwrap
// and asserts that the recovered pre-master secret matches the one returned
// by ClientKeyExchange.
//
// This test covers both the Kuznyechik and Magma variants.
func TestGost2018Exchange_KEXSymmetry(t *testing.T) {
	curve := gost.GOST2001CryptoProAParamSetCurve()

	// Generate a synthetic server keypair (production uses crypto/rand; here
	// we use a fixed seed to make failures reproducible).
	serverSeed := make([]byte, 64)
	for i := range serverSeed {
		serverSeed[i] = byte(i + 1)
	}
	serverPrivRaw, serverPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(serverSeed))
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	cases := []struct {
		name    string
		variant Gost2018Variant
	}{
		{"Kuznyechik", Variant2018Kuznyechik},
		{"Magma", Variant2018Magma},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ex, err := NewGost2018Exchange(curve, fixedSPKIAlgo2018, serverPubRaw, tc.variant, nil)
			if err != nil {
				t.Fatalf("NewGost2018Exchange: %v", err)
			}
			// Use crypto/rand (ex.rng == nil → defaults to rand.Reader).

			cke, preMaster, err := ex.ClientKeyExchange(nil)
			if err != nil {
				t.Fatalf("ClientKeyExchange: %v", err)
			}
			if len(preMaster) != 32 {
				t.Fatalf("preMaster length = %d, want 32", len(preMaster))
			}
			if len(cke) == 0 || cke[0] != 0x30 {
				t.Fatalf("cke does not look like DER SEQUENCE (first byte %02x)", cke[0])
			}

			recovered, err := gost2018Unwrap(cke, serverPrivRaw, curve, tc.variant)
			if err != nil {
				t.Fatalf("gost2018Unwrap: %v", err)
			}
			if !bytes.Equal(recovered, preMaster) {
				t.Errorf("KEX symmetry failed for %s:\n  recovered: %x\n  original:  %x",
					tc.name, recovered, preMaster)
			}
		})
	}
}
