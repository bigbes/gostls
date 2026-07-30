// covgap_review_test.go — deep-review coverage-gap pass for internal/ke.
//
// This file closes three review-identified gaps. It is a white-box test
// (package ke) because the GOST-2018 assertions reach unexported helpers
// (newTestExchangeForVariant, gost2018Unwrap, the PSKeyTransport parse structs)
// and the VKO envelope assertions reach the unexported ASN.1 types and cipher
// OID vars. It also reuses the white-box DHE helpers (decodeHexWB,
// appendU16FieldWB, ffdhe2048PHexWB) defined in coverage2/coverage3.
//
// Oracles (never self-derived by the code under test):
//   - GOST-2018 UKM: gost.Streebog256 primitive, whose own correctness is
//     proven by the gostcrypto-compat parity gate. The gost2018 orchestration
//     under test only *selects* it, so comparing the wire UKM against
//     Streebog256(randoms) is an independent structural oracle.
//   - DHE: math/big.Int.Exp — a completely separate modular-exponentiation
//     implementation from the filippo.io/bigmod path exercised by DHEExchange.
//
// Gaps NOT closed with a real oracle are recorded in the task's gapsDeferred,
// not faked here:
//   - A byte-for-byte GOST-2018 / kexp15 KAT would require a gost-engine or
//     gogost reference vector; none exists in gostcrypto-compat for the full
//     composite orchestration, and importing gogost into gostls violates the
//     license boundary. The strongest reachable substitute (deterministic,
//     size-checked output + independent UKM oracle + fail-closed on UKM
//     divergence) is provided instead.

//nolint:testpackage // white-box: uses unexported gost2018 helpers, ASN.1 types, and cipher OID vars.
package ke

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"testing"

	gost "github.com/bigbes/gostcrypto"
)

// ---------------------------------------------------------------------------
// GOST-2018 (RFC 9367 suites 0xC100/0xC101)
// ---------------------------------------------------------------------------.

// pskTransportParse mirrors the on-wire PSKeyTransport_gost DER produced by
// marshalPSKeyTransport (psexp, ephemeral SPKI, UKM). Same shape as the
// helper struct in gost2018_test.go; duplicated here to keep this file
// self-contained.
type pskTransportParse struct {
	PsExp    []byte
	EphemKey asn1.RawValue
	UKM      []byte `asn1:"optional"`
}

// parsePSKUKM extracts the UKM field carried on the wire in a GOST-2018 CKE.
func parsePSKUKM(t *testing.T, ckeDER []byte) []byte {
	t.Helper()

	var pkt pskTransportParse

	rest, err := asn1.Unmarshal(ckeDER, &pkt)
	if err != nil {
		t.Fatalf("parse PSKeyTransport_gost: %v", err)
	}

	if len(rest) != 0 {
		t.Fatalf("trailing bytes after PSKeyTransport_gost: %d", len(rest))
	}

	return pkt.UKM
}

// TestGost2018_UKMDerivation_StreebogOracle verifies the wire contract that,
// when the handshake supplies clientRandom||serverRandom, the CKE's UKM field
// is Streebog-256(randoms) — NOT a fresh random. The oracle is the independent
// gost.Streebog256 primitive (validated by the parity gate), so this checks the
// orchestration's UKM *selection* rather than re-deriving with the code under
// test. Also asserts determinism (fixed randoms + fixed RNG → identical CKE)
// and that the premaster round-trips through the server-side unwrap.
func TestGost2018_UKMDerivation_StreebogOracle(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	serverSeed := make([]byte, 64)
	for i := range serverSeed {
		serverSeed[i] = byte(i + 0x11)
	}

	serverPrivRaw, serverPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(serverSeed))
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	// clientRandom || serverRandom (64 bytes) — the handshake input.
	randoms := make([]byte, gost2018RandomsLen)
	for i := range randoms {
		randoms[i] = byte(i*7 + 3)
	}

	wantUKM := gost.Streebog256(randoms) // independent oracle.

	run := func() (cke, preMaster []byte) {
		ex, err := NewGost2018Exchange(curve, fixedSPKIAlgo2018, serverPubRaw, Variant2018Kuznyechik, randoms)
		if err != nil {
			t.Fatalf("NewGost2018Exchange: %v", err)
		}

		clientSeed := make([]byte, 128)
		for i := range clientSeed {
			clientSeed[i] = byte(i + 0x55)
		}

		ex.rng = bytes.NewReader(clientSeed)

		cke, preMaster, err = ex.ClientKeyExchange(nil)
		if err != nil {
			t.Fatalf("ClientKeyExchange: %v", err)
		}

		return cke, preMaster
	}

	cke, preMaster := run()

	// The wire UKM must equal Streebog-256(randoms).
	gotUKM := parsePSKUKM(t, cke)
	if !bytes.Equal(gotUKM, wantUKM) {
		t.Errorf("wire UKM mismatch\n got:  %x\n want: %x (Streebog256(randoms))", gotUKM, wantUKM)
	}

	if len(preMaster) != gost2018PreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), gost2018PreMasterLen)
	}

	// Determinism: same randoms + same RNG seed → identical output.
	cke2, preMaster2 := run()
	if !bytes.Equal(cke, cke2) {
		t.Error("CKE not deterministic for fixed randoms + fixed RNG")
	}

	if !bytes.Equal(preMaster, preMaster2) {
		t.Error("preMaster not deterministic for fixed randoms + fixed RNG")
	}

	// Server-side unwrap recovers the same premaster.
	recovered, err := gost2018Unwrap(cke, serverPrivRaw, curve, Variant2018Kuznyechik)
	if err != nil {
		t.Fatalf("gost2018Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, preMaster) {
		t.Errorf("round-trip mismatch\n recovered: %x\n original:  %x", recovered, preMaster)
	}
}

// gost2018UnwrapWithUKM is a server-side unwrap that uses an explicitly supplied
// UKM instead of the one carried on the wire. It models the real TLS 1.2 server,
// which derives UKM = Streebog256(clientRandom||serverRandom) independently and
// never trusts the wire field for key derivation. A UKM that differs from the
// one the client wrapped under must fail closed (KEG diverges → CTR keystream
// diverges → OMAC tag mismatch).
func gost2018UnwrapWithUKM(
	t *testing.T,
	ckeDER, serverPrivRaw, ukm []byte,
	curve *gost.Curve,
	variant Gost2018Variant,
) (preMaster []byte, err error) {
	t.Helper()

	var pkt pskTransportParse

	if _, err = asn1.Unmarshal(ckeDER, &pkt); err != nil {
		return nil, fmt.Errorf("parse PSKeyTransport_gost: %w", err)
	}

	psexp := pkt.PsExp

	var spki keSPKI

	if _, err = asn1.Unmarshal(pkt.EphemKey.FullBytes, &spki); err != nil {
		return nil, fmt.Errorf("parse ephemeral SPKI: %w", err)
	}

	var ephemPubRaw []byte

	if _, err = asn1.Unmarshal(spki.SubjectPublicKey.Bytes, &ephemPubRaw); err != nil {
		return nil, fmt.Errorf("parse ephemeral pubkey OCTET STRING: %w", err)
	}

	expkeys, err := gost.KEG2012_256(curve, ephemPubRaw, serverPrivRaw, ukm)
	if err != nil {
		return nil, fmt.Errorf("KEG2012_256: %w", err)
	}

	// Kuznyechik parameters (this helper is only exercised with Kuznyechik).
	if variant != Variant2018Kuznyechik {
		return nil, errors.New("gost2018UnwrapWithUKM: only Kuznyechik supported in this helper")
	}

	const (
		blockSize = 16
		ivLenK    = 8
		macLenK   = 16
	)

	cipherKey := expkeys[32:]
	macKey := expkeys[:32]

	iv := ukm[gost2018UKMIVOffset : gost2018UKMIVOffset+ivLenK]
	ivFull := make([]byte, blockSize)
	copy(ivFull, iv)

	ctr, err := gost.NewCTR(gost.NewKuznyechikCipher(cipherKey), ivFull)
	if err != nil {
		return nil, fmt.Errorf("NewCTR: %w", err)
	}

	plaintext := make([]byte, len(psexp))
	ctr.XORKeyStream(plaintext, psexp)

	keyLen := len(psexp) - macLenK
	if keyLen < 0 {
		return nil, fmt.Errorf("psexp too short (%d bytes)", len(psexp))
	}

	recoveredKey := plaintext[:keyLen]
	gotTag := plaintext[keyLen:]

	omac, err := gost.NewOMAC(gost.NewKuznyechikCipher(macKey), macLenK)
	if err != nil {
		return nil, fmt.Errorf("NewOMAC: %w", err)
	}

	if _, err = omac.Write(iv); err != nil {
		return nil, fmt.Errorf("OMAC.Write(iv): %w", err)
	}

	if _, err = omac.Write(recoveredKey); err != nil {
		return nil, fmt.Errorf("OMAC.Write(key): %w", err)
	}

	if !bytes.Equal(gotTag, omac.Sum(nil)) {
		return nil, errors.New("OMAC tag mismatch")
	}

	return recoveredKey, nil
}

// TestGost2018_FreshRandomUKM_FailsClosed verifies the safety property behind
// the fresh-random UKM fallback: a fresh-random UKM (the randoms==nil path) is
// bound into the kexp15 wrap, so a server that derives a *different* UKM cannot
// unwrap the premaster — it fails closed with an OMAC mismatch rather than
// recovering a wrong key. This is exactly why production callers must pass the
// 64-byte randoms (so both peers agree on Streebog256(randoms)).
func TestGost2018_FreshRandomUKM_FailsClosed(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	serverSeed := make([]byte, 64)
	for i := range serverSeed {
		serverSeed[i] = byte(i + 0x30)
	}

	serverPrivRaw, serverPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(serverSeed))
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	// randoms == nil → the client uses a fresh random UKM (= first 32 bytes of
	// the RNG seed here).
	ex, err := NewGost2018Exchange(curve, fixedSPKIAlgo2018, serverPubRaw, Variant2018Kuznyechik, nil)
	if err != nil {
		t.Fatalf("NewGost2018Exchange: %v", err)
	}

	clientSeed := make([]byte, 128)
	for i := range clientSeed {
		clientSeed[i] = byte(i + 0x01)
	}

	ex.rng = bytes.NewReader(clientSeed)

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	wireUKM := parsePSKUKM(t, cke)

	// Sanity: unwrapping with the client's actual (fresh-random) UKM succeeds —
	// this proves the CKE itself is well-formed, isolating the failure below to
	// UKM divergence rather than a broken message.
	recovered, err := gost2018UnwrapWithUKM(t, cke, serverPrivRaw, wireUKM, curve, Variant2018Kuznyechik)
	if err != nil {
		t.Fatalf("unwrap with wire UKM should succeed: %v", err)
	}

	if !bytes.Equal(recovered, preMaster) {
		t.Fatalf("unwrap with wire UKM recovered wrong premaster")
	}

	// The server independently derives UKM = Streebog256(clientRandom||serverRandom).
	// The fresh-random path did NOT use that, so the server's UKM differs and the
	// unwrap must fail closed.
	serverRandoms := make([]byte, gost2018RandomsLen)
	for i := range serverRandoms {
		serverRandoms[i] = byte(i*3 + 7)
	}

	serverUKM := gost.Streebog256(serverRandoms)

	if bytes.Equal(serverUKM, wireUKM) {
		t.Fatal("test setup: server-derived UKM unexpectedly equals wire UKM")
	}

	if _, err := gost2018UnwrapWithUKM(t, cke, serverPrivRaw, serverUKM, curve, Variant2018Kuznyechik); err == nil {
		t.Fatal("expected fail-closed (OMAC mismatch) when server UKM diverges, got nil error")
	}
}

// ---------------------------------------------------------------------------
// VKO2012_256 / VKO2001 envelope structure
// ---------------------------------------------------------------------------.

// TestVKO2012_256_Envelope_Structure exercises VKOGost2012_256Exchange at the
// envelope level (the existing tests only cover the VKO primitive KEK vector
// and a parties-agree round-trip). It asserts the GOST_KEY_TRANSPORT is
// well-formed DER, that the S-box cipher OID is id-tc26-gost-28147-param-Z
// (the 2012 distinguisher vs. the 2001 CryptoPro-A OID), that the wire UKM is
// the supplied 8-byte value, and that a synthetic server recovers the wrap by
// re-deriving the KEK via VKO and re-wrapping to the identical encrypted_key /
// imit (an inversion proof independent of gost-engine wire parity).
func TestVKO2012_256_Envelope_Structure(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	srvPrv := make([]byte, 32)
	for i := range srvPrv {
		srvPrv[i] = byte(i + 0x20)
	}

	srvPubRaw, err := gost.PublicKeyRawFromPrivate(curve, srvPrv)
	if err != nil {
		t.Fatalf("server pubkey: %v", err)
	}

	ukm := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	ex, err := NewVKOGost2012_256Exchange(curve, fixedSPKIAlgo2018, srvPubRaw, ukm)
	if err != nil {
		t.Fatalf("NewVKOGost2012_256Exchange: %v", err)
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(preMaster) != vkoPreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), vkoPreMasterLen)
	}

	var params gostClientKeyExchangeParams

	rest, err := asn1.Unmarshal(cke, &params)
	if err != nil {
		t.Fatalf("unmarshal GOST_CLIENT_KEY_EXCHANGE_PARAMS: %v", err)
	}

	if len(rest) != 0 {
		t.Fatalf("trailing bytes after CKE: %d", len(rest))
	}

	gkt := params.GKT

	// S-box OID must be the 2012 param-Z, distinguishing it from the 2001 path.
	if !gkt.KeyAgreementInfo.Cipher.Equal(oidTc26Gost28147ParamZ) {
		t.Errorf("cipher OID = %v, want %v (tc26 param-Z)", gkt.KeyAgreementInfo.Cipher, oidTc26Gost28147ParamZ)
	}

	if !bytes.Equal(gkt.KeyAgreementInfo.EphIV, ukm) {
		t.Errorf("wire UKM = %x, want %x", gkt.KeyAgreementInfo.EphIV, ukm)
	}

	if len(gkt.KeyInfo.EncryptedKey) != 32 {
		t.Errorf("encrypted_key len = %d, want 32", len(gkt.KeyInfo.EncryptedKey))
	}

	if len(gkt.KeyInfo.IMIT) != 4 {
		t.Errorf("imit len = %d, want 4", len(gkt.KeyInfo.IMIT))
	}

	// Server-side inversion: recover the ephemeral pubkey, re-derive the KEK,
	// and confirm re-wrapping the premaster reproduces the wire fields.
	ephBytes := gkt.KeyAgreementInfo.EphemKey.FullBytes
	spkiDER := make([]byte, len(ephBytes))
	copy(spkiDER, ephBytes)

	spkiDER[0] = 0x30 // [0] IMPLICIT → universal SEQUENCE.

	var ephemSPKI keSPKI

	if _, err := asn1.Unmarshal(spkiDER, &ephemSPKI); err != nil {
		t.Fatalf("unmarshal ephemeral SPKI: %v", err)
	}

	var ephPubRaw []byte

	if _, err := asn1.Unmarshal(ephemSPKI.SubjectPublicKey.Bytes, &ephPubRaw); err != nil {
		t.Fatalf("unmarshal ephemeral pubkey OCTET STRING: %v", err)
	}

	kek, err := gost.VKO2012_256OnCurve(curve, srvPrv, ephPubRaw, gkt.KeyAgreementInfo.EphIV)
	if err != nil {
		t.Fatalf("server VKO: %v", err)
	}

	reWrapped, err := gost.KeyWrapCryptoPro(gost.SboxTC26Z, kek, gkt.KeyAgreementInfo.EphIV, preMaster)
	if err != nil {
		t.Fatalf("re-wrap: %v", err)
	}

	if !bytes.Equal(reWrapped[cryptoProWrapEncKeyOff:cryptoProWrapEncKeyEnd], gkt.KeyInfo.EncryptedKey) {
		t.Errorf("encrypted_key not recovered\n wire:   %x\n rewrap: %x",
			gkt.KeyInfo.EncryptedKey, reWrapped[cryptoProWrapEncKeyOff:cryptoProWrapEncKeyEnd])
	}

	if !bytes.Equal(reWrapped[cryptoProWrapEncKeyEnd:cryptoProWrapIMITEnd], gkt.KeyInfo.IMIT) {
		t.Errorf("imit not recovered\n wire:   %x\n rewrap: %x",
			gkt.KeyInfo.IMIT, reWrapped[cryptoProWrapEncKeyEnd:cryptoProWrapIMITEnd])
	}
}

// TestVKO2001_Envelope_UsesCryptoProAOID locks in the S-box distinction on the
// other side: the VKO2001 suite must carry the CryptoPro-A cipher OID, not the
// 2012 param-Z OID. Guards against the two envelope builders being swapped.
func TestVKO2001_Envelope_UsesCryptoProAOID(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	srvPrv := make([]byte, 32)
	for i := range srvPrv {
		srvPrv[i] = byte(i + 0x05)
	}

	srvPubRaw, err := gost.PublicKeyRawFromPrivate(curve, srvPrv)
	if err != nil {
		t.Fatalf("server pubkey: %v", err)
	}

	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	ex, err := NewVKOGost2001Exchange(curve, fixedSPKIAlgo2018, srvPubRaw, ukm)
	if err != nil {
		t.Fatalf("NewVKOGost2001Exchange: %v", err)
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(preMaster) != vkoPreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), vkoPreMasterLen)
	}

	var params gostClientKeyExchangeParams

	if _, err := asn1.Unmarshal(cke, &params); err != nil {
		t.Fatalf("unmarshal CKE: %v", err)
	}

	if !params.GKT.KeyAgreementInfo.Cipher.Equal(oidGost28147CryptoProA) {
		t.Errorf("cipher OID = %v, want %v (CryptoPro-A)",
			params.GKT.KeyAgreementInfo.Cipher, oidGost28147CryptoProA)
	}

	if params.GKT.KeyAgreementInfo.Cipher.Equal(oidTc26Gost28147ParamZ) {
		t.Error("VKO2001 envelope must NOT carry the 2012 tc26 param-Z OID")
	}
}

// ---------------------------------------------------------------------------
// DHE — non-ffdhe prime acceptance and leading-zero premaster preservation
// ---------------------------------------------------------------------------.

// rfc3526Group14PHex is the RFC 3526 §3 2048-bit MODP group (id 14) prime. It
// is a published, independent 2048-bit safe prime that is distinct from the
// RFC 7919 ffdhe2048/ffdhe3072 groups the client advertises. Used to document
// that DHEExchange enforces only a bit-length floor and oddness — it has NO
// ffdhe allowlist, so a well-formed non-ffdhe 2048-bit prime is ACCEPTED.
const rfc3526Group14PHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

// leftPadBig renders a big.Int as fixed-length big-endian bytes (independent of
// the code under test's leftPad).
func leftPadBig(z *big.Int, n int) []byte {
	out := make([]byte, n)
	z.FillBytes(out)

	return out
}

// TestDHE_NonFFDHEPrime_Accepted verifies two facts at once:
//   - A well-formed 2048-bit odd prime that is NOT an RFC 7919 ffdhe group
//     (here RFC 3526 group 14) is ACCEPTED — there is no ffdhe allowlist.
//   - The resulting premaster equals Z = Ys^x mod p computed by an INDEPENDENT
//     oracle (math/big.Int.Exp), so acceptance also implies correct arithmetic.
func TestDHE_NonFFDHEPrime_Accepted(t *testing.T) {
	t.Parallel()

	p := decodeHexWB(rfc3526Group14PHex)
	if len(p) != 256 {
		t.Fatalf("RFC 3526 group 14 prime length = %d bytes, want 256", len(p))
	}

	// Confirm this prime is genuinely different from the advertised ffdhe2048.
	if bytes.Equal(p, decodeHexWB(ffdhe2048PHexWB)) {
		t.Fatal("test setup: RFC 3526 group 14 must differ from ffdhe2048")
	}

	pBig := new(big.Int).SetBytes(p)
	g := big.NewInt(2)

	// Fixed private exponents (big-endian bytes fed to DHEExchange).
	clientXBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x12, 0x34}
	serverXBytes := []byte{0xca, 0xfe, 0xba, 0xbe, 0x56, 0x78}

	clientX := new(big.Int).SetBytes(clientXBytes)
	serverX := new(big.Int).SetBytes(serverXBytes)

	// Independent oracle (math/big): Ys = g^serverX mod p, Z = Ys^clientX mod p.
	Ys := new(big.Int).Exp(g, serverX, pBig)
	wantZ := leftPadBig(new(big.Int).Exp(Ys, clientX, pBig), len(p))

	var params []byte

	params = appendU16FieldWB(params, p)
	params = appendU16FieldWB(params, g.Bytes())
	params = appendU16FieldWB(params, Ys.Bytes())

	ex := NewDHEExchange(clientXBytes)

	_, preMaster, err := ex.ClientKeyExchange(params)
	if err != nil {
		t.Fatalf("non-ffdhe 2048-bit prime should be accepted, got error: %v", err)
	}

	if len(preMaster) != len(p) {
		t.Errorf("preMaster len = %d, want %d (= len(p))", len(preMaster), len(p))
	}

	if !bytes.Equal(preMaster, wantZ) {
		t.Errorf("premaster mismatch vs math/big oracle\n got:  %x\n want: %x", preMaster, wantZ)
	}
}

// TestDHE_LeadingZeroZ_Preserved verifies RFC 5246 §8.1.2 fixed-width padding:
// when the shared secret Z is numerically short enough to have a leading zero
// byte, the premaster is still exactly len(p) bytes with the leading 0x00
// preserved (modern TLS 1.2 behavior — NOT stripped). serverX below was found
// offline (deterministic search) as the smallest exponent for which Z has a
// leading zero byte under the fixed clientX; the expected value is recomputed
// here with the independent math/big oracle.
func TestDHE_LeadingZeroZ_Preserved(t *testing.T) {
	t.Parallel()

	p := decodeHexWB(rfc3526Group14PHex)
	pBig := new(big.Int).SetBytes(p)
	g := big.NewInt(2)

	clientXBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x12, 0x34}
	clientX := new(big.Int).SetBytes(clientXBytes)

	// serverX = 1354 yields a Z whose top byte is zero (255-byte magnitude),
	// discovered by deterministic offline search over g^serverX mod p.
	serverX := big.NewInt(1354)

	Ys := new(big.Int).Exp(g, serverX, pBig)
	zBig := new(big.Int).Exp(Ys, clientX, pBig)

	// Precondition the vector actually exercises the leading-zero path.
	if zBig.BitLen() > 8*(len(p)-1) {
		t.Fatalf("test vector no longer has a leading zero byte (Z bitlen %d)", zBig.BitLen())
	}

	wantZ := leftPadBig(zBig, len(p))
	if wantZ[0] != 0x00 {
		t.Fatalf("oracle Z top byte = %02x, want 0x00", wantZ[0])
	}

	var params []byte

	params = appendU16FieldWB(params, p)
	params = appendU16FieldWB(params, g.Bytes())
	params = appendU16FieldWB(params, Ys.Bytes())

	ex := NewDHEExchange(clientXBytes)

	_, preMaster, err := ex.ClientKeyExchange(params)
	if err != nil {
		t.Fatalf("ClientKeyExchange: %v", err)
	}

	if len(preMaster) != len(p) {
		t.Errorf("preMaster len = %d, want %d (leading zero must be preserved, not stripped)",
			len(preMaster), len(p))
	}

	if preMaster[0] != 0x00 {
		t.Errorf("preMaster[0] = %02x, want 0x00 (RFC 5246 §8.1.2 zero-fill)", preMaster[0])
	}

	if !bytes.Equal(preMaster, wantZ) {
		t.Errorf("premaster mismatch vs math/big oracle\n got:  %x\n want: %x", preMaster, wantZ)
	}
}
