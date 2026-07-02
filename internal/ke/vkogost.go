package ke

// VKOGost2001Exchange and VKOGost2012_256Exchange implement the Exchange
// interface for GOST key-agreement cipher suites.
//
// Unlike ECDHE or DHE, GOST suites do NOT send a ServerKeyExchange message.
// The server's public key is extracted from the server certificate (signed
// with GOST R 34.10-2001 or GOST R 34.10-2012). This is analogous to RSA
// key exchange where the encryption key comes from the certificate.
//
// Pre-master secret derivation (RFC 9189 §4.1):
//
//	pre_master_secret = VKO(client_ephemeral_private, server_cert_public, UKM)
//
// UKM (User Keying Material) = first 8 bytes of client_random per RFC 9189 §4.1.
// Confirmed against Tarantool-EE 3.5.0 via TestTarantoolEE_Ping_GOST_Pure.
//
// ClientKeyExchange body format (RFC 9189 §4.1 and gost-engine's
// pkey_GOST_ECcp_encrypt in tmp/engine/gost_ec_keyx.c): both VKO2001 and
// VKO2012_256 suites send a GOST_KEY_TRANSPORT-wrapped CKE. The 32-byte
// premaster is a fresh random value wrapped via CryptoPro key wrap under the
// VKO-derived shared key. The cipher OID and S-box differ:
//
//	VKO2001 (0x0081):           id-Gost28147-89-CryptoPro-A-ParamSet, SboxCryptoProA
//	VKO2012_256 (0xFF85, etc.): id-tc26-gost-28147-param-Z,           SboxTC26Z

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"

	gost "github.com/bigbes/gostcrypto"
)

// VKO key exchange size constants.
const (
	// vkoUKMMinLen is the minimum UKM length; the TLS spec uses first 8 bytes per RFC 9189 §4.1.
	vkoUKMMinLen = 8

	// vkoPreMasterLen is the fixed 32-byte pre-master secret size for VKO exchanges.
	vkoPreMasterLen = 32

	// vkoKEKLen is the expected length of the VKO-derived key encryption key.
	vkoKEKLen = 32

	// cryptoProWrapEncKeyOff is the byte offset within KeyWrapCryptoPro output where
	// the encrypted key starts (after the 8-byte UKM prefix).
	cryptoProWrapEncKeyOff = 8

	// cryptoProWrapEncKeyEnd is the byte offset where the encrypted key ends
	// (UKM(8) + encryptedKey(32) = 40).
	cryptoProWrapEncKeyEnd = 40

	// cryptoProWrapIMITEnd is the byte offset where the IMIT (MAC) ends
	// (UKM(8) + encryptedKey(32) + imit(4) = 44).
	cryptoProWrapIMITEnd = 44
)

// Sentinel errors for VKO GOST key exchange validation.
var (
	errVKO2001CurveRequired   = errors.New("ke/vkogost: VKO2001 curve is required")
	errVKO2001SpkiRequired    = errors.New("ke/vkogost: VKO2001 server SPKI AlgorithmIdentifier is required")
	errVKO2001UKMTooShort     = errors.New("ke/vkogost: VKO2001 UKM must be at least 8 bytes")
	errVKO2001BadPreMasterLen = errors.New("ke/vkogost: VKO2001TestCurve returned wrong number of bytes, want 32")
	errVKO2001BadKEKLen       = errors.New("ke/vkogost: VKO2001 returned wrong number of bytes, want 32")
	errVKO2012CurveRequired   = errors.New("ke/vkogost: VKO2012_256 curve is required")
	errVKO2012SpkiRequired    = errors.New("ke/vkogost: VKO2012_256 server SPKI AlgorithmIdentifier is required")
	errVKO2012UKMTooShort     = errors.New("ke/vkogost: VKO2012_256 UKM must be at least 8 bytes")
)

// oidTc26Gost28147ParamZ is the OID of id-tc26-gost-28147-param-Z (the
// GOST 28147-89 parameter set used by the CryptoPro key wrap when the
// server certificate is GOST R 34.10-2012). Source:
// tmp/engine/tcl_tests/name2oid.tcl:25.
var oidTc26Gost28147ParamZ = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}

// oidGost28147CryptoProA is the OID of id-Gost28147-89-CryptoPro-A-ParamSet,
// the GOST 28147-89 parameter set used by the CryptoPro key wrap when the
// server certificate is GOST R 34.10-2001. Source: gost-engine's
// crypt_params_obj selection in pkey_GOST_ECcp_encrypt
// (tmp/engine/gost_ec_keyx.c:285-287) and NID_id_Gost28147_89_CryptoPro_A_ParamSet.
var oidGost28147CryptoProA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}

// ── VKOGost2001Exchange ───────────────────────────────────────────────────────.

// VKOGost2001Exchange implements Exchange for GOST2001-GOST89-GOST89
// (suite ID 0x0081). It uses GOST R 34.10-2001 VKO key agreement (RFC 4357)
// combined with CryptoPro key wrap to produce a GOST_KEY_TRANSPORT envelope,
// matching gost-engine's pkey_GOST_ECcp_encrypt.
//
// The client generates a fresh ephemeral key pair per handshake on the same
// curve carried by the server's certificate.
type VKOGost2001Exchange struct {
	curve       *gost.Curve
	spkiAlgo    []byte // server cert SPKI AlgorithmIdentifier DER (reused for ephem SPKI).
	prvRaw      []byte // client ephemeral private key.
	ephemPubRaw []byte // client ephemeral public key (derived at construction).
	pubRaw      []byte // server certificate public key.
	ukm         []byte // UKM = first 8 bytes of client_random.
}

// NewVKOGost2001Exchange creates a VKOGost2001Exchange that generates a fresh
// ephemeral key pair on the given curve. curve must match the curve OID from
// the server certificate (resolve via gost.CurveByOID). spkiAlgo is the DER of
// the server cert's SPKI AlgorithmIdentifier; it is reused to build the
// ephemeral key's SPKI inside the GOST_KEY_TRANSPORT envelope. pubRaw is the
// server's GOST R 34.10-2001 public key from the server certificate SPKI. ukm
// is derived from client_random (first 8 bytes).
func NewVKOGost2001Exchange(curve *gost.Curve, spkiAlgo, pubRaw, ukm []byte) (*VKOGost2001Exchange, error) {
	if curve == nil {
		return nil, fmt.Errorf("%w", errVKO2001CurveRequired)
	}

	if len(spkiAlgo) == 0 {
		return nil, fmt.Errorf("%w", errVKO2001SpkiRequired)
	}

	if len(ukm) < vkoUKMMinLen {
		return nil, fmt.Errorf("ke/vkogost: VKO2001 UKM must be at least 8 bytes, got %d: %w",
			len(ukm), errVKO2001UKMTooShort)
	}

	prvRaw, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ke/vkogost: VKO2001 keygen: %w", err)
	}

	return &VKOGost2001Exchange{
		curve:       curve,
		spkiAlgo:    spkiAlgo,
		prvRaw:      prvRaw,
		ephemPubRaw: ephemPubRaw,
		pubRaw:      pubRaw,
		ukm:         ukm[:vkoUKMMinLen],
	}, nil
}

// GOST2001TestPublicKeyFromPrivate derives the GOST R 34.10-2001 public key
// from a private key using the test parameter set curve.
// Used in tests to generate the public key for the upstream test vectors
// (which use CurveIdGostR34102001TestParamSet, not CryptoPro-A).
func GOST2001TestPublicKeyFromPrivate(prvRaw []byte) ([]byte, error) {
	return gost.PublicKeyRawFromPrivate2001Test(prvRaw)
}

// vkoGost2001TestCurveExchange is the test-curve variant of VKOGost2001Exchange.
type vkoGost2001TestCurveExchange struct {
	prvRaw []byte
	pubRaw []byte
	ukm    []byte
}

// NewVKOGost2001ExchangeTestCurve creates a VKOGost2001Exchange that uses the
// GOST R 34.10-2001 test parameter set curve (not CryptoPro-A). Used only in
// unit tests that verify round-trip logic with upstream gogost test vectors.
//
// Production code uses NewVKOGost2001ExchangeWithKey (CryptoPro-A curve).
func NewVKOGost2001ExchangeTestCurve(prvRaw, pubRaw, ukm []byte) *vkoGost2001TestCurveExchange {
	return &vkoGost2001TestCurveExchange{prvRaw: prvRaw, pubRaw: pubRaw, ukm: ukm}
}

func (e *vkoGost2001TestCurveExchange) ClientKeyExchange(_ []byte) (cke []byte, preMaster []byte, err error) {
	preMaster, err = gost.VKO2001TestCurve(e.prvRaw, e.pubRaw, e.ukm)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001TestCurve: %w", err)
	}

	if len(preMaster) != vkoPreMasterLen {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001TestCurve returned %d bytes, want 32: %w",
			len(preMaster), errVKO2001BadPreMasterLen)
	}

	// CKE = raw public key from test-param-set curve.
	cke, err = gost.PublicKeyRawFromPrivate2001Test(e.prvRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: derive pubkey: %w", err)
	}

	return cke, preMaster, nil
}

// ClientKeyExchange implements Exchange for VKO2001.
//
// serverParams is ignored (GOST suites have no ServerKeyExchange; the server
// public key was provided at construction time via pubRaw).
//
// Produces a GOST_KEY_TRANSPORT-wrapped ClientKeyExchange body per RFC 9189
// §4.1 and gost-engine's pkey_GOST_ECcp_encrypt
// (tmp/engine/gost_ec_keyx.c:277-407). The 32-byte premaster is a fresh
// random value wrapped via CryptoPro key wrap under the VKO2001-derived
// shared key (CryptoPro-A S-box); the wrap output goes into GOST_KEY_INFO,
// and the ephemeral public key + UKM go into GOST_KEY_AGREEMENT_INFO.
func (e *VKOGost2001Exchange) ClientKeyExchange(_ []byte) (cke []byte, preMaster []byte, err error) {
	preMaster = make([]byte, vkoPreMasterLen)
	if _, err := rand.Read(preMaster); err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001 premaster rand: %w", err)
	}

	kek, err := gost.VKO2001OnCurve(e.curve, e.prvRaw, e.pubRaw, e.ukm)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001 shared key: %w", err)
	}

	if len(kek) != vkoKEKLen {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001 returned %d bytes, want 32: %w", len(kek), errVKO2001BadKEKLen)
	}

	wrapped, err := gost.KeyWrapCryptoPro(gost.SboxCryptoProA, kek, e.ukm, preMaster)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001 key wrap: %w", err)
	}

	if len(wrapped) < cryptoProWrapIMITEnd {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001 key wrap output %d bytes, want %d: %w",
			len(wrapped), cryptoProWrapIMITEnd, errVKO2001BadKEKLen)
	}

	cke, err = marshalGOSTKeyTransport(
		e.spkiAlgo,
		e.ephemPubRaw,
		wrapped[cryptoProWrapEncKeyOff:cryptoProWrapEncKeyEnd],
		wrapped[cryptoProWrapEncKeyEnd:cryptoProWrapIMITEnd],
		oidGost28147CryptoProA,
		e.ukm,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2001 marshal GKT: %w", err)
	}

	return cke, preMaster, nil
}

// ── VKOGost2012_256Exchange ───────────────────────────────────────────────────.

// VKOGost2012_256Exchange implements Exchange for GOST2012-GOST8912-GOST8912
// (suite IDs 0xFF85 / 0xC102). It uses GOST R 34.10-2012 VKO with 256-bit KEK
// (RFC 7836) on the curve carried by the server certificate. Observed curves
// in Tarantool-EE fixtures include id-GostR3410-2001-CryptoPro-A (256-bit)
// for GOST2012-256 certificates; the 512-bit paramSetA may also appear.
type VKOGost2012_256Exchange struct {
	curve       *gost.Curve
	spkiAlgo    []byte // server cert SPKI AlgorithmIdentifier DER (reused for ephem SPKI).
	prvRaw      []byte // client ephemeral private key.
	ephemPubRaw []byte // client ephemeral public key (derived at construction).
	pubRaw      []byte // server certificate public key.
	ukm         []byte // UKM = first 8 bytes of client_random.
}

// NewVKOGost2012_256Exchange creates a VKOGost2012_256Exchange with a fresh
// ephemeral key on the given curve. curve must match the server certificate's
// CurveOID (resolve via gost.CurveByOID). spkiAlgo is the DER of the server
// cert's SPKI AlgorithmIdentifier (x509gost.Certificate.SPKIAlgorithmDER);
// it is reused to build the ephemeral key's SPKI inside the GOST_KEY_TRANSPORT
// envelope. pubRaw is the server's public key bytes. ukm is derived from
// client_random (first 8 bytes).
func NewVKOGost2012_256Exchange(curve *gost.Curve, spkiAlgo, pubRaw, ukm []byte) (*VKOGost2012_256Exchange, error) {
	if curve == nil {
		return nil, fmt.Errorf("%w", errVKO2012CurveRequired)
	}

	if len(spkiAlgo) == 0 {
		return nil, fmt.Errorf("%w", errVKO2012SpkiRequired)
	}

	if len(ukm) < vkoUKMMinLen {
		return nil, fmt.Errorf("ke/vkogost: VKO2012_256 UKM must be at least 8 bytes, got %d: %w",
			len(ukm), errVKO2012UKMTooShort)
	}

	prvRaw, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ke/vkogost: VKO2012_256 keygen: %w", err)
	}

	return &VKOGost2012_256Exchange{
		curve:       curve,
		spkiAlgo:    spkiAlgo,
		prvRaw:      prvRaw,
		ephemPubRaw: ephemPubRaw,
		pubRaw:      pubRaw,
		ukm:         ukm[:vkoUKMMinLen],
	}, nil
}

// ClientKeyExchange implements Exchange for VKO2012_256.
//
// Produces a GOST_KEY_TRANSPORT-wrapped ClientKeyExchange body per RFC 9189
// §4.1 and gost-engine's pkey_GOST_ECcp_encrypt. The 32-byte premaster is a
// fresh random value wrapped via CryptoPro key wrap under the VKO-derived
// shared key; the wrap output goes into GOST_KEY_INFO, and the ephemeral
// public key + UKM go into GOST_KEY_AGREEMENT_INFO.
func (e *VKOGost2012_256Exchange) ClientKeyExchange(_ []byte) (cke []byte, preMaster []byte, err error) {
	preMaster = make([]byte, vkoPreMasterLen)
	if _, err := rand.Read(preMaster); err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2012_256 premaster rand: %w", err)
	}

	kek, err := gost.VKO2012_256OnCurve(e.curve, e.prvRaw, e.pubRaw, e.ukm)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2012_256 shared key: %w", err)
	}

	if len(kek) != vkoKEKLen {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2012_256 returned %d bytes, want 32: %w",
			len(kek), errVKO2001BadKEKLen)
	}

	wrapped, err := gost.KeyWrapCryptoPro(gost.SboxTC26Z, kek, e.ukm, preMaster)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2012_256 key wrap: %w", err)
	}

	if len(wrapped) < cryptoProWrapIMITEnd {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2012_256 key wrap output %d bytes, want %d: %w",
			len(wrapped), cryptoProWrapIMITEnd, errVKO2001BadKEKLen)
	}

	cke, err = marshalGOSTKeyTransport(
		e.spkiAlgo,
		e.ephemPubRaw,
		wrapped[cryptoProWrapEncKeyOff:cryptoProWrapEncKeyEnd],
		wrapped[cryptoProWrapEncKeyEnd:cryptoProWrapIMITEnd],
		oidTc26Gost28147ParamZ,
		e.ukm,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/vkogost: VKO2012_256 marshal GKT: %w", err)
	}

	return cke, preMaster, nil
}
