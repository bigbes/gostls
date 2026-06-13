package ke

// Gost2018Exchange implements the GOST 2018 key exchange for RFC 9367 suites
// 0xC100 (kuznyechik) and 0xC101 (magma).
//
// Orchestration mirrors pkey_gost2018_encrypt in
// tmp/engine/gost_ec_keyx.c:413-551.
//
// The client:
//  1. Generates a 32-byte random UKM.
//  2. Generates a 32-byte random pre-master secret.
//  3. Generates an ephemeral EC key pair on the server's curve.
//  4. Derives 64-byte expkeys via KEG2012_256(curve, serverPub, clientPriv, ukm).
//     Layout: expkeys[:32] = mac_key, expkeys[32:] = cipher_key
//     (gost_keg output, matches gost_kexp15 input layout: expkeys+0=mac, expkeys+32=cipher).
//  5. Selects IV = ukm[24 : 24+ivLen] where ivLen = 4 (Magma) or 8 (Kuznyechik).
//  6. Wraps pre-master via kexp15(variant, preMaster, cipherKey, macKey, iv).
//  7. Assembles PSKeyTransport_gost{psexp=wrapped, ephem_key=SPKI, ukm=ukm[0:32]}.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	gost "github.com/bigbes/gostcrypto"
)

// GOST 2018 key exchange size constants.
const (
	// gost2018RandomsLen is the required length of clientRandom || serverRandom.
	gost2018RandomsLen = 64

	// gost2018Streebog256Len is the expected output length of Streebog-256.
	gost2018Streebog256Len = 32

	// gost2018UKMLen is the length of the UKM for fallback random generation.
	gost2018UKMLen = 32

	// gost2018PreMasterLen is the length of the pre-master secret.
	gost2018PreMasterLen = 32

	// gost2018IVKuznyechik is the IV length for Kuznyechik variant.
	gost2018IVKuznyechik = 8

	// gost2018IVMagma is the IV length for Magma variant.
	gost2018IVMagma = 4

	// gost2018UKMIVOffset is the offset within the UKM where the IV starts.
	// IV = ukm[gost2018UKMIVOffset : gost2018UKMIVOffset+ivLen].
	gost2018UKMIVOffset = 24
)

// Sentinel errors for GOST 2018 key exchange validation.
var (
	errGost2018CurveRequired     = errors.New("ke/gost2018: curve is required")
	errGost2018SpkiAlgoRequired  = errors.New("ke/gost2018: spkiAlgo is required")
	errGost2018ServerPubRequired = errors.New("ke/gost2018: serverPubRaw is required")
	errGost2018UnknownVariant    = errors.New("ke/gost2018: unknown variant")
	errGost2018RandomsLen        = errors.New("ke/gost2018: randoms must be 64 bytes (clientRandom || serverRandom)")
	errGost2018Streebog256Len    = errors.New("ke/gost2018: unexpected Streebog-256 output length")
)

// Gost2018Variant selects the block cipher used for kexp15 key transport.
// Mirrors gost.KexpVariant but lives in ke for the public-surface Export.
type Gost2018Variant int

const (
	// Variant2018Kuznyechik uses Kuznyechik (128-bit block, iv_len=8, mac_len=16).
	// Corresponds to TLS suite 0xC100.
	Variant2018Kuznyechik Gost2018Variant = iota

	// Variant2018Magma uses Magma (64-bit block, iv_len=4, mac_len=8).
	// Corresponds to TLS suite 0xC101.
	Variant2018Magma
)

// kexpVariant converts a Gost2018Variant to the internal gost.KexpVariant.
func kexpVariant(v Gost2018Variant) gost.KexpVariant {
	switch v {
	case Variant2018Kuznyechik:
		return gost.KexpKuznyechik
	case Variant2018Magma:
		return gost.KexpMagma
	default:
		panic(fmt.Sprintf("ke/gost2018: unknown Gost2018Variant %d", v))
	}
}

// ivLen returns the IV length (bytes) for the given variant.
// Kuznyechik: 8, Magma: 4. Source: tmp/engine/gost_ec_keyx.c:421-428.
func ivLen(v Gost2018Variant) int {
	switch v {
	case Variant2018Kuznyechik:
		return gost2018IVKuznyechik
	case Variant2018Magma:
		return gost2018IVMagma
	default:
		panic(fmt.Sprintf("ke/gost2018: unknown Gost2018Variant %d", v))
	}
}

// Gost2018Exchange implements the Exchange interface for GOST 2018 key exchange
// (draft-smyshlyaev-tls12-gost-suites, suites 0xC100 / 0xC101).
//
// The exchange generates an ephemeral GOST R 34.10-2012 keypair, derives the
// 64-byte key material via KEG2012_256, and wraps the pre-master secret using
// kexp15 (R 1323565.1.020-2018 §6.3.2). The result is encoded as a
// PSKeyTransport_gost ASN.1 structure (tmp/engine/gost_asn1.c:70-76).
type Gost2018Exchange struct {
	curve        *gost.Curve
	spkiAlgo     []byte // server cert SPKI AlgorithmIdentifier DER (reused verbatim).
	serverPubRaw []byte // server cert public key (LE Y || LE X, 64 bytes).
	variant      Gost2018Variant
	// clientRandom || serverRandom (64 bytes total) — hashed with Streebog-256
	// to produce the UKM. See comment on NewGost2018Exchange for the derivation
	// rationale; empty means fall back to a random 32-byte UKM (not
	// interoperable with OpenSSL servers, retained only for unit tests).
	randoms []byte
	rng     io.Reader // defaults to crypto/rand.Reader when nil.
}

// NewGost2018Exchange creates a Gost2018Exchange ready to produce a CKE.
//
// curve must be the GOST R 34.10-2012 256-bit curve from the server certificate
// (resolve via gost.CurveByOID). spkiAlgo is the raw DER of the server cert's
// SPKI AlgorithmIdentifier (used verbatim in the ephemeral SPKI). serverPubRaw
// is the 64-byte raw public key. variant selects Kuznyechik or Magma.
//
// randoms is clientRandom || serverRandom (64 bytes). Per OpenSSL
// ssl/statem/statem_clnt.c:ossl_gost_ukm, the TLS 1.2 GOST 2018 UKM is
// Streebog-256(clientRandom || serverRandom) — not a fresh random. The
// server derives the same UKM independently and uses it to unwrap the CKE;
// if the UKM on the wire differs, `gost_kimp15` returns BAD_MAC and the
// handshake aborts. Callers may pass nil only for unit tests; production
// callers from the TLS handshake path must supply the 64-byte concatenation.
//
// rng is injectable for deterministic testing; pass nil to use crypto/rand.Reader.
func NewGost2018Exchange(
	curve *gost.Curve,
	spkiAlgo, serverPubRaw []byte,
	variant Gost2018Variant,
	randoms []byte,
) (*Gost2018Exchange, error) {
	if curve == nil {
		return nil, fmt.Errorf("%w", errGost2018CurveRequired)
	}

	if len(spkiAlgo) == 0 {
		return nil, fmt.Errorf("%w", errGost2018SpkiAlgoRequired)
	}

	if len(serverPubRaw) == 0 {
		return nil, fmt.Errorf("%w", errGost2018ServerPubRequired)
	}

	if variant != Variant2018Kuznyechik && variant != Variant2018Magma {
		return nil, fmt.Errorf("ke/gost2018: unknown variant %d: %w", variant, errGost2018UnknownVariant)
	}

	if randoms != nil && len(randoms) != gost2018RandomsLen {
		return nil, fmt.Errorf(
			"ke/gost2018: randoms must be 64 bytes (clientRandom || serverRandom), got %d: %w",
			len(randoms), errGost2018RandomsLen)
	}

	return &Gost2018Exchange{
		curve:        curve,
		spkiAlgo:     spkiAlgo,
		serverPubRaw: serverPubRaw,
		variant:      variant,
		randoms:      randoms,
		rng:          nil, // resolved to rand.Reader in ClientKeyExchange.
	}, nil
}

// ClientKeyExchange implements Exchange for GOST 2018 KEX.
//
// serverParams is ignored — the server public key was provided at construction
// time; GOST 2018 suites do not send a ServerKeyExchange message.
//
// Orchestration reference: tmp/engine/gost_ec_keyx.c:413-551 (pkey_gost2018_encrypt).
func (e *Gost2018Exchange) ClientKeyExchange(_ []byte) (cke, preMaster []byte, err error) {
	rng := e.rng
	if rng == nil {
		rng = rand.Reader
	}

	// Step 1: derive the 32-byte UKM deterministically from
	// Streebog-256(clientRandom || serverRandom). OpenSSL's
	// ssl/statem/statem_clnt.c:ossl_gost_ukm establishes this as the wire
	// contract for TLS 1.2 GOST 2018: both peers compute the same UKM from
	// the two randoms they already exchanged, so the `ukm` field on the
	// PSKeyTransport_gost is effectively informational. A fresh-random UKM
	// would make the server's `gost_kimp15` check fail with BAD_MAC.
	//
	// For unit tests that don't carry a TLS handshake context we fall back
	// to a random UKM — callers from tests use only the round-trip helpers
	// they control both sides of.
	var ukm []byte

	if len(e.randoms) == gost2018RandomsLen {
		d := gost.Streebog256(e.randoms)
		if len(d) != gost2018Streebog256Len {
			return nil, nil, fmt.Errorf(
				"ke/gost2018: unexpected Streebog-256 output length %d: %w",
				len(d), errGost2018Streebog256Len)
		}

		ukm = d
	} else {
		ukm = make([]byte, gost2018UKMLen)
		if _, err = rng.Read(ukm); err != nil {
			return nil, nil, fmt.Errorf("ke/gost2018: ukm rand: %w", err)
		}
	}

	// Step 2: generate 32-byte random pre-master secret.
	// tmp/engine/gost_ec_keyx.c:460-461: generate random session key.
	preMaster = make([]byte, gost2018PreMasterLen)
	if _, err = rng.Read(preMaster); err != nil {
		return nil, nil, fmt.Errorf("ke/gost2018: premaster rand: %w", err)
	}

	// Step 3: generate ephemeral EC key pair on the server's curve.
	// tmp/engine/gost_ec_keyx.c:471-476: generate ephemeral key.
	clientPrivRaw, clientPubRaw, err := gost.GenerateEphemeralKey(e.curve, rng)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/gost2018: ephemeral keygen: %w", err)
	}

	// Step 4: derive 64-byte expkeys via KEG2012_256.
	// tmp/engine/gost_ec_keyx.c:478-484: gost_keg(shared_ukm, ..., expkeys).
	// expkeys[:32] = mac_key, expkeys[32:] = cipher_key.
	expkeys, err := gost.KEG2012_256(e.curve, e.serverPubRaw, clientPrivRaw, ukm)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/gost2018: KEG2012_256: %w", err)
	}

	// Step 5: IV = ukm[gost2018UKMIVOffset : gost2018UKMIVOffset+ivLen].
	// tmp/engine/gost_ec_keyx.c:486: gost_kexp15(..., shared_ukm+24, iv_len, ...).
	iv := ukm[gost2018UKMIVOffset : gost2018UKMIVOffset+ivLen(e.variant)]

	// Step 6: wrap pre-master via kexp15.
	// tmp/engine/gost_ec_keyx.c:486-498: gost_kexp15(session_key, key_len,
	//   cipher_nid, expkeys+32, mac_nid, expkeys+0, shared_ukm+24, iv_len, ...).
	wrapped, err := gost.Kexp15(kexpVariant(e.variant), preMaster, expkeys[32:], expkeys[:32], iv)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/gost2018: kexp15: %w", err)
	}

	// Step 7: assemble PSKeyTransport_gost{psexp, ephem_key SPKI, ukm}.
	// tmp/engine/gost_ec_keyx.c:501-541: i2d_PSKeyTransport_gost assembly.
	cke, err = marshalPSKeyTransport(wrapped, e.spkiAlgo, clientPubRaw, ukm)
	if err != nil {
		return nil, nil, fmt.Errorf("ke/gost2018: marshalPSKeyTransport: %w", err)
	}

	return cke, preMaster, nil
}
