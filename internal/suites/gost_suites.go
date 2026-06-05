// Package suites — GOST cipher suite registrations (pure-Go clean-room backend).
// Compiled in every build EXCEPT -tags openssl_gost_engine, where the OpenSSL
// gost-engine placeholder registrations in gost_suites_openssl_engine.go own
// the same IANA IDs and this file would double-register them.
// It registers two suites advertised by Tarantool-EE and one alias, plus two
// RFC 9367 suites.
//
// References:
//   - draft-chudov-cryptopro-cptls (expired) — defines 0x0081
//   - OpenSSL gost-engine — uses 0xFF85 for the 2012 suite (private use)
//   - draft-smyshlyaev-tls12-gost-suites — defines 0xC102 as the standardised ID
//   - RFC 9189 — TLS 1.2 GOST cipher suites (current best reference)
//   - RFC 9367 — Kuznyechik-CTR-OMAC (0xC100) and Magma-CTR-OMAC (0xC101)
//   - RFC 4357 — VKO GOST R 34.10-2001
//   - RFC 7836 — VKO GOST R 34.10-2012

package suites

import (
	"hash"

	gost "github.com/bigbes/gostcrypto"
)

func init() {
	registerGOSTSuites()
}

// ---- GOST 28147-89 cipher and MAC specs ------------------------------------
//
// GOST 28147-89 in CNT (counter stream) mode. CryptoPro-A S-box (RFC 4357)
// for 0x0081 and tc26-Z for 0xFF85 / 0xC102 — S-box selection is done in
// buildGOSTProtector based on suite.KX, not here.
//
// Key = 32 bytes, IV = 8 bytes (one GOST block), no wire IV.
// Validated against Tarantool-EE 3.5.0 via TestTarantoolEE_Ping_GOST_Pure.

var specGOST28147CNT = CipherSpec{
	Name: "GOST28147-CNT",
	// GOST 28147-89 key = 32 bytes.
	KeyLen: 32,
	// FixedIVLen = 8: the implicit IV from the TLS key block (one GOST block).
	// RFC 9189 §4.2: the IV is derived from the key block; no per-record IV is
	// prepended to the record fragment. Reference: gost-engine EVP cipher
	// Gost28147_89_cnt_cipher has OFB_MODE flag and iv_len=8
	// (tmp/engine/gost_crypt.c:174-182).
	FixedIVLen:    8,
	ExplicitIVLen: 0,
	AEAD:          false,
	TagLen:        0,
}

// GOST 28147-89 IMIT MAC spec.
//
// MACLen = 4 (4-byte truncation from the 8-byte IMIT output per RFC 9189 §4.2).
// MacKey = 32 bytes (separate from the encryption key, from key block).
// Validated against Tarantool-EE 3.5.0 via TestTarantoolEE_Ping_GOST_Pure.
var specGOST28147IMIT = MACSpec{
	Hash:   gost28147IMITHashNew,
	KeyLen: 32,
	MACLen: 4,
}

// gost28147IMITHashNew returns a hash.Hash for GOST 28147-89 IMIT.
// The key is embedded via the closure returned by the MAC factory.
// Note: this factory is used only to satisfy MACSpec.Hash for metadata
// purposes (e.g. reporting); the actual MAC computation in the Protector
// calls the GOST primitives directly.
//
// We use a 1-block all-zero IV for the hash factory (the real IV in TLS
// is the first data block, but this is handled in the protector).
func gost28147IMITHashNew() hash.Hash {
	// Placeholder instance (zero key/IV); only consulted for MACSpec metadata.
	// The real MAC uses the session MAC key, computed in the protector.
	return gost.NewGOST28147IMITPlaceholderHash()
}

// ---- RFC 9367 cipher and MAC specs --------------------------------------------
//
// Suite 0xC100: GOST2012-KUZNYECHIK-KUZNYECHIKOMAC
// Kuznyechik (GOST R 34.12-2015, 128-bit block) in CTR mode + OMAC-16.
// RFC 9189 §4.3 / RFC 9367: KeyLen=32, IV=16 bytes (from key block, no wire IV).
//
// Suite 0xC101: GOST2012-MAGMA-MAGMAOMAC
// Magma (GOST R 34.12-2015, 64-bit block) in CTR mode + OMAC-8.
// RFC 9189 §4.4 / RFC 9367: KeyLen=32, IV=8 bytes (from key block, no wire IV).

// specKuznyechikCTROMAC describes the Kuznyechik CTR cipher for RFC 9367.
//
// This is MAC-then-encrypt, NOT integrated AEAD: OpenSSL's TLS stack maps
// 0xC100 to the `kuznyechik-ctr-acpkm` EVP cipher plus a separate
// `kuznyechik-mac` EVP digest with mac_secret_size=32
// (ssl/ssl_ciph.c `ssl_mac_secret_size[SSL_MD_KUZNYECHIKOMAC_IDX] = 32`).
// Key block layout per RFC 5246 §6.3:
//
//	clientMACKey(32) || serverMACKey(32) ||
//	  clientEncKey(32) || serverEncKey(32) ||
//	  clientIV(8)     || serverIV(8)
//
// Per-record both the MAC key and the enc key go through TLSTREE
// (tmp/engine/test_tlstree.c:114-146). The `-acpkm-omac` integrated cipher
// (with KDFTree(iv) → cipher/mac masters and a random kdf_seed) is the CMS
// variant (draft-smyshlyaev-tls12-gost-suites §4 notwithstanding), not the
// TLS 1.2 record-layer cipher.
//
// TagLen = 16: full Kuznyechik block (gost_omac.c:48-56).
var specKuznyechikCTROMAC = CipherSpec{
	Name:          "KUZNYECHIK-CTR-OMAC",
	KeyLen:        32,
	FixedIVLen:    8,
	ExplicitIVLen: 0,
	AEAD:          false,
	TagLen:        0, // non-AEAD — MAC length is MACSpec.MACLen
}

// specKuznyechikOMAC: separate 32-byte MAC key per RFC 9367 / OpenSSL
// ssl_mac_secret_size mapping. Hash=nil because the record protector uses
// Kuznyechik-OMAC (a block-cipher MAC, not a hash) directly.
var specKuznyechikOMAC = MACSpec{
	Hash:   nil,
	KeyLen: 32,
	MACLen: 16,
}

var specMagmaCTROMAC = CipherSpec{
	Name:          "MAGMA-CTR-OMAC",
	KeyLen:        32,
	FixedIVLen:    4,
	ExplicitIVLen: 0,
	AEAD:          false,
	TagLen:        0,
}

var specMagmaOMAC = MACSpec{
	Hash:   nil,
	KeyLen: 32,
	MACLen: 8,
}

// ---- PRF specs for GOST suites -----------------------------------------------

// GOST R 34.11-94 PRF: used by GOST2001-GOST89-GOST89.
// RFC 9189 §4 specifies Streebog-256 for both suites, but older drafts
// (draft-chudov-cryptopro-cptls) specify GOST R 34.11-94 for the 2001 suite;
// Tarantool-EE 3.5.0 follows the older draft (confirmed by Ping handshake
// reaching Finished with this PRF).
var specPRFGOSTR341194 = PRFSpec{
	Hash: gost.NewGOSTR341194CryptoProHash,
}

// Streebog-256 PRF: used by GOST2012-GOST8912-GOST8912 per RFC 9189 §4.
var specPRFStreebog256 = PRFSpec{
	Hash: gost.NewStreebog256Hash,
}

// ---- Suite registrations -------------------------------------------------------

func registerGOSTSuites() {
	// Suite 0x0081: GOST2001-GOST89-GOST89
	//
	// ID: 0x0081 per draft-chudov-cryptopro-cptls and OpenSSL's historical
	// assignment. Confirmed advertised by Tarantool-EE 3.5.0.
	//
	// KX: GOST R 34.10-2001 VKO (no ServerKeyExchange — server cert is the key).
	// Auth: GOST R 34.10-2001 certificate.
	// Cipher: GOST 28147-89 CNT mode (CryptoPro-A S-box).
	// MAC: GOST 28147-89 IMIT, 4-byte output.
	// PRF: HMAC-GOSTR341194 (CryptoPro param set).
	register(&Suite{
		ID:     0x0081,
		Name:   "GOST2001-GOST89-GOST89",
		KX:     KexGOST2001,
		Auth:   AuthGOST2001,
		Cipher: specGOST28147CNT,
		MAC:    specGOST28147IMIT,
		PRF:    specPRFGOSTR341194,
	})

	// Suite 0xFF85: GOST2012-GOST8912-GOST8912 (primary ID)
	//
	// ID: 0xFF85 — OpenSSL gost-engine private-use ID, widely deployed.
	// Tarantool-EE 3.5.0 advertises this ID (confirmed on the wire).
	// draft-smyshlyaev-tls12-gost-suites standardised 0xC102 for the same
	// ciphersuite; registered below as an alias for servers that offer it.
	//
	// KX: GOST R 34.10-2012 VKO, 256-bit KEK (no ServerKeyExchange).
	// Auth: GOST R 34.10-2012 (256-bit) certificate.
	// Cipher: GOST 28147-89 CNT mode (tc26-Z S-box).
	// MAC: GOST 28147-89 IMIT, 4-byte output.
	// PRF: HMAC-Streebog-256 per RFC 9189 §4.
	register(&Suite{
		ID:     0xFF85,
		Name:   "GOST2012-GOST8912-GOST8912",
		KX:     KexGOST2012_256,
		Auth:   AuthGOST2012_256,
		Cipher: specGOST28147CNT,
		MAC:    specGOST28147IMIT,
		PRF:    specPRFStreebog256,
	})

	// Suite 0xC102: alias for GOST2012-GOST8912-GOST8912 (draft-smyshlyaev ID).
	//
	// draft-smyshlyaev-tls12-gost-suites defines TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
	// as 0xC102. This is the standardised ID; 0xFF85 is the gost-engine private-use
	// pre-standardisation value. We register both so that if a server offers either,
	// we can accept.
	//
	// Name uses the "IANA-" prefix to avoid the unique-name constraint in the
	// registry and to match gost-engine 3.0.3's `openssl ciphers -V` output for
	// 0xC102 (aligned with the openssl_gost_engine variant).
	// Note: Tarantool-EE 3.5.0 advertises 0xFF85, not 0xC102 — this alias
	// exists for forward compatibility with servers that migrate to the
	// standardised ID.
	register(&Suite{
		ID:     0xC102,
		Name:   "IANA-GOST2012-GOST8912-GOST8912",
		KX:     KexGOST2012_256,
		Auth:   AuthGOST2012_256,
		Cipher: specGOST28147CNT,
		MAC:    specGOST28147IMIT,
		PRF:    specPRFStreebog256,
	})

	// Suite 0xC100: GOST2012-KUZNYECHIK-KUZNYECHIKOMAC
	// RFC 9189 §4.3 / RFC 9367 — Kuznyechik in CTR mode + OMAC, 16-byte tag.
	// Key derivation per record uses TLSTREE (RFC 9367 §4).
	// KX: GOST 2018 key transport (RFC 9367) — structurally distinct from VKO 2012.
	// `openssl ciphers -V 0xC100` reports Kx=GOST18, not Kx=GOST.
	register(&Suite{
		ID:     0xC100,
		Name:   "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC",
		KX:     KexGOST2018_256,
		Auth:   AuthGOST2012_256,
		Cipher: specKuznyechikCTROMAC,
		MAC:    specKuznyechikOMAC,
		PRF:    specPRFStreebog256,
	})

	// Suite 0xC101: GOST2012-MAGMA-MAGMAOMAC
	// RFC 9189 §4.4 / RFC 9367 — Magma in CTR mode + OMAC, 8-byte tag.
	// Key derivation per record uses TLSTREE (RFC 9367 §4).
	// KX: GOST 2018 key transport (RFC 9367) — structurally distinct from VKO 2012.
	// `openssl ciphers -V 0xC101` reports Kx=GOST18, not Kx=GOST.
	register(&Suite{
		ID:     0xC101,
		Name:   "GOST2012-MAGMA-MAGMAOMAC",
		KX:     KexGOST2018_256,
		Auth:   AuthGOST2012_256,
		Cipher: specMagmaCTROMAC,
		MAC:    specMagmaOMAC,
		PRF:    specPRFStreebog256,
	})
}
