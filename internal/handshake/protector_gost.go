package handshake

import (
	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// buildGOSTProtector constructs a GOST 28147-89 CNT + IMIT protector. Called
// from buildProtector when the negotiated suite uses cipher "GOST28147-CNT".
//
// S-box selection follows gost-engine: tc26-Z for GOST R 34.10-2012 suites
// (0xFF85, 0xC102), CryptoPro-A for GOST R 34.10-2001 suites (0x0081).
func buildGOSTProtector(suite *suites.Suite, encKey, macKey, iv []byte) (record.Protector, error) {
	sbox := gost.SboxCryptoProA // CryptoPro-A default
	if suite.KX == suites.KexGOST2012_256 {
		sbox = gost.SboxTC26Z // tc26-Z for 2012 suites
	}
	return record.NewGOST28147Protector(encKey, macKey, iv, sbox)
}

// buildKuznyechikCTROMACProtector constructs a Kuznyechik CTR + OMAC-16
// protector. Called from buildProtector when the negotiated suite uses
// cipher "KUZNYECHIK-CTR-OMAC" (suite 0xC100, RFC 9367).
//
// RFC 9367 suites are MAC-then-encrypt with separate 32-byte enc and MAC
// keys from the TLS key block (ssl/ssl_ciph.c `ssl_mac_secret_size
// [SSL_MD_KUZNYECHIKOMAC_IDX] = 32`). Per-record diversification is TLSTREE
// on each key.
func buildKuznyechikCTROMACProtector(_ *suites.Suite, encKey, macKey, iv []byte) (record.Protector, error) {
	return record.NewKuznyechikCTROMACProtector(encKey, macKey, iv)
}

// buildMagmaCTROMACProtector constructs a Magma CTR + OMAC-8 protector.
// Called from buildProtector when the negotiated suite uses cipher
// "MAGMA-CTR-OMAC" (suite 0xC101, RFC 9367). See
// buildKuznyechikCTROMACProtector for key-layout rationale.
func buildMagmaCTROMACProtector(_ *suites.Suite, encKey, macKey, iv []byte) (record.Protector, error) {
	return record.NewMagmaCTROMACProtector(encKey, macKey, iv)
}
