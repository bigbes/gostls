package handshake

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// verifyRSASignature verifies an RSA PKCS#1 v1.5 signature.
// hashAlg is the TLS hash algorithm byte; digest is the pre-computed hash.
func verifyRSASignature(pub *rsa.PublicKey, hashAlg uint8, digest, sig []byte) error {
	// hashForSigAlg is the single source of truth for the hash-byte mapping.
	cryptoHash, err := hashForSigAlg(hashAlg)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pub, cryptoHash, digest, sig)
}

// verifyECDSASignature verifies an ECDSA signature over a pre-computed digest.
func verifyECDSASignature(pub *ecdsa.PublicKey, digest, sig []byte) error {
	var esig struct {
		R, S *big.Int
	}

	if rest, err := asn1.Unmarshal(sig, &esig); err != nil {
		return fmt.Errorf("ecdsa: parse signature: %w", err)
	} else if len(rest) != 0 {
		return errECDSATrailingBytes
	}

	if !ecdsa.Verify(pub, digest, esig.R, esig.S) {
		return errECDSAVerifyFailed
	}

	return nil
}

// buildProtector constructs a record.Protector for the given suite and key material.
// For AES-GCM suites iv is the 4-byte salt; for ChaCha20-Poly1305 iv is the
// 12-byte implicit write_IV (RFC 7905).
func buildProtector(suite *suites.Suite, encKey, macKey, iv []byte, _ io.Reader) (record.Protector, error) {
	switch suite.Cipher.Name {
	case "GOST28147-CNT":
		return buildGOSTProtector(suite, encKey, macKey, iv)
	case "KUZNYECHIK-CTR-OMAC":
		return buildKuznyechikCTROMACProtector(suite, encKey, macKey, iv)
	case "MAGMA-CTR-OMAC":
		return buildMagmaCTROMACProtector(suite, encKey, macKey, iv)
	}

	if suite.Cipher.AEAD {
		switch suite.Cipher.Name {
		case "AES-128-GCM", "AES-256-GCM":
			return record.NewAEADProtector(encKey, iv)
		case "CHACHA20-POLY1305":
			return record.NewChaCha20Poly1305Protector(encKey, iv)
		default:
			return nil, fmt.Errorf("%w %q", errUnsupportedAEAD, suite.Cipher.Name)
		}
	}

	// CBC: MAC-then-encrypt with HMAC.
	var newHash record.NewHashFunc

	switch suite.MAC.MACLen {
	case 20: //nolint:mnd // 20 = SHA-1 HMAC length.
		newHash = record.SHA1Hash
	case 32: //nolint:mnd // 32 = SHA-256 HMAC length.
		newHash = record.SHA256Hash
	case 48: //nolint:mnd // 48 = SHA-384 HMAC length.
		newHash = record.SHA384Hash
	default:
		return nil, fmt.Errorf("%w %d for suite %s", errUnsupportedMACLen, suite.MAC.MACLen, suite.Name)
	}

	var newCipher record.NewCipherFunc

	switch suite.Cipher.Name {
	case "AES-128-CBC", "AES-256-CBC":
		newCipher = record.NewAESCipher
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedCBCCipher, suite.Cipher.Name)
	}

	return record.NewCBCHMACProtector(newCipher, newHash, encKey, macKey)
}
