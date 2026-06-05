package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // SHA-1 is used for legacy TLS MAC only
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// SHA1Hash returns a new SHA-1 hash. Used by cbcHMACProtector for legacy suites.
func SHA1Hash() hash.Hash {
	return sha1.New() //nolint:gosec
}

// SHA256Hash returns a new SHA-256 hash.
func SHA256Hash() hash.Hash {
	return sha256.New()
}

// SHA384Hash returns a new SHA-384 hash.
func SHA384Hash() hash.Hash {
	return sha512.New384()
}

// NewAESCipher is the exported AES block cipher constructor.
// Same as the unexported newAESCipher in record.go; exposed here for
// handshake/crypto.go which calls buildProtector.
func NewAESCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
