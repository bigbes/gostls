package ke

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
)

// RSA key exchange constants.
const (
	// rsaPreMasterLen is the fixed length of the RSA pre-master secret per RFC 5246 §7.4.7.1.
	rsaPreMasterLen = 48

	// rsaCKELenPrefixSize is the size of the uint16 big-endian length prefix in the CKE body.
	rsaCKELenPrefixSize = 2
)

// RSAExchange implements the RSA key exchange for TLS 1.2 (RFC 5246 §7.4.7.1).
//
// The server public key is loaded at construction time (from the server
// certificate). There is no ServerKeyExchange message for RSA key exchange.
// ServerParams passed to ClientKeyExchange is ignored; pass nil.
//
// Pre-master secret: 48 bytes with version prefix {0x03, 0x03} followed by
// 46 random bytes.
//
// ClientKeyExchange body (cke): per RFC 5246 §7.4.7.1, a uint16 big-endian
// length prefix followed by the PKCS#1 v1.5 encrypted pre-master secret.
// Its length is 2 + modulus bytes (e.g. 258 bytes for RSA-2048).
type RSAExchange struct {
	pub *rsa.PublicKey
}

// NewRSAExchange creates an RSAExchange with the server's RSA public key.
// pub must not be nil.
func NewRSAExchange(pub *rsa.PublicKey) *RSAExchange {
	if pub == nil {
		panic("ke: NewRSAExchange: nil public key")
	}

	return &RSAExchange{pub: pub}
}

// ClientKeyExchange generates a 48-byte pre-master secret with version prefix
// {0x03, 0x03}, encrypts it with the server's RSA public key using PKCS#1 v1.5,
// and returns the encrypted bytes as the ClientKeyExchange body.
//
// serverParams is ignored (RSA key exchange has no ServerKeyExchange); pass nil.
func (r *RSAExchange) ClientKeyExchange(serverParams []byte) (cke []byte, preMaster []byte, err error) {
	preMaster = make([]byte, rsaPreMasterLen)
	preMaster[0] = 0x03
	preMaster[1] = 0x03

	if _, err = rand.Read(preMaster[rsaCKELenPrefixSize:]); err != nil {
		return nil, nil, fmt.Errorf("ke: RSA: generate pre-master random: %w", err)
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, r.pub, preMaster)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: RSA: encrypt pre-master: %w", err)
	}

	// RFC 5246 §7.4.7.1: the CKE body is a <0..2^16-1> opaque vector —
	// a uint16 big-endian length prefix followed by the ciphertext bytes.
	cke = make([]byte, rsaCKELenPrefixSize+len(ciphertext))
	binary.BigEndian.PutUint16(cke[:rsaCKELenPrefixSize], uint16(len(ciphertext)))
	copy(cke[2:], ciphertext)

	return cke, preMaster, nil
}
