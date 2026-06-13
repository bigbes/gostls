package ke

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"

	"filippo.io/bigmod"
)

// ecdhExchangeWithRand is an ECDHEExchange that uses a caller-supplied random reader.
// This enables deterministic testing.
type ecdhExchangeWithRand struct {
	rnd io.Reader
}

// NewECDHEExchangeWithRand creates an ECDHEExchange that reads from rnd instead of
// crypto/rand.Reader. If rnd is nil, crypto/rand.Reader is used.
func NewECDHEExchangeWithRand(rnd io.Reader) Exchange {
	if rnd == nil {
		rnd = rand.Reader
	}

	return &ecdhExchangeWithRand{rnd: rnd}
}

// ClientKeyExchange is identical to ECDHEExchange.ClientKeyExchange but uses e.rnd.
func (e *ecdhExchangeWithRand) ClientKeyExchange(serverParams []byte) (cke []byte, preMaster []byte, err error) {
	if len(serverParams) < ecdheServerParamsMinLen {
		return nil, nil, fmt.Errorf("ke: ECDHE serverParams too short (%d bytes): %w",
			len(serverParams), errECDHEServerParamsTooShort)
	}

	curveType := serverParams[0]
	if curveType != ecdheCurveTypeNamed {
		return nil, nil, fmt.Errorf(
			"ke: unsupported curve_type %d (only named_curve=3 is supported): %w",
			curveType, errECDHEUnsupportedCurveType)
	}

	namedCurve := uint16(serverParams[1])<<ecdheNamedCurveHighByteShift | uint16(serverParams[2])

	curve, err := curveByID(namedCurve)
	if err != nil {
		return nil, nil, err
	}

	pointLen := int(serverParams[3])
	if len(serverParams) < ecdheHeaderLen+pointLen {
		return nil, nil, fmt.Errorf("ke: ECDHE serverParams truncated: need %d bytes after header, have %d: %w",
			pointLen, len(serverParams)-ecdheHeaderLen, errECDHEServerParamsTruncated)
	}

	serverPubBytes := serverParams[ecdheHeaderLen : ecdheHeaderLen+pointLen]

	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: parse server public key: %w", err)
	}

	clientPriv, err := curve.GenerateKey(e.rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: generate client key: %w", err)
	}

	preMaster, err = clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: ECDH: %w", err)
	}

	clientPubBytes := clientPriv.PublicKey().Bytes()
	// CKE body: 1-byte length prefix + client public key bytes.
	cke = make([]byte, 1+len(clientPubBytes))
	cke[0] = byte(len(clientPubBytes))
	copy(cke[1:], clientPubBytes)

	return cke, preMaster, nil
}

// rsaExchangeWithRand is an RSAExchange that uses a caller-supplied random reader.
type rsaExchangeWithRand struct {
	rnd io.Reader
	pub *rsa.PublicKey
}

// NewRSAExchangeWithRand creates an RSAExchange that reads from rnd.
// If rnd is nil, crypto/rand.Reader is used.
func NewRSAExchangeWithRand(rnd io.Reader, pub *rsa.PublicKey) Exchange {
	if rnd == nil {
		rnd = rand.Reader
	}

	if pub == nil {
		panic("ke: NewRSAExchangeWithRand: nil public key")
	}

	return &rsaExchangeWithRand{rnd: rnd, pub: pub}
}

// ClientKeyExchange generates a 48-byte pre-master secret, encrypts it with
// the server's RSA public key, and returns the CKE body and pre-master secret.
func (r *rsaExchangeWithRand) ClientKeyExchange(serverParams []byte) (cke []byte, preMaster []byte, err error) {
	preMaster = make([]byte, rsaPreMasterLen)
	preMaster[0] = 0x03
	preMaster[1] = 0x03

	if _, err = io.ReadFull(r.rnd, preMaster[rsaCKELenPrefixSize:]); err != nil {
		return nil, nil, fmt.Errorf("ke: RSA: generate pre-master random: %w", err)
	}

	ciphertext, err := rsa.EncryptPKCS1v15(r.rnd, r.pub, preMaster)
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

// ECDHGeneratePublic generates an ECDH P-256 public key from a fixed 32-byte seed.
// Returns the raw private key bytes and the uncompressed public key bytes.
// Used in tests to build deterministic server ECDHE parameters.
func ECDHGeneratePublic(seed []byte) (privBytes, pubBytes []byte, err error) {
	priv, err := ecdh.P256().NewPrivateKey(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: ECDHGeneratePublic: invalid seed: %w", err)
	}

	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// DHEComputePublic computes base^exponent mod p using constant-time bigmod arithmetic.
// pBytes is the group prime; baseBytes is the base (g for computing public key, Yc for shared secret);
// exponentBytes is the private exponent x.
// Returns the result left-padded to len(pBytes) bytes.
//
// Note: This function does NOT validate the DHE parameters (it is used for both
// key generation and shared-secret computation by trusted callers). Callers
// that receive base from an untrusted source must validate with validateDHEParams first.
func DHEComputePublic(pBytes, baseBytes, exponentBytes []byte) ([]byte, error) {
	mod, err := bigmod.NewModulus(pBytes)
	if err != nil {
		return nil, fmt.Errorf("ke: DHEComputePublic: build modulus: %w", err)
	}

	result, err := modExp(baseBytes, exponentBytes, mod)
	if err != nil {
		return nil, fmt.Errorf("ke: DHEComputePublic: modExp: %w", err)
	}

	return leftPad(result, len(pBytes)), nil
}
