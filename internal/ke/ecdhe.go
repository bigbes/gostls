package ke

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

// TLS 1.2 RFC 4492 NamedCurve identifiers.
const (
	namedCurveP256   uint16 = 0x0017 // secp256r1.
	namedCurveP384   uint16 = 0x0018 // secp384r1.
	namedCurveP521   uint16 = 0x0019 // secp521r1.
	namedCurveX25519 uint16 = 0x001D // x25519.

	// ecdheCurveTypeNamed is the curve_type value for named_curve (RFC 4492 §5.4).
	ecdheCurveTypeNamed = 3

	// ecdheServerParamsMinLen is the minimum length of a ServerKeyExchange ECDHE params block.
	// curve_type(1) + named_curve(2) + point_len(1) = 4 bytes.
	ecdheServerParamsMinLen = 4

	// ecdheNamedCurveHighByteShift is the bit-shift to extract the high byte of named_curve.
	ecdheNamedCurveHighByteShift = 8

	// ecdheHeaderLen is the number of header bytes before the point bytes
	// (curve_type + named_curve + point_len = 4).
	ecdheHeaderLen = 4
)

// Sentinel errors for ECDHE parameter validation.
var (
	errECDHEUnsupportedCurve      = errors.New("ke: unsupported named curve")
	errECDHEServerParamsTooShort  = errors.New("ke: ECDHE serverParams too short")
	errECDHEUnsupportedCurveType  = errors.New("ke: unsupported curve_type (only named_curve=3 is supported)")
	errECDHEServerParamsTruncated = errors.New("ke: ECDHE serverParams truncated")
)

// ECDHEExchange implements the ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
// key exchange for TLS 1.2.
//
// Supported named curves (RFC 4492 NamedCurve values):
//   - 0x0017: secp256r1 (P-256)
//   - 0x0018: secp384r1 (P-384)
//   - 0x0019: secp521r1 (P-521)
//   - 0x001D: x25519
//
// ServerParams format (RFC 5246 §7.4.3 / RFC 4492 §5.4):
//
//	curve_type   uint8  = 3 (named_curve; any other value is rejected)
//	named_curve  uint16
//	point_len    uint8
//	point        [point_len]byte  (uncompressed for P-curves; raw 32 bytes for X25519)
//
// ClientKeyExchange body (cke):
//
//	point_len    uint8
//	point        [point_len]byte  (client ephemeral public key)
//
// Pre-master secret: the X coordinate (P-curves) or raw output (X25519) of
// the ECDH shared secret, with leading zeros preserved to the curve's fixed size.
type ECDHEExchange struct{}

// NewECDHEExchange creates an ECDHEExchange.
func NewECDHEExchange() *ECDHEExchange {
	return &ECDHEExchange{}
}

// curveByID returns the crypto/ecdh curve for the given RFC 4492 NamedCurve ID.
func curveByID(id uint16) (ecdh.Curve, error) {
	switch id {
	case namedCurveP256:
		return ecdh.P256(), nil
	case namedCurveP384:
		return ecdh.P384(), nil
	case namedCurveP521:
		return ecdh.P521(), nil
	case namedCurveX25519:
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("ke: unsupported named curve 0x%04X: %w", id, errECDHEUnsupportedCurve)
	}
}

// ClientKeyExchange generates a client ephemeral keypair, computes the shared
// secret against the server's public key, and returns the CKE body and
// pre-master secret.
func (e *ECDHEExchange) ClientKeyExchange(serverParams []byte) (cke []byte, preMaster []byte, err error) {
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

	clientPriv, err := curve.GenerateKey(rand.Reader)
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
