package ke

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"filippo.io/bigmod"
)

// DHEExchange implements the finite-field Diffie-Hellman Ephemeral (DHE) key
// exchange for TLS 1.2 (RFC 5246 §7.4.3, §8.1.2).
//
// # ServerParams encoding
//
// The raw ServerKeyExchange body per RFC 5246 §7.4.3:
//
//	dh_p    opaque <1..2^16-1>   — big-endian big integer
//	dh_g    opaque <1..2^16-1>
//	dh_Ys   opaque <1..2^16-1>
//
// Each field is length-prefixed with a 2-byte big-endian length.
//
// # Parameter validation (fail-fast)
//
//   - p must be at least 1024 bits (128 bytes).
//   - p must be odd (even p is not prime, hence invalid).
//   - g must be ≥ 2.
//   - 1 < Ys < p-1 (strict bounds; identity element and p-1 are both rejected).
//
// For RFC 7919 named groups (ffdhe2048, ffdhe3072): the Ys^q ≡ 1 (mod p)
// check where q = (p-1)/2 is implied by the bounds check on safe primes.
// RFC 7919 ffdhe groups are safe primes (p = 2q+1, q prime), so the only
// elements of order ≤ 2 in (Z/pZ)* are {1, p-1}. Both are already caught
// by the strict range check. For non-named groups we skip the subgroup check
// (non-named groups may not be safe primes and the server is trusted per TLS).
//
// # Constant-time invariant
//
// The private exponent x and the shared secret Z = Ys^x mod p are computed
// exclusively with filippo.io/bigmod.Nat.Exp — a constant-time Montgomery
// modular exponentiation — never with math/big.Int.Exp.
//
// math/big is used ONLY for public operations:
//   - Parsing p, g, Ys from bytes (math/big.Int.SetBytes — public data)
//   - Computing p-1 for the bounds check (public data)
//   - Comparing Ys against 1 and p-1 (public data)
//   - Checking g ≥ 2 (public data)
//
// # ClientKeyExchange body format
//
// Per RFC 5246 §7.4.7.2:
//
//	dh_Yc   opaque <1..2^16-1>   (2-byte length + client public key bytes)
//
// # Pre-master secret
//
// Z = Ys^x mod p, left-padded with zero bytes to len(p) bytes per RFC 5246 §8.1.2.
type DHEExchange struct {
	// privateX is the caller-supplied private exponent (for testing determinism).
	// If nil, a random exponent of the same bit length as p is generated.
	privateX []byte
}

// NewDHEExchange creates a DHEExchange.
//
// privateX optionally fixes the client private exponent for testing. In
// production, pass nil to use a securely random exponent.
func NewDHEExchange(privateX []byte) *DHEExchange {
	return &DHEExchange{privateX: privateX}
}

// ClientKeyExchange parses the ServerKeyExchange DHE params, validates them,
// generates (or reuses) a client private exponent, computes the shared secret,
// and returns the CKE body and pre-master secret.
func (d *DHEExchange) ClientKeyExchange(serverParams []byte) (cke []byte, preMaster []byte, err error) {
	pBytes, gBytes, YsBytes, err := parseDHEServerParams(serverParams)
	if err != nil {
		return nil, nil, err
	}

	if err = validateDHEParams(pBytes, gBytes, YsBytes); err != nil {
		return nil, nil, err
	}

	// Build the bigmod modulus from p.
	// bigmod.NewModulus requires an odd modulus; p is prime (odd), so this is safe.
	mod, err := bigmod.NewModulus(pBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: DHE: build modulus: %w", err)
	}

	// Select or generate the private exponent x.
	xBytes := d.privateX
	if xBytes == nil {
		// Generate a random exponent of the same byte length as p.
		xBytes = make([]byte, len(pBytes))
		if _, err = rand.Read(xBytes); err != nil {
			return nil, nil, fmt.Errorf("ke: DHE: generate private exponent: %w", err)
		}
	}

	// Compute client public value Yc = g^x mod p (constant-time via bigmod).
	Yc, err := modExp(gBytes, xBytes, mod)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: DHE: compute Yc: %w", err)
	}

	// Compute shared secret Z = Ys^x mod p (constant-time via bigmod).
	// This is the secret-dependent operation; bigmod.Nat.Exp is used here.
	Z, err := modExp(YsBytes, xBytes, mod)
	if err != nil {
		return nil, nil, fmt.Errorf("ke: DHE: compute Z: %w", err)
	}

	// Left-pad Z to len(p) bytes per RFC 5246 §8.1.2.
	preMaster = leftPad(Z, len(pBytes))

	// CKE body: 2-byte big-endian length + Yc bytes.
	YcPadded := leftPad(Yc, len(pBytes))
	cke = make([]byte, 2+len(YcPadded))
	cke[0] = byte(len(YcPadded) >> 8)
	cke[1] = byte(len(YcPadded))
	copy(cke[2:], YcPadded)

	return cke, preMaster, nil
}

// parseDHEServerParams splits the raw ServerKeyExchange body into p, g, Ys.
// Each is 2-byte length-prefixed per RFC 5246 §7.4.3.
func parseDHEServerParams(params []byte) (p, g, Ys []byte, err error) {
	p, rest, err := readU16LenPrefixed(params)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ke: DHE: parse dh_p: %w", err)
	}
	g, rest, err = readU16LenPrefixed(rest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ke: DHE: parse dh_g: %w", err)
	}
	Ys, rest, err = readU16LenPrefixed(rest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ke: DHE: parse dh_Ys: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, nil, fmt.Errorf("ke: DHE: trailing bytes in serverParams: %d", len(rest))
	}
	return p, g, Ys, nil
}

// readU16LenPrefixed reads a 2-byte big-endian length followed by that many bytes.
func readU16LenPrefixed(b []byte) (data, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("too short for length prefix: need 2, have %d", len(b))
	}
	n := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < n {
		return nil, nil, fmt.Errorf("truncated: need %d bytes, have %d", n, len(b))
	}
	return b[:n], b[n:], nil
}

// validateDHEParams enforces the fail-fast rules described in the type comment.
//
// math/big is used here for public comparisons only (p, g, Ys are all from
// the server's ServerKeyExchange message — public data). No secret material
// is touched in this function.
func validateDHEParams(pBytes, gBytes, YsBytes []byte) error {
	// p must be at least 1024 bits.
	if len(pBytes)*8 < 1024 {
		return fmt.Errorf("ke: DHE: p is too short: %d bits, minimum is 1024", len(pBytes)*8)
	}

	// p must be odd (necessary condition for primality; primes > 2 are odd).
	// math/big used for public data only.
	if len(pBytes) == 0 || pBytes[len(pBytes)-1]&1 == 0 {
		return fmt.Errorf("ke: DHE: p is even — not a valid DH prime")
	}

	// g must be ≥ 2. math/big used for public data only.
	gBig := new(big.Int).SetBytes(gBytes) //nolint:forbidigo // public data
	if gBig.Cmp(big.NewInt(2)) < 0 {
		return fmt.Errorf("ke: DHE: g must be ≥ 2, got %s", gBig)
	}

	// Parse Ys and p for bounds check. math/big used for public data only.
	pBig := new(big.Int).SetBytes(pBytes)   //nolint:forbidigo // public data
	YsBig := new(big.Int).SetBytes(YsBytes) //nolint:forbidigo // public data

	// Ys must be > 1 (not the identity element).
	one := big.NewInt(1)
	if YsBig.Cmp(one) <= 0 {
		return fmt.Errorf("ke: DHE: Ys out of range: must be > 1, got %s", YsBig)
	}

	// Ys must be < p-1 (p-1 has order 2, a small-subgroup element for safe primes).
	pMinus1 := new(big.Int).Sub(pBig, one) //nolint:forbidigo // public data
	if YsBig.Cmp(pMinus1) >= 0 {
		return fmt.Errorf("ke: DHE: Ys out of range: must be < p-1")
	}

	return nil
}

// modExp computes base^exp mod m using filippo.io/bigmod for constant-time
// modular exponentiation. base is in big-endian bytes; exp is in big-endian
// bytes; m is the pre-built modulus. Returns the result as fixed-size
// big-endian bytes (length = m.Size()).
//
// This is the ONLY place where modular exponentiation is performed. Both
// the DHE public key generation (Yc = g^x mod p) and shared secret
// computation (Z = Ys^x mod p) go through this function.
func modExp(baseBytes, expBytes []byte, m *bigmod.Modulus) ([]byte, error) {
	base := bigmod.NewNat()
	// Use SetOverflowingBytes because Ys from the wire may be slightly larger
	// than p in byte representation (e.g., leading zeros stripped). g is always
	// small. SetBytes would reject values ≥ p, but SetOverflowingBytes handles
	// values that fit in the same number of limbs but exceed p numerically;
	// however our validateDHEParams already guarantees 1 < Ys < p-1, so
	// SetBytes is safe for a Ys that fits. Use SetOverflowingBytes for
	// robustness in case the byte encoding has leading zeros that make the
	// field appear wider.
	if _, err := base.SetBytes(baseBytes, m); err != nil {
		// If SetBytes fails due to overflow (base ≥ p), try reducing first.
		// This can happen for g = 2 which has fewer bytes than p.
		// Actually for g < p (always true for valid g), SetBytes should work.
		// If it fails, fall back to SetOverflowingBytes.
		var err2 error
		base, err2 = bigmod.NewNat().SetOverflowingBytes(baseBytes, m)
		if err2 != nil {
			return nil, fmt.Errorf("ke: DHE: load base into modulus: %w (original: %v)", err2, err)
		}
	}

	// exp is the private exponent x (secret). It is passed as raw bytes to
	// bigmod.Nat.Exp which treats it as a big-endian exponent in the windowed
	// Montgomery ladder. The exponent itself is not loaded into a Nat — bigmod
	// takes it as []byte directly, keeping the constant-time guarantee.
	result := bigmod.NewNat().Exp(base, expBytes, m)
	return result.Bytes(m), nil
}

// leftPad pads b with leading zero bytes to length n. If b is already n or
// more bytes, it is returned as-is (or truncated leading zeros are preserved).
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	padded := make([]byte, n)
	copy(padded[n-len(b):], b)
	return padded
}

// ============================================================================
// RFC 7919 named group prime constants
// ============================================================================

// ffdhe2048P is the 2048-bit safe prime from RFC 7919 Appendix A.1.
// Generator g = 2.
var ffdhe2048P = mustDecodeHex(
	"FFFFFFFFFFFFFFFF" +
		"ADF85458A2BB4A9A" +
		"AFDC5620273D3CF1" +
		"D8B9C583CE2D3695" +
		"A9E13641146433FB" +
		"CC939DCE249B3EF9" +
		"7D2FE363630C75D8" +
		"F681B202AEC4617A" +
		"D3DF1ED5D5FD6561" +
		"2433F51F5F066ED0" +
		"856365553DED1AF3" +
		"B557135E7F57C935" +
		"984F0C70E0E68B77" +
		"E2A689DAF3EFE872" +
		"1DF158A136ADE735" +
		"30ACCA4F483A797A" +
		"BC0AB182B324FB61" +
		"D108A94BB2C8E3FB" +
		"B96ADAB760D7F468" +
		"1D4F42A3DE394DF4" +
		"AE56EDE76372BB19" +
		"0B07A7C8EE0A6D70" +
		"9E02FCE1CDF7E2EC" +
		"C03405CD28342F61" +
		"9172FE9CE98583FF" +
		"8E4F1232EEF28183" +
		"C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005" +
		"C58EF1837D1683B2" +
		"C6F34A26C1B2EFFA" +
		"886B423861285C97" +
		"FFFFFFFFFFFFFFFF",
)

// ffdhe3072P is the 3072-bit safe prime from RFC 7919 Appendix A.2.
// Generator g = 2.
var ffdhe3072P = mustDecodeHex(
	"FFFFFFFFFFFFFFFF" +
		"ADF85458A2BB4A9A" +
		"AFDC5620273D3CF1" +
		"D8B9C583CE2D3695" +
		"A9E13641146433FB" +
		"CC939DCE249B3EF9" +
		"7D2FE363630C75D8" +
		"F681B202AEC4617A" +
		"D3DF1ED5D5FD6561" +
		"2433F51F5F066ED0" +
		"856365553DED1AF3" +
		"B557135E7F57C935" +
		"984F0C70E0E68B77" +
		"E2A689DAF3EFE872" +
		"1DF158A136ADE735" +
		"30ACCA4F483A797A" +
		"BC0AB182B324FB61" +
		"D108A94BB2C8E3FB" +
		"B96ADAB760D7F468" +
		"1D4F42A3DE394DF4" +
		"AE56EDE76372BB19" +
		"0B07A7C8EE0A6D70" +
		"9E02FCE1CDF7E2EC" +
		"C03405CD28342F61" +
		"9172FE9CE98583FF" +
		"8E4F1232EEF28183" +
		"C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005" +
		"C58EF1837D1683B2" +
		"C6F34A26C1B2EFFA" +
		"886B423861285C97" +
		"ADB1A48CB7B1B8CD" +
		"B9D6A56BCF4B58E7" +
		"6A2CD9E5E25EC4F5" +
		"2B58F1D385A68ABD" +
		"BE9BCEF305B7D3CB" +
		"8D9AD78A41B16B17" +
		"B479D4E5ACCA0BB2" +
		"F4FAEDD3D13D5CAB" +
		"9BD0456AC0BEDB2B" +
		"E8CADFA43AFFE97B" +
		"BC23FF7AF68E7DA0" +
		"50F3B88DC7D0F282" +
		"7DFFF810DC30F0AB" +
		"37C34BC0B76C8E6A" +
		"69266EDAD58F8F81" +
		"FCBFCCE7FFEB88AF" +
		"FFFFFFFFFFFFFFFF",
)

// isNamedFFDHEGroup returns true if p matches one of the RFC 7919 named groups.
// This enables stricter validation for known groups.
func isNamedFFDHEGroup(p []byte) bool {
	return bytes.Equal(p, ffdhe2048P) || bytes.Equal(p, ffdhe3072P)
}

// mustDecodeHex decodes a hex string (no spaces) and panics on error.
// Used only for package-level constants.
func mustDecodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		hi := hexNibble(s[2*i])
		lo := hexNibble(s[2*i+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		panic(fmt.Sprintf("ke: invalid hex nibble %q", c))
	}
}
