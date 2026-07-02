package ke

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/bigmod"
)

// DHE wire format constants.
const (
	// dheMinPBits is the minimum allowed bit length for the DHE prime p. A
	// 2048-bit floor rejects the standardized 1024-bit groups broken by
	// precomputation (Logjam, CVE-2015-4000). The client advertises only the
	// RFC 7919 ffdhe2048/ffdhe3072 groups, so a compliant server never sends a
	// smaller prime.
	dheMinPBits = 2048

	// dheU16PrefixLen is the size of the 2-byte big-endian length prefix used
	// in both the ServerKeyExchange and ClientKeyExchange DHE wire formats.
	dheU16PrefixLen = 2

	// dheMinG is the minimum allowed value for the DHE generator g.
	dheMinG = 2

	// u16ShiftBits is the number of bits to shift when reading/writing a 2-byte
	// big-endian length field (high byte).
	u16ShiftBits = 8

	// ckeYcLenShift is the bit-shift for the high byte of the 2-byte CKE Yc length field.
	ckeYcLenShift = 8
)

// Sentinel errors for DHE parameter validation and parsing.
var (
	errDHETrailingBytes = errors.New("ke: DHE: trailing bytes in serverParams")
	errDHETooShort      = errors.New("too short for length prefix: need 2")
	errDHETruncated     = errors.New("truncated")
	errDHEPTooShort     = errors.New("ke: DHE: p is too short: minimum is 2048 bits")
	errDHEPEven         = errors.New("ke: DHE: p is even — not a valid DH prime")
	errDHEGTooSmall     = errors.New("ke: DHE: g must be ≥ 2")
	errDHEYsLow         = errors.New("ke: DHE: Ys out of range: must be > 1")
	errDHEYsHigh        = errors.New("ke: DHE: Ys out of range: must be < p-1")
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
//   - p must be at least 2048 bits (256 bytes).
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

	cke = make([]byte, dheU16PrefixLen+len(YcPadded))
	cke[0] = byte(len(YcPadded) >> ckeYcLenShift)
	cke[1] = byte(len(YcPadded))
	copy(cke[dheU16PrefixLen:], YcPadded)

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
		return nil, nil, nil, fmt.Errorf("ke: DHE: trailing bytes in serverParams: %d: %w",
			len(rest), errDHETrailingBytes)
	}

	return p, g, Ys, nil
}

// readU16LenPrefixed reads a 2-byte big-endian length followed by that many bytes.
func readU16LenPrefixed(b []byte) (data, rest []byte, err error) {
	if len(b) < dheU16PrefixLen {
		return nil, nil, fmt.Errorf("too short for length prefix: need 2, have %d: %w", len(b), errDHETooShort)
	}

	n := int(b[0])<<u16ShiftBits | int(b[1])

	b = b[dheU16PrefixLen:]

	if len(b) < n {
		return nil, nil, fmt.Errorf("truncated: need %d bytes, have %d: %w", n, len(b), errDHETruncated)
	}

	return b[:n], b[n:], nil
}

// validateDHEParams enforces the fail-fast rules described in the type comment.
//
// math/big is used here for public comparisons only (p, g, Ys are all from
// the server's ServerKeyExchange message — public data). No secret material
// is touched in this function.
func validateDHEParams(pBytes, gBytes, YsBytes []byte) error {
	// p must be at least dheMinPBits (2048) bits.
	pBits := len(pBytes) * bitsPerByte

	if pBits < dheMinPBits {
		return fmt.Errorf("ke: DHE: p is too short: %d bits, minimum is %d: %w", pBits, dheMinPBits, errDHEPTooShort)
	}

	// p must be odd (necessary condition for primality; primes > 2 are odd).
	// math/big used for public data only.
	if len(pBytes) == 0 || pBytes[len(pBytes)-1]&1 == 0 {
		return fmt.Errorf("%w", errDHEPEven)
	}

	// g must be ≥ 2. math/big used for public data only.
	gBig := new(big.Int).SetBytes(gBytes)
	if gBig.Cmp(big.NewInt(dheMinG)) < 0 {
		return fmt.Errorf("ke: DHE: g must be ≥ 2, got %s: %w", gBig, errDHEGTooSmall)
	}

	// Parse Ys and p for bounds check. math/big used for public data only.
	pBig := new(big.Int).SetBytes(pBytes)
	YsBig := new(big.Int).SetBytes(YsBytes)

	// Ys must be > 1 (not the identity element).
	one := big.NewInt(1)
	if YsBig.Cmp(one) <= 0 {
		return fmt.Errorf("ke: DHE: Ys out of range: must be > 1, got %s: %w", YsBig, errDHEYsLow)
	}

	// Ys must be < p-1 (p-1 has order 2, a small-subgroup element for safe primes).
	pMinus1 := new(big.Int).Sub(pBig, one)
	if YsBig.Cmp(pMinus1) >= 0 {
		return fmt.Errorf("%w", errDHEYsHigh)
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
			return nil, fmt.Errorf("ke: DHE: load base into modulus: %w (original: %w)", err2, err)
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
