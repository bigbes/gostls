package suites

import (
	"crypto/hmac"
	"errors"
	"hash"
)

// ErrEmptyLabel is returned by PRF when label is empty.
// RFC 5246 §5 requires a non-empty label to distinguish different derivations.
var ErrEmptyLabel = errors.New("suites/prf: label must not be empty")

// ErrZeroLength is returned by PRF when the requested output length is zero.
var ErrZeroLength = errors.New("suites/prf: requested output length must be greater than zero")

// pHash computes P_hash(secret, seed) as defined in RFC 5246 §5:
//
//	P_hash(secret, seed) =
//	    HMAC_hash(secret, A(1) || seed) ||
//	    HMAC_hash(secret, A(2) || seed) || ...
//
// where A(0) = seed and A(i) = HMAC_hash(secret, A(i-1)).
// The result is truncated to outLen bytes.
func pHash(newHash func() hash.Hash, secret, seed []byte, outLen int) []byte {
	hmacNew := func(key, msg []byte) []byte {
		h := hmac.New(newHash, key)
		h.Write(msg)
		return h.Sum(nil)
	}

	out := make([]byte, 0, outLen)
	a := seed // A(0) = seed
	for len(out) < outLen {
		a = hmacNew(secret, a) // A(i) = HMAC_hash(secret, A(i-1))
		out = append(out, hmacNew(secret, append(a, seed...))...)
	}
	return out[:outLen]
}

// PRF computes the TLS 1.2 pseudo-random function as defined in RFC 5246 §5:
//
//	PRF(secret, label, seed) = P_<hash>(secret, label || seed)
//
// The hash function is provided by newHash (e.g. sha256.New or sha512.New384).
// outLen specifies the number of output bytes requested.
//
// Returns ErrEmptyLabel if label is empty.
// Returns ErrZeroLength if outLen is zero.
func PRF(newHash func() hash.Hash, secret, label, seed []byte, outLen int) ([]byte, error) {
	if len(label) == 0 {
		return nil, ErrEmptyLabel
	}
	if outLen <= 0 {
		return nil, ErrZeroLength
	}

	// Concatenate label || seed as the PRF seed per RFC 5246 §5.
	fullSeed := make([]byte, len(label)+len(seed))
	copy(fullSeed, label)
	copy(fullSeed[len(label):], seed)

	return pHash(newHash, secret, fullSeed, outLen), nil
}
