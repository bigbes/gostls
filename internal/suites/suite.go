// Package suites defines the TLS 1.2 cipher suite registry, PRF, and key
// schedule for github.com/bigbes/gostls.
//
// This package is data-only: it provides suite metadata and cryptographic
// derivation functions. It does not produce Protectors (record-layer wiring
// lives in Phase 8).
package suites

import "hash"

// KexKind identifies the key exchange algorithm used by a suite.
type KexKind uint8

const (
	KexRSA          KexKind = iota // RSA static key exchange.
	KexDHE                         // ephemeral Diffie-Hellman.
	KexECDHE                       // ephemeral Elliptic-Curve Diffie-Hellman.
	KexGOST2001                    // GOST R 34.10-2001 VKO key agreement (RFC 4357, RFC 9189).
	KexGOST2012_256                // GOST R 34.10-2012 VKO key agreement, 256-bit KEK (RFC 7836, RFC 9189).
	KexGOST2018_256                // GOST 2018 key transport (RFC 9367 suites 0xC100 / 0xC101).
)

// AuthKind identifies the authentication algorithm used by a suite.
type AuthKind uint8

const (
	AuthRSA          AuthKind = iota // RSA certificate authentication.
	AuthECDSA                        // ECDSA certificate authentication.
	AuthAnonymous                    // anonymous (reserved; no registered suite uses this).
	AuthGOST2001                     // GOST R 34.10-2001 certificate authentication.
	AuthGOST2012_256                 // GOST R 34.10-2012 (256-bit) certificate authentication.
)

// CipherSpec describes the symmetric cipher used by a suite.
//
// ExplicitIVLen is the number of bytes prepended to the ciphertext on the wire
// for the per-record explicit IV or nonce:
//   - CBC suites: ExplicitIVLen = block size (random IV per record).
//   - AES-GCM suites: ExplicitIVLen = 8 (64-bit sequence-derived nonce).
//   - CHACHA20-POLY1305 suites: ExplicitIVLen = 0. Per RFC 7905, the 12-byte
//     nonce is derived entirely from the implicit write_IV XORed with the 64-bit
//     sequence number (padded on the left to 12 bytes). No bytes are prepended to
//     the wire record — the nonce is fully implicit. Phase 8 must handle this
//     differently from AES-GCM when assembling Protectors.
//
// TagLen is the AEAD authentication tag length (0 for MAC-based suites).
type CipherSpec struct {
	Name          string // e.g. "AES-128-CBC", "AES-256-GCM", "CHACHA20-POLY1305".
	KeyLen        int    // encryption key length in bytes.
	FixedIVLen    int    // implicit IV / salt length in bytes.
	ExplicitIVLen int    // per-record explicit IV / nonce length in bytes (0 for ChaCha20).
	AEAD          bool   // true for AEAD suites; false for MAC-then-encrypt suites.
	TagLen        int    // AEAD tag length in bytes (0 for non-AEAD).
}

// MACSpec describes the MAC algorithm used by a MAC-then-encrypt suite.
// For AEAD suites all fields are zero/nil.
type MACSpec struct {
	Hash   func() hash.Hash // nil for AEAD suites.
	KeyLen int              // MAC key length in bytes.
	MACLen int              // MAC output length in bytes.
}

// PRFSpec describes the PRF hash used for this suite (RFC 5246 §5).
// Hash is the factory for the underlying HMAC hash; SHA-256 for most suites,
// SHA-384 for *-SHA384 suites.
type PRFSpec struct {
	Hash func() hash.Hash
}

// Suite is a fully described TLS 1.2 cipher suite.
type Suite struct {
	ID     uint16
	Name   string // OpenSSL-style name.
	KX     KexKind
	Auth   AuthKind
	Cipher CipherSpec
	MAC    MACSpec
	PRF    PRFSpec
}

// registry holds all registered suites, keyed by IANA ID.
var registry = map[uint16]*Suite{}

// nameIndex provides fast lookup by OpenSSL name.
var nameIndex = map[string]*Suite{}

// register adds a suite to the registry. It panics on duplicate ID or name.
func register(s *Suite) {
	if _, dup := registry[s.ID]; dup {
		panic("suites: duplicate suite ID " + s.Name)
	}

	if _, dup := nameIndex[s.Name]; dup {
		panic("suites: duplicate suite name " + s.Name)
	}

	registry[s.ID] = s
	nameIndex[s.Name] = s
}

// Lookup returns the Suite with the given IANA ID, or (nil, false) if not registered.
func Lookup(id uint16) (*Suite, bool) {
	s, ok := registry[id]
	return s, ok
}

// LookupByName returns the Suite with the given OpenSSL name, or (nil, false).
func LookupByName(name string) (*Suite, bool) {
	s, ok := nameIndex[name]
	return s, ok
}

// All returns all registered suites in an unspecified but stable order.
func All() []*Suite {
	out := make([]*Suite, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}

	return out
}
