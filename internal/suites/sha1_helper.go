package suites

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is used only for legacy CBC-SHA suites per RFC 5246
	"hash"
)

// sha1New returns a new SHA-1 hash. Used exclusively for legacy CBC-SHA suites
// (ECDHE-*-AES*-SHA, DHE-RSA-AES*-SHA, AES*-SHA) where the IANA definition
// mandates HMAC-SHA1 as the MAC. No new suites use SHA-1.
func sha1New() hash.Hash {
	return sha1.New()
}
