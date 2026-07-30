//go:build !openssl_gost_engine

package suites

// IsGOSTBuild reports whether the pure-Go clean-room GOST suites are registered.
// They are registered in every build except -tags openssl_gost_engine (where the
// OpenSSL gost-engine placeholder suites take over the same IANA IDs).
func IsGOSTBuild() bool { return true }
