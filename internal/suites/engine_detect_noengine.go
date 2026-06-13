package suites

// IsOpenSSLGostEngineBuild returns false when the openssl gost-engine
// placeholder suite registrations are not active (i.e. not built with
// -tags "openssl openssl_gost_engine").
func IsOpenSSLGostEngineBuild() bool { return false }
