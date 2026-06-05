package suites

// isOpenSSLGostEngineBuild returns false when the openssl gost-engine
// placeholder suite registrations are not active (i.e. not built with
// -tags "openssl openssl_gost_engine").
func isOpenSSLGostEngineBuild() bool { return false }
