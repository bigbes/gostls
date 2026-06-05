// Package ke implements TLS 1.2 key exchange methods.
//
// Each Exchange implementation produces a ClientKeyExchange message body (cke)
// and the pre-master secret (preMaster) used by suites.MasterSecret.
//
// Implementations: ECDHEExchange (P-256/P-384/P-521/X25519), RSAExchange,
// DHEExchange. GOST VKO is Phase 6.
package ke

// Exchange is the interface implemented by all TLS 1.2 key exchange methods.
//
// ServerParams encoding per key exchange type:
//   - ECDHE: raw body of the ServerKeyExchange message, starting with
//     curve_type (1 byte) then named_curve (2 bytes) then server public key
//     length-prefixed (1 byte). Defined in RFC 5246 §7.4.3 / RFC 4492 §5.4.
//   - DHE: raw body of the ServerKeyExchange message: dh_p (2-byte length +
//     data), dh_g (2-byte length + data), dh_Ys (2-byte length + data).
//     Defined in RFC 5246 §7.4.3.
//   - RSA: RSAExchange holds *rsa.PublicKey directly; ServerParams is ignored
//     (pass nil). The server public key comes from the server certificate, not
//     from a ServerKeyExchange message.
type Exchange interface {
	// ClientKeyExchange computes the client's key-exchange contribution.
	//
	// cke is the raw ClientKeyExchange message body sent on the wire.
	// preMaster is the pre-master secret fed into MasterSecret.
	// err is non-nil if the server parameters are invalid or crypto fails.
	ClientKeyExchange(serverParams []byte) (cke []byte, preMaster []byte, err error)
}
