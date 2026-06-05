// Package tls implements a TLS 1.2 client with a crypto/tls-shaped API.
//
// This implementation is TLS 1.2 only. TLS 1.3, session resumption,
// renegotiation, ALPN extensibility, and 0-RTT are not supported.
// There is no server role.
//
// Cipher suite availability: AES-128-CBC, AES-256-CBC, AES-128-GCM,
// AES-256-GCM, and CHACHA20-POLY1305 (RFC 7905) suites are included by
// default. GOST suites are registered in every build (clean-room backend) but
// are not in the default negotiation set; request them explicitly via
// Config.CipherSuites.
package gostls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/bigbes/gostls/internal/handshake"
)

// Certificate holds a certificate and its private key.
// Mirrors crypto/tls.Certificate in structure.
type Certificate struct {
	// Certificate is the parsed certificate (optional; used for display only).
	Certificate *x509.Certificate
	// RawCertificate holds the DER-encoded certificate.
	RawCertificate []byte
	// PrivateKey is the private key corresponding to the certificate's public
	// key. Required when using mutual TLS (client authentication).
	PrivateKey crypto.PrivateKey
}

// Config is the TLS 1.2 client configuration. Field names and semantics
// mirror crypto/tls.Config where the feature exists in stdlib.
//
// Only a subset of crypto/tls.Config is implemented.
type Config struct {
	// RootCAs defines the set of root certificate authorities used to verify
	// the server's certificate. If nil, the host's default root CA set is used.
	//
	// RootCAs and RootCAPEMs are mutually exclusive. Setting both is an error.
	RootCAs *x509.CertPool

	// RootCAPEMs holds PEM-encoded trusted root certificates. Each element may
	// be a single PEM block or a concatenation of multiple PEM blocks. Only
	// CERTIFICATE-typed blocks are used; other block types (keys, etc.) are
	// ignored, but each element must contain at least one CERTIFICATE block.
	//
	// This field is the preferred way to supply an in-memory trust store when
	// using the openssl backend, where RootCAs is not supported.
	//
	// RootCAs and RootCAPEMs are mutually exclusive. Setting both is an error.
	RootCAPEMs [][]byte

	// Certificates contains client certificates for mutual TLS (mTLS) client
	// authentication. When the server sends a CertificateRequest during the
	// handshake, the first entry in this slice is offered. If the server's
	// requested signature algorithms do not include any algorithm supported by
	// the key, an empty Certificate message is sent (which is valid per RFC 5246).
	//
	// Each Certificate.PrivateKey must be *rsa.PrivateKey or *ecdsa.PrivateKey;
	// any other type causes Handshake() to return a hard error. If
	// Certificate.Certificate is nil, RawCertificate is parsed on demand; an
	// empty RawCertificate is a hard error.
	Certificates []Certificate

	// ServerName is the server name sent in the SNI extension and used for
	// certificate verification. If empty and InsecureSkipVerify is false,
	// certificate verification will fail because x509 requires a DNS name.
	ServerName string

	// CipherSuites specifies the list of cipher suite IDs to offer in the
	// ClientHello. If nil, all registered suites whose cipher is AES-128-CBC,
	// AES-256-CBC, AES-128-GCM, AES-256-GCM, or CHACHA20-POLY1305 are offered.
	CipherSuites []uint16

	// InsecureSkipVerify controls whether the client verifies the server's
	// certificate chain and host name.
	//
	// WARNING: Setting this to true disables all certificate authentication.
	// The connection is susceptible to man-in-the-middle attacks. Use only
	// for debugging or with VerifyPeerCertificate performing custom verification.
	InsecureSkipVerify bool

	// VerifyPeerCertificate is called after normal certificate verification
	// (or instead of it if InsecureSkipVerify is true). The first argument is
	// the raw DER bytes of the certificates provided by the server. The second
	// is the verified chains (empty when InsecureSkipVerify is true).
	//
	// A non-nil error aborts the handshake with bad_certificate.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// Rand provides the source of entropy for random values used during the
	// handshake: client random, client ephemeral keys, RSA pre-master secret,
	// and CBC per-record IVs.
	//
	// If nil, crypto/rand.Reader is used (the correct default for production).
	// Override in tests to produce deterministic handshake bytes.
	Rand io.Reader
}

// rand returns the configured random source, defaulting to crypto/rand.Reader.
func (c *Config) rand() io.Reader {
	if c != nil && c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

// rootCAPool returns the certificate pool to use for server verification.
//
// Priority rules:
//   - If both RootCAs and RootCAPEMs are set, an error is returned.
//   - If only RootCAs is set, it is returned as-is.
//   - If only RootCAPEMs is set, a new pool is built from those PEM blocks.
//   - If neither is set, nil is returned (the backend uses the OS trust store).
//
// When c is nil, (nil, nil) is returned.
func (c *Config) rootCAPool() (*x509.CertPool, error) {
	if c == nil {
		return nil, nil
	}
	if c.RootCAs != nil && len(c.RootCAPEMs) > 0 {
		return nil, fmt.Errorf("tls: Config.RootCAs and Config.RootCAPEMs are mutually exclusive; set only one")
	}
	if c.RootCAs != nil {
		return c.RootCAs, nil
	}
	if len(c.RootCAPEMs) == 0 {
		return nil, nil
	}

	pool := x509.NewCertPool()
	for i, block := range c.RootCAPEMs {
		if !pool.AppendCertsFromPEM(block) {
			// AppendCertsFromPEM returns false when no CERTIFICATE blocks were
			// found. Other block types are silently ignored by AppendCertsFromPEM,
			// but an element with no certificates at all is a misconfiguration.
			//
			// We need to distinguish "no blocks at all" from "blocks present but
			// no CERTIFICATE type". Decode to check.
			hasCertBlock := false
			rest := block
			for {
				var pemBlock *pem.Block
				pemBlock, rest = pem.Decode(rest)
				if pemBlock == nil {
					break
				}
				if pemBlock.Type == "CERTIFICATE" {
					hasCertBlock = true
					break
				}
			}
			if hasCertBlock {
				// There was a CERTIFICATE block but it failed to parse.
				return nil, fmt.Errorf("tls: RootCAPEMs[%d]: failed to parse certificate", i)
			}
			return nil, fmt.Errorf("tls: RootCAPEMs[%d]: no CERTIFICATE blocks found", i)
		}
	}
	return pool, nil
}

// clientCerts validates Config.Certificates and converts them to
// []handshake.ClientCertificate.
//
// Validation rules (hard errors — fail loud at handshake start):
//   - PrivateKey must be *rsa.PrivateKey or *ecdsa.PrivateKey.
//   - RawCertificate must be non-empty. It is what gets placed on the wire;
//     a pre-populated Certificate field is auxiliary metadata and does not
//     substitute for the DER bytes.
//   - When Certificate is nil, RawCertificate is parsed to populate it.
//
// Returns (nil, nil) when Certificates is empty.
func (c *Config) clientCerts() ([]handshake.ClientCertificate, error) {
	if len(c.Certificates) == 0 {
		return nil, nil
	}

	result := make([]handshake.ClientCertificate, 0, len(c.Certificates))
	for i, cert := range c.Certificates {
		// Validate key type.
		switch cert.PrivateKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			// OK
		default:
			return nil, fmt.Errorf("tls: Certificates[%d].PrivateKey has unsupported type %T; want *rsa.PrivateKey or *ecdsa.PrivateKey", i, cert.PrivateKey)
		}

		// RawCertificate is what gets emitted on the wire; validate
		// unconditionally, regardless of whether Certificate is pre-parsed.
		// A nil/empty RawCertificate with a non-nil Certificate would otherwise
		// produce a malformed zero-length certificate entry (RFC 5246 §7.4.2
		// requires each entry in the list to be at least 1 byte).
		if len(cert.RawCertificate) == 0 {
			return nil, fmt.Errorf("tls: Certificates[%d].RawCertificate is empty", i)
		}

		if cert.Certificate == nil {
			parsed, err := x509.ParseCertificate(cert.RawCertificate)
			if err != nil {
				return nil, fmt.Errorf("tls: Certificates[%d].RawCertificate: %w", i, err)
			}
			cert.Certificate = parsed
		}

		result = append(result, handshake.ClientCertificate{
			RawCertificate: cert.RawCertificate,
			PrivateKey:     cert.PrivateKey,
			Certificate:    cert.Certificate,
		})
	}
	return result, nil
}
