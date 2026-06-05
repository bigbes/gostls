package handshake

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/bigbes/gostcrypto/x509gost"
)

// ErrGOSTRootsRequired is returned when the server presents a GOST-signed
// certificate but ClientParams.GOSTRoots is empty. Set GOSTRoots (a
// []*x509gost.Certificate) before calling Handshake, or set
// InsecureSkipVerify to bypass verification entirely.
var ErrGOSTRootsRequired = errors.New("tls: GOST-signed server certificate but no GOSTRoots configured")

// parseAndVerifyLeaf parses the leaf certificate DER and verifies the chain.
// GOST-signed certs are parsed and verified via the x509gost package; other
// certs fall back to stdlib x509. Returns the stdlib-shaped leaf for the
// caller (signature-algorithm-agnostic transcript / name verification).
//
// When gc.HasGOSTPubKey is true, c.gostLeaf is set to the *x509gost.Certificate
// so that buildGOSTExchange can retrieve the server public key without
// re-parsing. Certs signed by a non-GOST CA but carrying a GOST pubkey (common
// in test fixtures and in deployments with a shared RSA CA) reach this branch:
// chain verification is stdlib, KEX pubkey still comes from x509gost.
func parseAndVerifyLeaf(c *ClientState, rawLeaf []byte) (*x509.Certificate, [][]*x509.Certificate, error) {
	gc, err := x509gost.ParseCertificate(rawLeaf)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server leaf certificate: %w", err)
	}
	leafCert := gc.Stdlib

	if gc.HasGOSTPubKey {
		c.gostLeaf = gc
	}

	if c.params.InsecureSkipVerify {
		return leafCert, nil, nil
	}

	if gc.IsGOST {
		roots, err := extractGOSTRoots(c.params.GOSTRoots)
		if err != nil {
			return nil, nil, err
		}
		opts := x509gost.VerifyOptions{
			GOSTRoots:   roots,
			DNSName:     c.params.ServerName,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := gc.Verify(opts); err != nil {
			return nil, nil, fmt.Errorf("GOST certificate verification failed: %w", err)
		}
		// x509gost.Verify returns chains of *x509gost.Certificate; the
		// ClientState callback contract expects stdlib chains. For now we
		// surface nil chains on the GOST path; VerifyPeerCertificate still
		// receives the raw DER bytes and can reconstruct as needed.
		return leafCert, nil, nil
	}

	// Non-GOST signature (including GOST pubkey + RSA CA): use stdlib
	// verification.
	opts := x509.VerifyOptions{
		Roots:       c.params.RootCAs,
		DNSName:     c.params.ServerName,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	chains, err := leafCert.Verify(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate verification failed: %w", err)
	}
	return leafCert, chains, nil
}

// extractGOSTRoots asserts params.GOSTRoots to the expected concrete type.
// GOSTRoots is typed as any on ClientParams so the field signature does not
// force every importer of the package to depend on x509gost.
func extractGOSTRoots(v any) ([]*x509gost.Certificate, error) {
	if v == nil {
		return nil, ErrGOSTRootsRequired
	}
	roots, ok := v.([]*x509gost.Certificate)
	if !ok {
		return nil, fmt.Errorf("tls: ClientParams.GOSTRoots has wrong type %T, want []*x509gost.Certificate", v)
	}
	if len(roots) == 0 {
		return nil, ErrGOSTRootsRequired
	}
	return roots, nil
}
