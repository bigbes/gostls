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

// parseAndVerifyLeaf verifies a server certificate given only the leaf DER,
// with no server-supplied intermediates. It is a thin wrapper over
// parseAndVerifyChain retained for callers (and tests) that hold just the leaf.
func parseAndVerifyLeaf(c *ClientState, rawLeaf []byte) (*x509.Certificate, [][]*x509.Certificate, error) {
	return parseAndVerifyChain(c, [][]byte{rawLeaf})
}

// parseAndVerifyChain parses the leaf certificate DER (rawCerts[0]) and verifies
// the chain, using any server-supplied intermediates (rawCerts[1:]) to bridge
// the leaf to a configured root. GOST-signed certs are parsed and verified via
// the x509gost package; other certs fall back to stdlib x509. Returns the
// stdlib-shaped leaf and the verified chains (in stdlib shape on both paths) for
// the caller (signature-algorithm-agnostic transcript / name verification).
//
// When gc.HasGOSTPubKey is true, c.gostLeaf is set to the *x509gost.Certificate
// so that buildGOSTExchange can retrieve the server public key without
// re-parsing. Certs signed by a non-GOST CA but carrying a GOST pubkey (common
// in test fixtures and in deployments with a shared RSA CA) reach the stdlib
// branch: chain verification is stdlib, KEX pubkey still comes from x509gost.
func parseAndVerifyChain(c *ClientState, rawCerts [][]byte) (*x509.Certificate, [][]*x509.Certificate, error) {
	gc, err := x509gost.ParseCertificate(rawCerts[0])
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

		intermediates, err := extractGOSTIntermediates(c.params.GOSTIntermediates)
		if err != nil {
			return nil, nil, err
		}

		// Bridge with any intermediates the server sent on the wire, not just
		// the preconfigured ones.
		wireInter, err := parseGOSTIntermediates(rawCerts[1:])
		if err != nil {
			return nil, nil, err
		}

		intermediates = append(intermediates, wireInter...)

		opts := x509gost.VerifyOptions{
			GOSTRoots:         roots,
			GOSTIntermediates: intermediates,
			DNSName:           c.params.ServerName,
			CurrentTime:       time.Now(),
			KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		gostChains, err := gc.Verify(opts)
		if err != nil {
			return nil, nil, fmt.Errorf("GOST certificate verification failed: %w", err)
		}

		// Surface the verified chains in stdlib shape so VerifyPeerCertificate
		// receives a non-nil verifiedChains argument on the GOST path too.
		return leafCert, gostChainsToStdlib(gostChains), nil
	}

	// Non-GOST signature (including GOST pubkey + RSA CA): use stdlib
	// verification, feeding it the server-supplied intermediates.
	intermediates, err := parseStdlibIntermediates(rawCerts[1:])
	if err != nil {
		return nil, nil, err
	}

	opts := x509.VerifyOptions{
		Roots:         c.params.RootCAs,
		Intermediates: intermediates,
		DNSName:       c.params.ServerName,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	chains, err := leafCert.Verify(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate verification failed: %w", err)
	}

	return leafCert, chains, nil
}

// gostChainsToStdlib converts x509gost verified chains into stdlib chains using
// each certificate's embedded Stdlib view, so VerifyPeerCertificate receives
// chains in the documented [][]*x509.Certificate shape.
func gostChainsToStdlib(chains [][]*x509gost.Certificate) [][]*x509.Certificate {
	if len(chains) == 0 {
		return nil
	}

	out := make([][]*x509.Certificate, len(chains))
	for i, chain := range chains {
		conv := make([]*x509.Certificate, len(chain))
		for j, cert := range chain {
			conv[j] = cert.Stdlib
		}

		out[i] = conv
	}

	return out
}

// parseStdlibIntermediates parses DER-encoded intermediate certificates into an
// x509 pool. An empty input yields an empty (non-nil) pool, which x509.Verify
// treats the same as having no intermediates.
func parseStdlibIntermediates(rawInter [][]byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, der := range rawInter {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse server intermediate certificate: %w", err)
		}

		pool.AddCert(cert)
	}

	return pool, nil
}

// parseGOSTIntermediates parses DER-encoded intermediate certificates as
// x509gost certificates so they can bridge a GOST leaf to a configured GOST
// root. A nil/empty input yields a nil slice.
func parseGOSTIntermediates(rawInter [][]byte) ([]*x509gost.Certificate, error) {
	if len(rawInter) == 0 {
		return nil, nil
	}

	out := make([]*x509gost.Certificate, 0, len(rawInter))
	for _, der := range rawInter {
		cert, err := x509gost.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse server GOST intermediate certificate: %w", err)
		}

		out = append(out, cert)
	}

	return out, nil
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
		return nil, fmt.Errorf("%w: got %T, want []*x509gost.Certificate", errGOSTRootsWrongType, v)
	}

	if len(roots) == 0 {
		return nil, ErrGOSTRootsRequired
	}

	return roots, nil
}

// extractGOSTIntermediates asserts params.GOSTIntermediates to the expected
// concrete type. Unlike the roots, intermediates are optional: a nil field is
// valid and yields a nil pool (a direct leaf-signed-by-root chain). Only a
// non-nil value of the wrong type is an error.
func extractGOSTIntermediates(v any) ([]*x509gost.Certificate, error) {
	if v == nil {
		return nil, nil
	}

	intermediates, ok := v.([]*x509gost.Certificate)
	if !ok {
		return nil, fmt.Errorf("%w: got %T, want []*x509gost.Certificate", errGOSTIntermediatesWrongType, v)
	}

	return intermediates, nil
}
