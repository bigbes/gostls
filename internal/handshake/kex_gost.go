package handshake

import (
	"fmt"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostcrypto/x509gost"
	"github.com/bigbes/gostls/internal/ke"
	"github.com/bigbes/gostls/internal/suites"
)

// buildGOSTExchange constructs a ke.Exchange for GOST VKO key agreement.
//
// It type-asserts c.gostLeaf to *x509gost.Certificate (populated by
// parseAndVerifyLeaf when the server certificate carries a GOST public key),
// resolves the curve from the cert's CurveOID, reads PubKeyRaw, and dispatches
// on c.suite.KX to the appropriate VKO constructor. UKM is derived as
// clientRandom[:8] per RFC 9189 §4.1.
func buildGOSTExchange(c *ClientState) (ke.Exchange, error) {
	gc, ok := c.gostLeaf.(*x509gost.Certificate)
	if !ok || gc == nil {
		return nil, fmt.Errorf("%w (got %T)", errGOSTNeedGOSTCert, c.gostLeaf)
	}

	curve, err := gost.CurveByOID(gc.CurveOID)
	if err != nil {
		return nil, fmt.Errorf("tls: resolve GOST server cert curve: %w", err)
	}

	pubRaw := gc.PubKeyRaw
	ukm := c.clientRandom[:8]

	switch c.suite.KX {
	case suites.KexGOST2001:
		return ke.NewVKOGost2001Exchange(curve, gc.SPKIAlgorithmDER, pubRaw, ukm)
	case suites.KexGOST2012_256:
		return ke.NewVKOGost2012_256Exchange(curve, gc.SPKIAlgorithmDER, pubRaw, ukm)
	case suites.KexGOST2018_256:
		return buildGOST2018Exchange(c)
	case suites.KexRSA, suites.KexDHE, suites.KexECDHE:
		// Non-GOST KX kinds; not reachable in this function (caller guards).
		fallthrough
	default:
		return nil, fmt.Errorf("%w %d", errGOSTUnexpectedKXKind, c.suite.KX)
	}
}

// buildGOST2018Exchange constructs a ke.Exchange for GOST 2018 key transport
// (RFC 9367, suites 0xC100 / 0xC101).
//
// Unlike VKO (2001/2012), this is key-transport: the client generates an
// ephemeral EC keypair, derives 64-byte export keys via KEG2012_256, and
// wraps the pre-master secret with kexp15. See tmp/engine/gost_ec_keyx.c:413-551.
//
// The cipher variant is determined from the suite ID rather than a dedicated
// Suite field — the ID is sufficient and avoids polluting the suite spec.
func buildGOST2018Exchange(c *ClientState) (ke.Exchange, error) {
	gc, ok := c.gostLeaf.(*x509gost.Certificate)
	if !ok || gc == nil {
		return nil, fmt.Errorf("%w (got %T)", errGOST2018NeedGOSTCert, c.gostLeaf)
	}

	curve, err := gost.CurveByOID(gc.CurveOID)
	if err != nil {
		return nil, fmt.Errorf("tls: resolve GOST 2018 server cert curve: %w", err)
	}

	// Determine kexp15 variant from suite ID (RFC 9367):
	//   0xC100 → Kuznyechik (128-bit block, iv_len=8)
	//   0xC101 → Magma (64-bit block, iv_len=4)
	const (
		suiteIDKuznyechik = 0xC100
		suiteIDMagma      = 0xC101
	)

	var variant ke.Gost2018Variant

	switch c.suite.ID {
	case suiteIDKuznyechik:
		variant = ke.Variant2018Kuznyechik
	case suiteIDMagma:
		variant = ke.Variant2018Magma
	default:
		return nil, fmt.Errorf("%w 0x%04X", errGOST2018UnexpectedID, c.suite.ID)
	}

	// UKM = Streebog-256(clientRandom || serverRandom) per
	// ssl/statem/statem_clnt.c:ossl_gost_ukm in OpenSSL. Both peers derive
	// the same UKM independently; the `ukm` octet string in the wire
	// PSKeyTransport_gost is informational (the server ignores it in favour
	// of its own hash-derived UKM).
	const randomsLen = 64

	randoms := make([]byte, randomsLen)
	copy(randoms[:32], c.clientRandom[:])
	copy(randoms[32:], c.serverRandom[:])

	return ke.NewGost2018Exchange(curve, gc.SPKIAlgorithmDER, gc.PubKeyRaw, variant, randoms)
}
