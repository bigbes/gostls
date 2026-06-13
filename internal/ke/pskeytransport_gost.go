package ke

import (
	"encoding/asn1"
	"fmt"
)

// PSKeyTransport_gost ASN.1 marshaller for GOST 2018 KEX (draft-smyshlyaev-tls12-gost-suites).
//
// Wire format defined in tmp/engine/gost_asn1.c:70-76:
//
//	PSKeyTransport_gost ::= SEQUENCE {
//	    psexp     OCTET STRING,
//	    ephem_key SubjectPublicKeyInfo,
//	    ukm       OCTET STRING OPTIONAL
//	}
//
// SubjectPublicKeyInfo is a plain (non-implicitly-tagged) SEQUENCE, unlike the
// [0] IMPLICIT SPKI in GOST_KEY_AGREEMENT_INFO (used for 2001/2012 KEX).
// The BIT STRING body is an OCTET STRING wrapping the raw public-key bytes
// (LE Y || LE X) — same encoding as gost-engine's X509_PUBKEY_set output for
// GOST EC keys.

// psKeyTransportGost is the Go struct marshalled by encoding/asn1 into the
// PSKeyTransport_gost DER encoding.
//
// Note: keSPKI and keAlgorithmIdentifier are defined in gost_keytransport.go
// (same package). Do not redefine them here.
type psKeyTransportGost struct {
	PsExp    []byte `asn1:""`
	EphemKey keSPKI `asn1:""`
	// UKM is OPTIONAL: encoding/asn1 omits a nil []byte field tagged optional.
	// Callers must pass nil when no UKM is included; a non-nil empty slice
	// would produce an empty OCTET STRING which is not the intended omission.
	UKM []byte `asn1:"optional"`
}

// marshalPSKeyTransport produces the DER encoding of PSKeyTransport_gost.
//
// psexp is the pre-shared-key export (encrypted+wrapped session key bytes).
// ephemSPKIAlgo is the raw DER of the AlgorithmIdentifier from the server
// certificate's SPKI — it is reused verbatim for the ephemeral key's SPKI.
// ephemPubRaw is the ephemeral public key bytes as returned by gogost's
// PublicKey.Raw() (LE Y || LE X). It is wrapped in an OCTET STRING inside
// the BIT STRING per the X509_PUBKEY_set convention used by gost-engine.
// ukm is the 32-byte UKM for the key-exchange; pass nil to omit the OPTIONAL
// field entirely.
//
// The pattern mirrors marshalGOSTKeyTransport in gost_keytransport.go, but
// uses a plain SEQUENCE for ephem_key (no IMPLICIT context tag) per
// tmp/engine/gost_asn1.c:73.
func marshalPSKeyTransport(psexp, ephemSPKIAlgo, ephemPubRaw, ukm []byte) ([]byte, error) {
	var algID keAlgorithmIdentifier

	if _, err := asn1.Unmarshal(ephemSPKIAlgo, &algID); err != nil {
		return nil, fmt.Errorf("ke/pskeytransport_gost: unmarshal server SPKI algorithm: %w", err)
	}

	octet, err := asn1.Marshal(ephemPubRaw)
	if err != nil {
		return nil, fmt.Errorf("ke/pskeytransport_gost: marshal ephemeral key OCTET STRING: %w", err)
	}

	spki := keSPKI{
		Algorithm:        algID,
		SubjectPublicKey: asn1.BitString{Bytes: octet, BitLength: len(octet) * bitsPerByte},
	}

	pkt := psKeyTransportGost{
		PsExp:    psexp,
		EphemKey: spki,
		UKM:      ukm, // nil → omitted per asn1:"optional".
	}

	der, err := asn1.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("ke/pskeytransport_gost: marshal PSKeyTransport_gost: %w", err)
	}

	return der, nil
}
