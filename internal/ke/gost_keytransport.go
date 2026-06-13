package ke

import (
	"encoding/asn1"
	"fmt"
)

// ASN.1 DER encoding constants.
const (
	// bitsPerByte is used to compute BitLength for BIT STRING fields.
	bitsPerByte = 8

	// derLongFormMask is the high-bit mask indicating a long-form DER length.
	derLongFormMask = 0x80

	// derLengthBytesMask extracts the number of subsequent length bytes in long-form DER.
	derLengthBytesMask = 0x7f
)

// ASN.1 structures for the TLS 1.2 GOST-CNT ClientKeyExchange body
// (RFC 9189 §4.1). Mirrors gost-engine's ASN1_NDEF_SEQUENCE definitions
// in gost_asn1.c.
//
// The wire CKE body is GOST_CLIENT_KEY_EXCHANGE_PARAMS (tmp/engine/gost_asn1.c:56-60),
// a SEQUENCE wrapping a single GOST_KEY_TRANSPORT:
//
//	GOST_CLIENT_KEY_EXCHANGE_PARAMS ::= SEQUENCE {
//	    gkt  GOST_KEY_TRANSPORT
//	}
//	GOST_KEY_TRANSPORT ::= SEQUENCE {
//	    key_info            GOST_KEY_INFO,
//	    key_agreement_info  [0] IMPLICIT GOST_KEY_AGREEMENT_INFO
//	}
//	GOST_KEY_INFO ::= SEQUENCE {
//	    encrypted_key  OCTET STRING,
//	    imit           OCTET STRING
//	}
//	GOST_KEY_AGREEMENT_INFO ::= SEQUENCE {
//	    cipher      OBJECT IDENTIFIER,
//	    ephem_key   [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
//	    eph_iv      OCTET STRING
//	}
//	SubjectPublicKeyInfo ::= SEQUENCE {
//	    algorithm         AlgorithmIdentifier,
//	    subjectPublicKey  BIT STRING
//	}
//	AlgorithmIdentifier ::= SEQUENCE {
//	    algorithm   OBJECT IDENTIFIER,
//	    parameters  ANY DEFINED BY algorithm OPTIONAL
//	}

type gostClientKeyExchangeParams struct {
	GKT gostKeyTransport
}

type gostKeyTransport struct {
	KeyInfo          gostKeyInfo
	KeyAgreementInfo gostKeyAgreementInfo `asn1:"tag:0"`
}

type gostKeyInfo struct {
	EncryptedKey []byte
	IMIT         []byte
}

type gostKeyAgreementInfo struct {
	Cipher   asn1.ObjectIdentifier
	EphemKey asn1.RawValue
	EphIV    []byte
}

type keSPKI struct {
	Algorithm        keAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type keAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// marshalGOSTKeyTransport produces the DER encoding of GOST_KEY_TRANSPORT.
//
// spkiAlgo is the raw DER of the server certificate's SPKI AlgorithmIdentifier
// (reused for the ephemeral key's SPKI — same pubkey OID and curve params).
// ephemPubRaw is the ephemeral public key bytes as returned by gogost's
// PublicKey.Raw() — wrapped in an OCTET STRING inside the BIT STRING per RFC 4491.
// encryptedKey is the 32-byte wrapped session key (bytes 8..40 of the
// KeyWrapCryptoPro output); imit is the 4-byte MAC (bytes 40..44).
// cipherOID is the S-box param OID (e.g., tc26-gost-28147-param-Z for 2012
// certificates, CryptoPro-A for 2001).
// ephIV is the 8-byte UKM used for the wrap.
func marshalGOSTKeyTransport(
	spkiAlgo []byte,
	ephemPubRaw []byte,
	encryptedKey []byte,
	imit []byte,
	cipherOID asn1.ObjectIdentifier,
	ephIV []byte,
) ([]byte, error) {
	var algID keAlgorithmIdentifier

	if _, err := asn1.Unmarshal(spkiAlgo, &algID); err != nil {
		return nil, fmt.Errorf("ke/gost_keytransport: unmarshal server SPKI algorithm: %w", err)
	}

	octet, err := asn1.Marshal(ephemPubRaw)
	if err != nil {
		return nil, fmt.Errorf("ke/gost_keytransport: marshal ephemeral key OCTET STRING: %w", err)
	}

	spki := keSPKI{
		Algorithm:        algID,
		SubjectPublicKey: asn1.BitString{Bytes: octet, BitLength: len(octet) * bitsPerByte},
	}

	spkiDER, err := asn1.Marshal(spki)
	if err != nil {
		return nil, fmt.Errorf("ke/gost_keytransport: marshal ephemeral SPKI: %w", err)
	}

	ephemRaw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      spkiDER[2+lengthOfLength(spkiDER[1]):],
	}

	params := gostClientKeyExchangeParams{
		GKT: gostKeyTransport{
			KeyInfo: gostKeyInfo{
				EncryptedKey: encryptedKey,
				IMIT:         imit,
			},
			KeyAgreementInfo: gostKeyAgreementInfo{
				Cipher:   cipherOID,
				EphemKey: ephemRaw,
				EphIV:    ephIV,
			},
		},
	}

	return asn1.Marshal(params)
}

// lengthOfLength returns the number of bytes used to encode the DER length
// given the first length byte. The two bytes preceding spkiDER[2+...] are the
// outer SEQUENCE tag (0x30) and its length — we need to skip past both to
// get to the SEQUENCE body.
func lengthOfLength(first byte) int {
	if first&derLongFormMask == 0 {
		return 0 // short form: length fits in the first byte, already counted.
	}

	return int(first & derLengthBytesMask)
}
