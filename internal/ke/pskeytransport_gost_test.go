package ke

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	gost "github.com/bigbes/gostcrypto"
)

// fixedSpkiAlgo2012_256 is a DER-encoded AlgorithmIdentifier for GOST R
// 34.10-2012 256-bit (pubkey OID 1.2.643.7.1.1.1.1) with
// CryptoPro-A curve (1.2.643.2.2.35.1) and Streebog-256 hash
// (1.2.643.7.1.1.2.2). Identical to the vector used in
// gost_keytransport_roundtrip_test.go.
var fixedSpkiAlgo2012_256 = []byte{
	0x30, 0x1f,
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, // pubkey OID
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, // curve OID
	0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02, // hash OID
}

// TestMarshalPSKeyTransport_RoundTrip marshals a PSKeyTransport_gost, then
// re-parses it via encoding/asn1 and verifies all fields are recovered intact.
//
// Source: tmp/engine/gost_asn1.c:70-76.
func TestMarshalPSKeyTransport_RoundTrip(t *testing.T) {
	curve := gost.GOST2001CryptoProAParamSetCurve()

	// Generate a deterministic ephemeral key from a fixed seed.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	_, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}
	if len(ephemPubRaw) != 64 {
		t.Fatalf("ephemPubRaw: want 64 bytes, got %d", len(ephemPubRaw))
	}

	psexp := make([]byte, 8)
	for i := range psexp {
		psexp[i] = byte(0xA0 + i)
	}
	ukm := make([]byte, 32)
	for i := range ukm {
		ukm[i] = byte(0x10 + i)
	}

	der, err := marshalPSKeyTransport(psexp, fixedSpkiAlgo2012_256, ephemPubRaw, ukm)
	if err != nil {
		t.Fatalf("marshalPSKeyTransport: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("marshalPSKeyTransport: empty output")
	}
	t.Logf("DER (%d bytes): %x", len(der), der)

	// Re-parse.
	var parsed psKeyTransportGost
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after unmarshal: %d", len(rest))
	}

	// PsExp round-trips.
	if !bytes.Equal(parsed.PsExp, psexp) {
		t.Errorf("PsExp mismatch\ngot:  %x\nwant: %x", parsed.PsExp, psexp)
	}

	// UKM round-trips.
	if !bytes.Equal(parsed.UKM, ukm) {
		t.Errorf("UKM mismatch\ngot:  %x\nwant: %x", parsed.UKM, ukm)
	}

	// EphemKey: recover ephemPubRaw through BIT STRING → OCTET STRING → raw bytes.
	bitBytes := parsed.EphemKey.SubjectPublicKey.Bytes
	var pubOctet []byte
	rest2, err := asn1.Unmarshal(bitBytes, &pubOctet)
	if err != nil {
		t.Fatalf("unmarshal pubkey OCTET STRING: %v", err)
	}
	if len(rest2) != 0 {
		t.Fatalf("trailing bytes in OCTET STRING: %d", len(rest2))
	}
	if !bytes.Equal(pubOctet, ephemPubRaw) {
		t.Errorf("ephemPubRaw mismatch\ngot:  %x\nwant: %x", pubOctet, ephemPubRaw)
	}
}

// TestMarshalPSKeyTransport_RoundTrip_NilUKM verifies that passing ukm=nil
// produces a SEQUENCE with only two elements (psexp + ephem_key), and that
// parsing it back yields a zero-length UKM field (the OPTIONAL was omitted).
func TestMarshalPSKeyTransport_RoundTrip_NilUKM(t *testing.T) {
	curve := gost.GOST2001CryptoProAParamSetCurve()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 5)
	}
	_, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}

	psexp := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	der, err := marshalPSKeyTransport(psexp, fixedSpkiAlgo2012_256, ephemPubRaw, nil)
	if err != nil {
		t.Fatalf("marshalPSKeyTransport (nil UKM): %v", err)
	}

	var parsed psKeyTransportGost
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}
	if !bytes.Equal(parsed.PsExp, psexp) {
		t.Errorf("PsExp mismatch: got %x want %x", parsed.PsExp, psexp)
	}
	if len(parsed.UKM) != 0 {
		t.Errorf("UKM should be absent (nil/empty) but got %x", parsed.UKM)
	}
}

// TestMarshalPSKeyTransport_AsnParseStable pins the DER output for a fixed
// set of inputs.  The expected bytes were derived by calling marshalPSKeyTransport
// with the same inputs and verified with:
//
//	$ openssl asn1parse -inform DER -i -in pskt.der
//	    0:d=0  hl=3 l= 148 cons: SEQUENCE
//	    3:d=1  hl=2 l=   8 prim:  OCTET STRING      [HEX DUMP]:A0A1A2A3A4A5A6A7
//	   13:d=1  hl=2 l= 102 cons:  SEQUENCE
//	   15:d=2  hl=2 l=  31 cons:   SEQUENCE
//	   17:d=3  hl=2 l=   8 prim:    OBJECT            :GOST R 34.10-2012 with 256 bit modulus
//	   27:d=3  hl=2 l=  19 cons:    SEQUENCE
//	   29:d=4  hl=2 l=   7 prim:     OBJECT            :id-GostR3410-2001-CryptoPro-A-ParamSet
//	   38:d=4  hl=2 l=   8 prim:     OBJECT            :GOST R 34.11-2012 with 256 bit hash
//	   48:d=2  hl=2 l=  67 prim:   BIT STRING
//	  117:d=1  hl=2 l=  32 prim:  OCTET STRING      [HEX DUMP]:101112...2E2F
//
// Structure matches PSKeyTransport_gost from tmp/engine/gost_asn1.c:70-76:
// SEQUENCE { OCTET STRING (psexp), SEQUENCE (SubjectPublicKeyInfo), OCTET STRING (ukm) }.
//
// TODO(phase2-stable): replace self-derived expected bytes with a value
// produced by i2d_PSKeyTransport_gost() in gost-engine once a capture
// harness is available (see docs/tasks/pure-gost-2018-kex.md §verification).
func TestMarshalPSKeyTransport_AsnParseStable(t *testing.T) {
	// Fixed inputs — identical to TestMarshalPSKeyTransport_RoundTrip.
	curve := gost.GOST2001CryptoProAParamSetCurve()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	_, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}

	psexp := make([]byte, 8)
	for i := range psexp {
		psexp[i] = byte(0xA0 + i)
	}
	ukm := make([]byte, 32)
	for i := range ukm {
		ukm[i] = byte(0x10 + i)
	}

	// wantDER is the pinned DER output for the fixed inputs above.
	// Derived by marshalPSKeyTransport and verified field-by-field via
	// openssl asn1parse (output captured in the comment above).
	// Replace with engine-oracle bytes when a gost-engine capture harness
	// is available.
	wantDER, _ := hex.DecodeString(
		"3081940408a0a1a2a3a4a5a6a7" +
			"3066301f06082a85030701010101301306072a85030202230106082a850307010102020343000440" +
			"d4572c4a208ac360480314e38f9e087904be0aa145c2e4f70f9fb47de60cecd342052b8dac9a81dd2fdfbf7cefebd0596f694e87e71861ff9560cf1709312bc6" +
			"0420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")

	der, err := marshalPSKeyTransport(psexp, fixedSpkiAlgo2012_256, ephemPubRaw, ukm)
	if err != nil {
		t.Fatalf("marshalPSKeyTransport: %v", err)
	}

	if !bytes.Equal(der, wantDER) {
		t.Errorf("DER mismatch\ngot:  %x\nwant: %x", der, wantDER)
	}

	// Structural verification: parse and check field structure.
	var parsed psKeyTransportGost
	rest, err2 := asn1.Unmarshal(der, &parsed)
	if err2 != nil {
		t.Fatalf("structural parse: %v", err2)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}

	// Verify outer SEQUENCE tag (offset 0) and that psexp is OCTET STRING (offset 3,
	// after the 3-byte hl=3 header: tag 0x30 + 2-byte long-form length).
	if der[0] != 0x30 {
		t.Errorf("outer tag: want 0x30, got 0x%02x", der[0])
	}
	// Long-form length: der[1]=0x81 means 1 extra byte. psexp starts at offset 3.
	if der[3] != 0x04 {
		t.Errorf("psexp tag: want 0x04 (OCTET STRING), got 0x%02x", der[3])
	}
	if !bytes.Equal(parsed.PsExp, psexp) {
		t.Errorf("psexp: got %x want %x", parsed.PsExp, psexp)
	}
	if !bytes.Equal(parsed.UKM, ukm) {
		t.Errorf("ukm: got %x want %x", parsed.UKM, ukm)
	}

	// Verify that the EphemKey inner BIT STRING decodes to our pubkey.
	bitBytes := parsed.EphemKey.SubjectPublicKey.Bytes
	var pubOctet []byte
	if _, err3 := asn1.Unmarshal(bitBytes, &pubOctet); err3 != nil {
		t.Fatalf("inner OCTET STRING: %v", err3)
	}
	if !bytes.Equal(pubOctet, ephemPubRaw) {
		t.Errorf("ephemPubRaw: got %x want %x", pubOctet, ephemPubRaw)
	}
}
