//nolint:testpackage // white-box: FuzzParseDHEServerParams accesses unexported parseDHEServerParams.
package ke

// fuzz_test.go — fuzz targets for internal/ke.
//
// FuzzParseDHEServerParams targets the DHE wire parser (parseDHEServerParams).
// FuzzParseGOSTKeyTransport targets GOST key-transport DER unmarshal paths.
// FuzzParsePSKeyTransport targets PSKeyTransport_gost DER unmarshal.
//
// Contract for all targets: must never panic on arbitrary byte input.
// Errors are acceptable; panics are not.

import (
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

// FuzzParseDHEServerParams fuzzes the parseDHEServerParams function with
// arbitrary byte sequences. The function must never panic regardless of input;
// it should either return valid (p, g, Ys) slices or a descriptive error.
//
// Seeds include:
//   - A valid ffdhe2048 params blob (covers the success path).
//   - Minimal/degenerate cases (empty, too short, truncated fields, trailing bytes).
func FuzzParseDHEServerParams(f *testing.F) {
	// Seed 1: valid ffdhe2048 params (p=2048 bits, g=2, Ys=valid value > 1).
	// Build the seed from known ffdhe2048 constants.
	p, _ := hex.DecodeString(
		"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695" +
			"A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A" +
			"D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
			"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A" +
			"BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4" +
			"AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03405CD28342F61" +
			"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005" +
			"C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF")

	g := []byte{0x02}

	// Ys = g^x mod p for x=1 = 2 (a valid value 1 < Ys < p-1).
	Ys := []byte{0x02, 0x00} // 512 decimal, small value far from p-1.

	validSeed := buildDHESeed(p, g, Ys)
	f.Add(validSeed)

	// Seed 2: empty input (length 0).
	f.Add([]byte{})

	// Seed 3: one byte (too short for any length prefix).
	f.Add([]byte{0x01})

	// Seed 4: only p with length prefix, no g or Ys.
	shortSeed := buildDHESeed(p, nil, nil)

	f.Add(shortSeed[:len(shortSeed)/2]) // Truncate halfway.

	// Seed 5: valid p and g, but Ys declared length overflows.
	overflowSeed := buildDHESeed(p, g, nil)

	overflowSeed = append(overflowSeed, 0xFF, 0xFF) // Ys length = 65535, no body.
	f.Add(overflowSeed)

	// Seed 6: trailing garbage after valid (p, g, Ys).
	trailingSeed := append(validSeed, 0xDE, 0xAD, 0xBE, 0xEF)

	f.Add(trailingSeed)

	// Seed 7: p with length 0 (invalid).
	zeroP := append([]byte{0x00, 0x00}, buildDHESeed(nil, g, Ys)...)

	f.Add(zeroP)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: parseDHEServerParams must never panic.
		// It may return an error or valid (p, g, Ys) — both are fine.
		_, _, _, _ = parseDHEServerParams(data)
	})
}

// buildDHESeed encodes a DHE ServerKeyExchange params blob with 2-byte length
// prefixes for each of p, g, Ys. Fields with nil/empty value are encoded with
// a zero-length prefix (0x00 0x00).
func buildDHESeed(p, g, Ys []byte) []byte {
	var buf []byte

	for _, field := range [][]byte{p, g, Ys} {
		buf = append(buf, byte(len(field)>>8), byte(len(field)))
		buf = append(buf, field...)
	}

	return buf
}

// FuzzParseGOSTKeyTransport fuzzes the DER unmarshal path for GOST_KEY_TRANSPORT
// structures (used by VKO2001 and VKO2012_256 key exchange). The seed is a
// valid DER SEQUENCE of the GOST_KEY_TRANSPORT type.
//
// Contract: encoding/asn1.Unmarshal must never panic on arbitrary input;
// returning an error is always acceptable.
func FuzzParseGOSTKeyTransport(f *testing.F) {
	// Seed 1: a valid gostClientKeyExchangeParams DER produced by VKO2001
	// marshalGOSTKeyTransport with known fixed inputs.
	// This is a pre-computed DER blob from TestMarshalGOSTKeyTransport_Valid.
	// We use the fixed AlgorithmIdentifier + a zero-filled ephem pubkey for
	// determinism, then marshal it.
	validDER := makeValidGOSTKeyTransportDER()

	f.Add(validDER)

	// Seed 2: empty.
	f.Add([]byte{})

	// Seed 3: a SEQUENCE tag with zero length.
	f.Add([]byte{0x30, 0x00})

	// Seed 4: a SEQUENCE tag with length 1 and one byte of content.
	f.Add([]byte{0x30, 0x01, 0xAA})

	// Seed 5: indefinite-length encoding (not valid DER, but should not panic).
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})

	// Seed 6: large declared length but short content.
	f.Add([]byte{0x30, 0x82, 0xFF, 0xFF, 0x04, 0x02, 0xAB, 0xCD})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: asn1.Unmarshal of GOST_KEY_TRANSPORT must never panic.
		var params gostClientKeyExchangeParams

		_, _ = asn1.Unmarshal(data, &params)
	})
}

// makeValidGOSTKeyTransportDER produces a minimal but structurally valid DER
// encoding of gostClientKeyExchangeParams. This gives the fuzzer a rich seed.
func makeValidGOSTKeyTransportDER() []byte {
	spkiAlgo := []byte{
		0x30, 0x1f,
		0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,
		0x30, 0x13,
		0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01,
		0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02,
	}

	// A 64-byte all-zero ephemeral public key and fixed encrypted_key / imit.
	ephemPubRaw := make([]byte, 64)
	encryptedKey := make([]byte, 32)
	imit := make([]byte, 4)
	cipherOID := asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}
	ephIV := make([]byte, 8)

	der, err := marshalGOSTKeyTransport(spkiAlgo, ephemPubRaw, encryptedKey, imit, cipherOID, ephIV)
	if err != nil {
		// Return a minimal valid SEQUENCE if marshalling fails.
		return []byte{0x30, 0x00}
	}

	return der
}

// FuzzParsePSKeyTransport fuzzes the DER unmarshal path for PSKeyTransport_gost
// structures (used by GOST 2018 key exchange). The seed is a valid DER blob
// produced by marshalPSKeyTransport.
//
// Contract: encoding/asn1.Unmarshal must never panic on arbitrary input.
func FuzzParsePSKeyTransport(f *testing.F) {
	// Seed 1: valid PSKeyTransport_gost DER (from TestMarshalPSKeyTransport_AsnParseStable).
	validDER, _ := hex.DecodeString(
		"3081940408a0a1a2a3a4a5a6a7" +
			"3066301f06082a85030701010101301306072a85030202230106082a850307010102020343000440" +
			"d4572c4a208ac360480314e38f9e087904be0aa145c2e4f70f9fb47de60cecd3" +
			"42052b8dac9a81dd2fdfbf7cefebd0596f694e87e71861ff9560cf1709312bc6" +
			"0420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")

	f.Add(validDER)

	// Seed 2: empty.
	f.Add([]byte{})

	// Seed 3: SEQUENCE with one OCTET STRING child.
	f.Add([]byte{0x30, 0x04, 0x04, 0x02, 0xDE, 0xAD})

	// Seed 4: large outer length, short content.
	f.Add([]byte{0x30, 0x81, 0xFF, 0x04, 0x02, 0xAB, 0xCD})

	// Seed 5: nested SEQUENCEs (well-formed but wrong content for PSKeyTransport).
	f.Add([]byte{0x30, 0x06, 0x30, 0x04, 0x04, 0x02, 0xAA, 0xBB})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: parsing PSKeyTransport_gost must never panic.
		var pkt psKeyTransportGost

		_, _ = asn1.Unmarshal(data, &pkt)
	})
}
