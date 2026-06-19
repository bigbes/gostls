//nolint:testpackage // white-box: exercises unexported parseExtensions and marshalExtensions
package handshake

import (
	"testing"
)

// FuzzParseExtensions targets the extension list parser directly. Extensions
// are the richest attacker-controlled sub-surface of a ClientHello/ServerHello:
// each entry carries its own length-prefixed body fanned out to a dedicated
// sub-parser (server_name, supported_groups, ec_point_formats,
// signature_algorithms, ...), each with its own internal length fields.
//
// extData is the extension entry sequence *without* the outer 2-byte total
// length (ParseMessage strips that before calling parseExtensions), so seeds
// drop the prefix that marshalExtensions prepends.
//
// Contract: never panic — a truncated entry header, an over-declared inner
// length, or an unknown type must return an error.
func FuzzParseExtensions(f *testing.F) {
	full := marshalExtensions(parsedExtensions{
		ServerName:      "example.com",
		SupportedGroups: []uint16{0x0017, 0x0018, 0x0019},
		ECPointFormats:  []uint8{0x00, 0x01, 0x02},
		SignatureAlgorithms: []SigAndHash{
			{Hash: 0x04, Sig: 0x01},
			{Hash: 0x05, Sig: 0x01},
		},
		ExtendedMasterSecret: true,
		RenegotiationInfo:    true,
	})
	if len(full) >= 2 {
		f.Add(full[2:]) // strip the outer total-length prefix.
	}

	f.Add([]byte{})                                   // empty list (valid: no extensions).
	f.Add([]byte{0xFF, 0xFF, 0x00, 0x02, 0xAA, 0xBB}) // unknown type 0xFFFF.
	f.Add([]byte{0x00, 0x00, 0xFF, 0xFF})             // declared len 0xFFFF, no body.

	f.Fuzz(func(t *testing.T, extData []byte) {
		// Contract: must not panic on any input.
		_, _, _ = parseExtensions(extData)
	})
}
