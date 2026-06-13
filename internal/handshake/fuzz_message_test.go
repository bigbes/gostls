package handshake_test

import (
	"testing"

	"github.com/bigbes/gostls/internal/handshake"
)

// FuzzParseMessage stresses the handshake-message wire parser, the first code
// to touch attacker-controlled bytes after the TLS record layer. ParseMessage
// dispatches on the type byte to all nine parseXxx body parsers (and, through
// ClientHello/ServerHello, into the extension sub-parsers), so a single fuzz
// target with one valid seed per type drives the whole surface.
//
// Contract: parsing a server's (untrusted) handshake bytes must never panic —
// a malformed length prefix, truncated body, or bogus extension must come back
// as an error, not a slice-bounds crash that takes down the client.
func FuzzParseMessage(f *testing.F) {
	for _, m := range seedMessages() {
		f.Add(handshake.MarshalMessage(m))
	}

	// A couple of degenerate seeds the mutator can grow from.
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: must not panic on any input. err / nil are both fine.
		msg, remaining, err := handshake.ParseMessage(data)
		if err == nil && msg == nil {
			t.Fatal("ParseMessage returned nil message and nil error")
		}

		_ = remaining
	})
}

// seedMessages builds one valid instance of every handshake message type, so
// the fuzzer starts with coverage of each parseXxx branch.
func seedMessages() []handshake.Message {
	random := [32]byte{}
	for i := range random {
		random[i] = byte(i)
	}

	return []handshake.Message{
		&handshake.ClientHello{
			Version:            0x0303,
			Random:             random,
			SessionID:          []byte{0xAA, 0xBB, 0xCC},
			CipherSuites:       []uint16{0x002F, 0xC02C},
			CompressionMethods: []uint8{0x00},
			ServerName:         "example.com",
			SupportedGroups:    []uint16{0x0017, 0x0018},
			ECPointFormats:     []uint8{0x00},
			SignatureAlgorithms: []handshake.SigAndHash{
				{Hash: 0x04, Sig: 0x01},
				{Hash: 0x05, Sig: 0x01},
			},
		},
		&handshake.ServerHello{
			Version:           0x0303,
			Random:            random,
			SessionID:         []byte{0x01, 0x02},
			CipherSuite:       0xC02C,
			CompressionMethod: 0x00,
			RenegotiationInfo: true,
		},
		&handshake.Certificate{
			RawCerts: [][]byte{
				{0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB},
				{0x30, 0x82, 0x02, 0x00, 0xCC, 0xDD, 0xEE},
			},
		},
		&handshake.ServerKeyExchange{Body: []byte{0x03, 0x00, 0x17, 0x41, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}},
		&handshake.ServerHelloDone{},
		&handshake.ClientKeyExchange{Body: []byte{0x41, 0x04, 0xCA, 0xFE, 0xBA, 0xBE}},
		&handshake.CertificateVerify{
			Algorithm: handshake.SigAndHash{Hash: 0x04, Sig: 0x01},
			Signature: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
		},
		&handshake.Finished{VerifyData: make([]byte, 12)},
		// CertificateRequest: seed the parser via a raw body the mutator can grow.
		&handshake.RawMessage{
			MsgType: handshake.TypeCertificateRequest,
			Body:    []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00},
		},
	}
}
