package handshake_test

import (
	"strings"
	"testing"

	"github.com/bigbes/gostls/internal/handshake"
)

// -----------------------------------------------------------------------
// types.go: Type.String()
// -----------------------------------------------------------------------.

func TestTypeString_KnownTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ  handshake.Type
		want string
	}{
		{handshake.TypeHelloRequest, "HelloRequest"},
		{handshake.TypeClientHello, "ClientHello"},
		{handshake.TypeServerHello, "ServerHello"},
		{handshake.TypeCertificate, "Certificate"},
		{handshake.TypeServerKeyExchange, "ServerKeyExchange"},
		{handshake.TypeCertificateRequest, "CertificateRequest"},
		{handshake.TypeServerHelloDone, "ServerHelloDone"},
		{handshake.TypeCertificateVerify, "CertificateVerify"},
		{handshake.TypeClientKeyExchange, "ClientKeyExchange"},
		{handshake.TypeFinished, "Finished"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			got := tc.typ.String()
			if got != tc.want {
				t.Errorf("Type(%d).String() = %q, want %q", int(tc.typ), got, tc.want)
			}
		})
	}
}

func TestTypeString_Unknown(t *testing.T) {
	t.Parallel()

	unknown := handshake.Type(200)
	got := unknown.String()

	// Must not be empty and must contain the numeric value.
	if got == "" {
		t.Fatal("Type(200).String() returned empty string")
	}

	if !strings.Contains(got, "200") {
		t.Errorf("Type(200).String() = %q; want string containing '200'", got)
	}
}

// -----------------------------------------------------------------------
// messages.go: parseServerHelloDone — non-empty body is rejected
// -----------------------------------------------------------------------.

func TestParseMessage_ServerHelloDone_NonEmptyBody(t *testing.T) {
	t.Parallel()

	// Build a ServerHelloDone message with a non-empty body.
	// parseServerHelloDone requires exactly 0 bytes.
	wire := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeServerHelloDone,
		Body:    []byte{0xAA},
	})

	_, _, err := handshake.ParseMessage(wire)
	if err == nil {
		t.Fatal("parseServerHelloDone with non-empty body: expected error, got nil")
	}
}

func TestParseMessage_ServerHelloDone_EmptyBody(t *testing.T) {
	t.Parallel()

	done := &handshake.ServerHelloDone{}
	wire := handshake.MarshalMessage(done)

	msg, remaining, err := handshake.ParseMessage(wire)
	if err != nil {
		t.Fatalf("parseServerHelloDone empty body: %v", err)
	}

	if len(remaining) != 0 {
		t.Errorf("unexpected remaining: %d bytes", len(remaining))
	}

	_, ok := msg.(*handshake.ServerHelloDone)
	if !ok {
		t.Fatalf("expected *ServerHelloDone, got %T", msg)
	}
}

// -----------------------------------------------------------------------
// messages.go: parseFinished — invalid verify_data length
// -----------------------------------------------------------------------.

func TestParseMessage_Finished_BadLength(t *testing.T) {
	t.Parallel()

	for _, badLen := range []int{0, 1, 11, 13, 31, 33, 64} {
		t.Run("len"+string(rune('0'+badLen/10))+string(rune('0'+badLen%10)), func(t *testing.T) {
			t.Parallel()

			body := make([]byte, badLen)
			wire := handshake.MarshalMessage(&handshake.RawMessage{
				MsgType: handshake.TypeFinished,
				Body:    body,
			})

			_, _, err := handshake.ParseMessage(wire)
			if err == nil {
				t.Fatalf("parseFinished with %d bytes: expected error, got nil", badLen)
			}
		})
	}
}

func TestParseMessage_Finished_Valid12(t *testing.T) {
	t.Parallel()

	vd := make([]byte, 12)
	for i := range vd {
		vd[i] = byte(i + 1)
	}

	fin := &handshake.Finished{VerifyData: vd}
	wire := handshake.MarshalMessage(fin)

	msg, _, err := handshake.ParseMessage(wire)
	if err != nil {
		t.Fatalf("parseFinished 12 bytes: %v", err)
	}

	got, ok := msg.(*handshake.Finished)
	if !ok {
		t.Fatalf("expected *Finished, got %T", msg)
	}

	for i, b := range vd {
		if got.VerifyData[i] != b {
			t.Errorf("VerifyData[%d]: got 0x%02x, want 0x%02x", i, got.VerifyData[i], b)
		}
	}
}

func TestParseMessage_Finished_Valid32(t *testing.T) {
	t.Parallel()

	vd := make([]byte, 32)
	for i := range vd {
		vd[i] = byte(i + 100)
	}

	fin := &handshake.Finished{VerifyData: vd}
	wire := handshake.MarshalMessage(fin)

	msg, _, err := handshake.ParseMessage(wire)
	if err != nil {
		t.Fatalf("parseFinished 32 bytes: %v", err)
	}

	got, ok := msg.(*handshake.Finished)
	if !ok {
		t.Fatalf("expected *Finished, got %T", msg)
	}

	if len(got.VerifyData) != 32 {
		t.Errorf("VerifyData length: got %d, want 32", len(got.VerifyData))
	}
}

// -----------------------------------------------------------------------
// extensions.go: parseExtendedMasterSecret — non-empty body is rejected
// -----------------------------------------------------------------------.

func TestParseMessage_ExtendedMasterSecret_NonEmptyBody(t *testing.T) {
	t.Parallel()

	// Inject an extended_master_secret extension with a non-empty body
	// into a ServerHello. The EMS extension must have an empty body.
	//
	// Extension: type=0x0017, len=1, body={0xAA}.
	badEMSExt := []byte{
		0x00, 0x17, // extended_master_secret.
		0x00, 0x01, // length = 1.
		0xAA, // non-empty body (invalid).
	}
	extList := make([]byte, 2+len(badEMSExt))

	extList[0] = 0x00
	extList[1] = byte(len(badEMSExt))
	copy(extList[2:], badEMSExt)

	random := [32]byte{}
	base := &handshake.ServerHello{Version: 0x0303, Random: random, CipherSuite: 0x002F}
	baseBody := base.Marshal()

	wire := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeServerHello,
		Body:    append(baseBody, extList...),
	})

	_, _, err := handshake.ParseMessage(wire)
	if err == nil {
		t.Fatal("extended_master_secret with non-empty body: expected error, got nil")
	}

	if !strings.Contains(err.Error(), "extended_master_secret") {
		t.Errorf("error should mention extended_master_secret, got: %v", err)
	}
}

func TestParseMessage_ExtendedMasterSecret_EmptyBody(t *testing.T) {
	t.Parallel()

	// The valid EMS extension has an empty body.
	emsExt := []byte{
		0x00, 0x17, // extended_master_secret.
		0x00, 0x00, // length = 0.
	}
	extList := make([]byte, 2+len(emsExt))

	extList[0] = 0x00
	extList[1] = byte(len(emsExt))
	copy(extList[2:], emsExt)

	random := [32]byte{}
	base := &handshake.ServerHello{Version: 0x0303, Random: random, CipherSuite: 0x002F}
	baseBody := base.Marshal()

	wire := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeServerHello,
		Body:    append(baseBody, extList...),
	})

	msg, _, err := handshake.ParseMessage(wire)
	if err != nil {
		t.Fatalf("extended_master_secret with empty body: %v", err)
	}

	sh, ok := msg.(*handshake.ServerHello)
	if !ok {
		t.Fatalf("expected *ServerHello, got %T", msg)
	}

	if !sh.ExtendedMasterSecret {
		t.Error("ExtendedMasterSecret: got false, want true")
	}
}

// -----------------------------------------------------------------------
// types.go: ParseMessage — unknown message type
// -----------------------------------------------------------------------.

func TestParseMessage_UnknownType(t *testing.T) {
	t.Parallel()

	// Type 0x50 (80) is not a known handshake message type.
	wire := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.Type(0x50),
		Body:    []byte{0x01, 0x02},
	})

	_, _, err := handshake.ParseMessage(wire)
	if err == nil {
		t.Fatal("ParseMessage with unknown type 0x50: expected error, got nil")
	}

	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention 'unknown', got: %v", err)
	}
}

// -----------------------------------------------------------------------
// types.go: ParseMessage — truncated header
// -----------------------------------------------------------------------.

func TestParseMessage_TruncatedHeader(t *testing.T) {
	t.Parallel()

	// Fewer than 4 bytes (the minimum envelope size).
	_, _, err := handshake.ParseMessage([]byte{0x02, 0x00})
	if err == nil {
		t.Fatal("ParseMessage with 2-byte input: expected error, got nil")
	}
}

// -----------------------------------------------------------------------
// types.go: ParseMessage — body length mismatch
// -----------------------------------------------------------------------.

func TestParseMessage_BodyLengthMismatch(t *testing.T) {
	t.Parallel()

	// Build a valid ServerHelloDone (4 bytes total), then manually inflate
	// the declared body length to 5 while providing 0 bytes body.
	wire := []byte{
		byte(handshake.TypeServerHelloDone),
		0x00, 0x00, 0x05, // declared body length = 5.
		// but no body bytes follow.
	}

	_, _, err := handshake.ParseMessage(wire)
	if err == nil {
		t.Fatal("ParseMessage with body length mismatch: expected error, got nil")
	}
}

// -----------------------------------------------------------------------
// messages.go: Certificate — zero-length cert entry is rejected
// -----------------------------------------------------------------------.

func TestParseCertificate_ZeroLengthEntry(t *testing.T) {
	t.Parallel()

	// Wire: outer list length = 3, then one cert entry with length=0.
	// Format: [uint24 outer_len][uint24 cert_len][cert_bytes...].
	body := []byte{
		0x00, 0x00, 0x03, // outer list = 3 bytes.
		0x00, 0x00, 0x00, // cert entry length = 0 (invalid).
	}
	wire := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificate,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(wire)
	if err == nil {
		t.Fatal("parseCertificate with zero-length entry: expected error, got nil")
	}
}
