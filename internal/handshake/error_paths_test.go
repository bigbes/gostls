// Tests for the malformed-input / error branches that were below target
// coverage in wire.go, extensions.go, messages.go, crypto.go, and client.go.
//
//nolint:testpackage // white-box: exercises unexported parsing helpers
package handshake

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// ============================================================.
// wire.go — readUint16.
// ============================================================.

func TestReadUint16_Empty(t *testing.T) {
	t.Parallel()

	_, _, err := readUint16(nil)
	if err == nil {
		t.Fatal("readUint16(nil): expected error")
	}

	if !errors.Is(err, errTruncated2) {
		t.Errorf("got %v, want errTruncated2", err)
	}
}

func TestReadUint16_OneByte(t *testing.T) {
	t.Parallel()

	_, _, err := readUint16([]byte{0x01})
	if err == nil {
		t.Fatal("readUint16(1 byte): expected error")
	}

	if !errors.Is(err, errTruncated2) {
		t.Errorf("got %v, want errTruncated2", err)
	}
}

func TestReadUint16_Success(t *testing.T) {
	t.Parallel()

	v, rest, err := readUint16([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v != 0x0102 {
		t.Errorf("value: got 0x%04x, want 0x0102", v)
	}

	if !bytes.Equal(rest, []byte{0x03}) {
		t.Errorf("rest: got %x, want [03]", rest)
	}
}

// ============================================================.
// wire.go — readLenPrefixed8.
// ============================================================.

func TestReadLenPrefixed8_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed8(nil)
	if err == nil {
		t.Fatal("readLenPrefixed8(nil): expected error")
	}

	if !errors.Is(err, errPfxUint8) {
		t.Errorf("got %v, want errPfxUint8", err)
	}
}

func TestReadLenPrefixed8_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Length byte = 5 but only 2 bytes of body follow.
	_, _, err := readLenPrefixed8([]byte{0x05, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("readLenPrefixed8 body truncated: expected error")
	}

	if !errors.Is(err, errBodyShort) {
		t.Errorf("got %v, want errBodyShort", err)
	}
}

func TestReadLenPrefixed8_Success(t *testing.T) {
	t.Parallel()

	body, rest, err := readLenPrefixed8([]byte{0x02, 0xAA, 0xBB, 0xCC})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Errorf("body: got %x, want [AA BB]", body)
	}

	if !bytes.Equal(rest, []byte{0xCC}) {
		t.Errorf("rest: got %x, want [CC]", rest)
	}
}

// ============================================================.
// wire.go — readLenPrefixed16.
// ============================================================.

func TestReadLenPrefixed16_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed16(nil)
	if err == nil {
		t.Fatal("readLenPrefixed16(nil): expected error")
	}

	if !errors.Is(err, errPfxUint16) {
		t.Errorf("got %v, want errPfxUint16", err)
	}
}

func TestReadLenPrefixed16_OneByte(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed16([]byte{0x00})
	if err == nil {
		t.Fatal("readLenPrefixed16(1 byte): expected error")
	}

	if !errors.Is(err, errPfxUint16) {
		t.Errorf("got %v, want errPfxUint16", err)
	}
}

func TestReadLenPrefixed16_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Prefix declares 10 bytes, only 3 follow.
	_, _, err := readLenPrefixed16([]byte{0x00, 0x0A, 0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("readLenPrefixed16 body truncated: expected error")
	}

	if !errors.Is(err, errBodyShort) {
		t.Errorf("got %v, want errBodyShort", err)
	}
}

func TestReadLenPrefixed16_Success(t *testing.T) {
	t.Parallel()

	body, rest, err := readLenPrefixed16([]byte{0x00, 0x02, 0xAA, 0xBB, 0xCC})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Errorf("body: got %x, want [AA BB]", body)
	}

	if !bytes.Equal(rest, []byte{0xCC}) {
		t.Errorf("rest: got %x, want [CC]", rest)
	}
}

// ============================================================.
// wire.go — readLenPrefixed24.
// ============================================================.

func TestReadLenPrefixed24_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed24(nil)
	if err == nil {
		t.Fatal("readLenPrefixed24(nil): expected error")
	}

	if !errors.Is(err, errPfxUint24) {
		t.Errorf("got %v, want errPfxUint24", err)
	}
}

func TestReadLenPrefixed24_TwoBytesOnly(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed24([]byte{0x00, 0x00})
	if err == nil {
		t.Fatal("readLenPrefixed24(2 bytes): expected error")
	}

	if !errors.Is(err, errPfxUint24) {
		t.Errorf("got %v, want errPfxUint24", err)
	}
}

func TestReadLenPrefixed24_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Prefix declares 5 bytes, only 2 follow.
	_, _, err := readLenPrefixed24([]byte{0x00, 0x00, 0x05, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("readLenPrefixed24 body truncated: expected error")
	}

	if !errors.Is(err, errBodyShort) {
		t.Errorf("got %v, want errBodyShort", err)
	}
}

func TestReadLenPrefixed24_Success(t *testing.T) {
	t.Parallel()

	body, rest, err := readLenPrefixed24([]byte{0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Errorf("body: got %x, want [AA BB]", body)
	}

	if !bytes.Equal(rest, []byte{0xCC}) {
		t.Errorf("rest: got %x, want [CC]", rest)
	}
}

// ============================================================.
// extensions.go — parseServerName.
// ============================================================.

func TestParseServerName_EmptyBody(t *testing.T) {
	t.Parallel()

	// Empty body is valid in ServerHello — returns ("", nil).
	name, err := parseServerName(nil)
	if err != nil {
		t.Fatalf("empty body should be OK: %v", err)
	}

	if name != "" {
		t.Errorf("expected empty name, got %q", name)
	}
}

func TestParseServerName_TruncatedListLen(t *testing.T) {
	t.Parallel()

	// 1 byte only — need 2 for the uint16 list length.
	_, err := parseServerName([]byte{0x00})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, errSNITruncatedListLen) {
		t.Errorf("got %v, want errSNITruncatedListLen", err)
	}
}

func TestParseServerName_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=100 but only 2 bytes of data follow the length field.
	_, err := parseServerName([]byte{0x00, 0x64, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errSNIListLenExceeds, got nil")
	}

	if !errors.Is(err, errSNIListLenExceeds) {
		t.Errorf("got %v, want errSNIListLenExceeds", err)
	}
}

func TestParseServerName_TruncatedEntry(t *testing.T) {
	t.Parallel()

	// list_len = 2, content = [0xAA, 0xBB] — too short for min entry (3 bytes).
	_, err := parseServerName([]byte{0x00, 0x02, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errSNITruncatedEntry, got nil")
	}

	if !errors.Is(err, errSNITruncatedEntry) {
		t.Errorf("got %v, want errSNITruncatedEntry", err)
	}
}

func TestParseServerName_NameLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=5: [type=0x00, name_len_hi=0x00, name_len_lo=0x64, AA, BB].
	// name_len=100 but list only has 2 bytes after the 3-byte header.
	_, err := parseServerName([]byte{0x00, 0x05, 0x00, 0x00, 0x64, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errSNINameLenExceeds, got nil")
	}

	if !errors.Is(err, errSNINameLenExceeds) {
		t.Errorf("got %v, want errSNINameLenExceeds", err)
	}
}

func TestParseServerName_UnsupportedNameType(t *testing.T) {
	t.Parallel()

	// name_type = 0x01 (not host_name=0x00). list_len=6: type=0x01, name_len=3, name=[AA BB CC].
	_, err := parseServerName([]byte{0x00, 0x06, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC})
	if err == nil {
		t.Fatal("expected errSNIUnsupportedNameType, got nil")
	}

	if !errors.Is(err, errSNIUnsupportedNameType) {
		t.Errorf("got %v, want errSNIUnsupportedNameType", err)
	}
}

func TestParseServerName_HappyPath(t *testing.T) {
	t.Parallel()

	name := "example.com"
	body := marshalServerName(name)

	got, err := parseServerName(body)
	if err != nil {
		t.Fatalf("parseServerName(%q): %v", name, err)
	}

	if got != name {
		t.Errorf("got %q, want %q", got, name)
	}
}

// ============================================================.
// extensions.go — parseSupportedGroups.
// ============================================================.

func TestParseSupportedGroups_TruncatedListLen(t *testing.T) {
	t.Parallel()

	// Only 1 byte when 2 are needed for the list length.
	_, err := parseSupportedGroups([]byte{0x00})
	if err == nil {
		t.Fatal("expected errSGTruncatedListLen, got nil")
	}

	if !errors.Is(err, errSGTruncatedListLen) {
		t.Errorf("got %v, want errSGTruncatedListLen", err)
	}
}

func TestParseSupportedGroups_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=100 but only 2 bytes of data follow.
	_, err := parseSupportedGroups([]byte{0x00, 0x64, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errSGListLenExceeds, got nil")
	}

	if !errors.Is(err, errSGListLenExceeds) {
		t.Errorf("got %v, want errSGListLenExceeds", err)
	}
}

func TestParseSupportedGroups_OddListLen(t *testing.T) {
	t.Parallel()

	// list_len=3 (odd) with 3 bytes of data.
	_, err := parseSupportedGroups([]byte{0x00, 0x03, 0xAA, 0xBB, 0xCC})
	if err == nil {
		t.Fatal("expected errSGOddListLen, got nil")
	}

	if !errors.Is(err, errSGOddListLen) {
		t.Errorf("got %v, want errSGOddListLen", err)
	}
}

func TestParseSupportedGroups_HappyPath(t *testing.T) {
	t.Parallel()

	groups := []uint16{0x0017, 0x0018}
	body := marshalSupportedGroups(groups)

	got, err := parseSupportedGroups(body)
	if err != nil {
		t.Fatalf("parseSupportedGroups: %v", err)
	}

	if len(got) != len(groups) {
		t.Fatalf("len: got %d, want %d", len(got), len(groups))
	}

	for i, g := range groups {
		if got[i] != g {
			t.Errorf("[%d]: got 0x%04x, want 0x%04x", i, got[i], g)
		}
	}
}

// ============================================================.
// extensions.go — parseSignatureAlgorithms.
// ============================================================.

func TestParseSignatureAlgorithms_TruncatedListLen(t *testing.T) {
	t.Parallel()

	_, err := parseSignatureAlgorithms([]byte{0x00})
	if err == nil {
		t.Fatal("expected errSATruncatedListLen, got nil")
	}

	if !errors.Is(err, errSATruncatedListLen) {
		t.Errorf("got %v, want errSATruncatedListLen", err)
	}
}

func TestParseSignatureAlgorithms_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=100 but only 2 bytes follow.
	_, err := parseSignatureAlgorithms([]byte{0x00, 0x64, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errSAListLenExceeds, got nil")
	}

	if !errors.Is(err, errSAListLenExceeds) {
		t.Errorf("got %v, want errSAListLenExceeds", err)
	}
}

func TestParseSignatureAlgorithms_OddListLen(t *testing.T) {
	t.Parallel()

	// list_len=3 (odd) with 3 bytes of data.
	_, err := parseSignatureAlgorithms([]byte{0x00, 0x03, 0x04, 0x01, 0x05})
	if err == nil {
		t.Fatal("expected errSAOddListLen, got nil")
	}

	if !errors.Is(err, errSAOddListLen) {
		t.Errorf("got %v, want errSAOddListLen", err)
	}
}

func TestParseSignatureAlgorithms_HappyPath(t *testing.T) {
	t.Parallel()

	pairs := []SigAndHash{{Hash: 0x04, Sig: 0x01}, {Hash: 0x05, Sig: 0x03}}
	body := marshalSignatureAlgorithms(pairs)

	got, err := parseSignatureAlgorithms(body)
	if err != nil {
		t.Fatalf("parseSignatureAlgorithms: %v", err)
	}

	if len(got) != len(pairs) {
		t.Fatalf("len: got %d, want %d", len(got), len(pairs))
	}

	for i, p := range pairs {
		if got[i] != p {
			t.Errorf("[%d]: got %v, want %v", i, got[i], p)
		}
	}
}

// ============================================================.
// extensions.go — parseECPointFormats.
// ============================================================.

func TestParseECPointFormats_EmptyInput(t *testing.T) {
	t.Parallel()

	_, err := parseECPointFormats(nil)
	if err == nil {
		t.Fatal("expected errEPFTruncatedListLen, got nil")
	}

	if !errors.Is(err, errEPFTruncatedListLen) {
		t.Errorf("got %v, want errEPFTruncatedListLen", err)
	}
}

func TestParseECPointFormats_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// Length byte = 10, but only 2 bytes follow.
	_, err := parseECPointFormats([]byte{0x0A, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errEPFListLenExceeds, got nil")
	}

	if !errors.Is(err, errEPFListLenExceeds) {
		t.Errorf("got %v, want errEPFListLenExceeds", err)
	}
}

func TestParseECPointFormats_HappyPath(t *testing.T) {
	t.Parallel()

	formats := []uint8{0x00, 0x01}
	body := marshalECPointFormats(formats)

	got, err := parseECPointFormats(body)
	if err != nil {
		t.Fatalf("parseECPointFormats: %v", err)
	}

	if len(got) != len(formats) {
		t.Fatalf("len: got %d, want %d", len(got), len(formats))
	}

	for i, f := range formats {
		if got[i] != f {
			t.Errorf("[%d]: got 0x%02x, want 0x%02x", i, got[i], f)
		}
	}
}

// ============================================================.
// extensions.go — parseRenegotiationInfo.
// ============================================================.

func TestParseRenegotiationInfo_EmptyInput(t *testing.T) {
	t.Parallel()

	err := parseRenegotiationInfo(nil)
	if err == nil {
		t.Fatal("expected errRITruncatedBody, got nil")
	}

	if !errors.Is(err, errRITruncatedBody) {
		t.Errorf("got %v, want errRITruncatedBody", err)
	}
}

func TestParseRenegotiationInfo_DeclaredLenExceeds(t *testing.T) {
	t.Parallel()

	// ri_len=5 but only 2 bytes of data follow the length byte.
	err := parseRenegotiationInfo([]byte{0x05, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errRIDeclaredLenExceeds, got nil")
	}

	if !errors.Is(err, errRIDeclaredLenExceeds) {
		t.Errorf("got %v, want errRIDeclaredLenExceeds", err)
	}
}

func TestParseRenegotiationInfo_NonEmpty(t *testing.T) {
	t.Parallel()

	// ri_len=2 with 2 bytes — body is non-empty (renegotiation active).
	err := parseRenegotiationInfo([]byte{0x02, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected errRINonEmpty, got nil")
	}

	if !errors.Is(err, errRINonEmpty) {
		t.Errorf("got %v, want errRINonEmpty", err)
	}
}

func TestParseRenegotiationInfo_EmptyRIBody(t *testing.T) {
	t.Parallel()

	// ri_len=0 — valid initial-handshake marker.
	err := parseRenegotiationInfo([]byte{0x00})
	if err != nil {
		t.Fatalf("empty RI body should be OK: %v", err)
	}
}

// ============================================================.
// extensions.go — parseExtensions (header-level errors).
// ============================================================.

func TestParseExtensions_TruncatedHeader(t *testing.T) {
	t.Parallel()

	// 3 bytes — need 4 for the extension header (type=2 + len=2).
	_, err := parseExtensions([]byte{0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected errExtHeaderTruncated, got nil")
	}

	if !errors.Is(err, errExtHeaderTruncated) {
		t.Errorf("got %v, want errExtHeaderTruncated", err)
	}
}

func TestParseExtensions_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Header: type=0x0000 (SNI), len=10 — but only 0 bytes of body follow.
	_, err := parseExtensions([]byte{0x00, 0x00, 0x00, 0x0A})
	if err == nil {
		t.Fatal("expected errExtBodyTruncated, got nil")
	}

	if !errors.Is(err, errExtBodyTruncated) {
		t.Errorf("got %v, want errExtBodyTruncated", err)
	}
}

// ============================================================.
// messages.go — parseClientHello error paths.
// ============================================================.

// buildMinimalClientHelloBytes marshals a valid minimal ClientHello body.
func buildMinimalClientHelloBytes() []byte {
	ch := &ClientHello{
		Version:            0x0303,
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
	}

	return ch.Marshal()
}

func TestParseClientHello_TruncatedVersion(t *testing.T) {
	t.Parallel()

	// Only 1 byte — can't read 2-byte version.
	_, err := parseClientHello([]byte{0x03})
	if err == nil {
		t.Fatal("expected error for truncated version, got nil")
	}
}

func TestParseClientHello_TruncatedRandom(t *testing.T) {
	t.Parallel()

	// version OK, but random needs 32 bytes and we only have 4.
	_, err := parseClientHello([]byte{0x03, 0x03, 0x01, 0x02, 0x03, 0x04})
	if err == nil {
		t.Fatal("expected error for truncated random, got nil")
	}
}

func TestParseClientHello_SessionIDTooLong(t *testing.T) {
	t.Parallel()

	// Build a valid CH body and inject a session_id length of 33 at offset 34.
	// The session_id starts at offset 34 (2 version + 32 random).
	body := buildMinimalClientHelloBytes()
	sessionIDOffset := 34

	injected := make([]byte, sessionIDOffset+1+33)
	copy(injected, body[:sessionIDOffset])

	injected[sessionIDOffset] = 33 // length byte = 33 > maxSessionIDLen(32).

	for i := 1; i <= 33; i++ {
		injected[sessionIDOffset+i] = byte(i)
	}

	_, err := parseClientHello(injected)
	if err == nil {
		t.Fatal("expected errCHSessionIDTooLong, got nil")
	}

	if !errors.Is(err, errCHSessionIDTooLong) {
		t.Errorf("got %v, want errCHSessionIDTooLong", err)
	}
}

func TestParseClientHello_CSOddByteCount(t *testing.T) {
	t.Parallel()

	// After version(2) + random(32) + session_id(1+0), cipher_suites has odd byte count.
	body := make([]byte, 0, 40)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id length = 0.
	body = append(body, 0x00, 0x03)          // cipher_suites byte_len = 3 (odd).
	body = append(body, 0x00, 0x2F, 0x01)    // 3 bytes (invalid).

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("expected errCHCSOddByteCount, got nil")
	}

	if !errors.Is(err, errCHCSOddByteCount) {
		t.Errorf("got %v, want errCHCSOddByteCount", err)
	}
}

func TestParseClientHello_CSAtLeastOne(t *testing.T) {
	t.Parallel()

	// cipher_suites length = 0 — must have at least one.
	body := make([]byte, 0, 38)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id length = 0.
	body = append(body, 0x00, 0x00)          // cipher_suites: 0 bytes.

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("expected errCHCSAtLeastOne, got nil")
	}

	if !errors.Is(err, errCHCSAtLeastOne) {
		t.Errorf("got %v, want errCHCSAtLeastOne", err)
	}
}

func TestParseClientHello_CMAtLeastOne(t *testing.T) {
	t.Parallel()

	// compression_methods length = 0 — must have at least one.
	body := make([]byte, 0, 41)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id length = 0.
	body = append(body, 0x00, 0x02)          // cipher_suites: 2 bytes.
	body = append(body, 0x00, 0x2F)          // one suite.
	body = append(body, 0x00)                // compression_methods length = 0.

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("expected errCHCMAtLeastOne, got nil")
	}

	if !errors.Is(err, errCHCMAtLeastOne) {
		t.Errorf("got %v, want errCHCMAtLeastOne", err)
	}
}

func TestParseClientHello_ExtensionsTruncated(t *testing.T) {
	t.Parallel()

	// Valid minimal CH body, then append a 1-byte "extensions" section
	// (the outer uint16 prefix needs 2 bytes).
	body := buildMinimalClientHelloBytes()

	body = append(body, 0x00) // only 1 byte where 2 needed.

	_, err := parseClientHello(body)
	if err == nil {
		t.Fatal("expected error for truncated extensions length, got nil")
	}
}

// ============================================================.
// messages.go — parseServerHello error paths.
// ============================================================.

func TestParseServerHello_TruncatedVersion(t *testing.T) {
	t.Parallel()

	_, err := parseServerHello([]byte{0x03})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestParseServerHello_TruncatedRandom(t *testing.T) {
	t.Parallel()

	_, err := parseServerHello([]byte{0x03, 0x03, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated random, got nil")
	}
}

func TestParseServerHello_SessionIDTooLong(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len(1)+data(33) — session_id > 32.
	body := make([]byte, 0, 68)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x21)                // session_id_len = 33 > 32.
	body = append(body, make([]byte, 33)...) // session_id data.

	_, err := parseServerHello(body)
	if err == nil {
		t.Fatal("expected errSHSessionIDTooLong, got nil")
	}

	if !errors.Is(err, errSHSessionIDTooLong) {
		t.Errorf("got %v, want errSHSessionIDTooLong", err)
	}
}

func TestParseServerHello_TruncatedCipherSuite(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len(1)=0 + only 1 byte of cipher_suite.
	body := make([]byte, 0, 36)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id_len = 0.
	body = append(body, 0x00)                // only 1 byte of cipher_suite (need 2).

	_, err := parseServerHello(body)
	if err == nil {
		t.Fatal("expected error for truncated cipher_suite, got nil")
	}
}

func TestParseServerHello_TruncatedCompressionMethod(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len(1)=0 + cipher_suite(2) — no compression_method.
	body := make([]byte, 0, 37)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id_len = 0.
	body = append(body, 0x00, 0x2F)          // cipher_suite.
	// compression_method byte absent.

	_, err := parseServerHello(body)
	if err == nil {
		t.Fatal("expected error for missing compression_method, got nil")
	}
}

func TestParseServerHello_ExtensionsTruncated(t *testing.T) {
	t.Parallel()

	sh := &ServerHello{
		Version:           0x0303,
		CipherSuite:       0x002F,
		CompressionMethod: 0x00,
	}
	body := sh.Marshal()

	body = append(body, 0x00) // only 1 byte of extensions prefix (need 2).

	_, err := parseServerHello(body)
	if err == nil {
		t.Fatal("expected error for truncated extensions, got nil")
	}
}

// ============================================================.
// messages.go — parseCertificate error paths.
// ============================================================.

func TestParseCertificate_TruncatedOuterLen(t *testing.T) {
	t.Parallel()

	// Only 2 bytes — need 3 for the outer uint24 length prefix.
	_, err := parseCertificate([]byte{0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated outer length, got nil")
	}
}

func TestParseCertificate_OuterLenExceedsData(t *testing.T) {
	t.Parallel()

	// outer_len=100 but only 2 bytes of cert list follow.
	_, err := parseCertificate([]byte{0x00, 0x00, 0x64, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected error for outer_len > data, got nil")
	}
}

func TestParseCertificate_EntryLenExceedsData(t *testing.T) {
	t.Parallel()

	// outer_len=6: entry_len=100 but only 2 bytes follow in the list.
	_, err := parseCertificate([]byte{0x00, 0x00, 0x06, 0x00, 0x00, 0x64, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected error for entry_len > data, got nil")
	}
}

func TestParseCertificate_ZeroLengthEntry(t *testing.T) {
	t.Parallel()

	// outer_len=3: entry_len=0 → errCertEntryZeroLen.
	_, err := parseCertificate([]byte{0x00, 0x00, 0x03, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected errCertEntryZeroLen, got nil")
	}

	if !errors.Is(err, errCertEntryZeroLen) {
		t.Errorf("got %v, want errCertEntryZeroLen", err)
	}
}

func TestParseCertificate_HappyPath(t *testing.T) {
	t.Parallel()

	cert := &Certificate{RawCerts: [][]byte{{0x30, 0x01, 0xAA}}}
	body := cert.Marshal()

	got, err := parseCertificate(body)
	if err != nil {
		t.Fatalf("parseCertificate: %v", err)
	}

	if len(got.RawCerts) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(got.RawCerts))
	}

	if !bytes.Equal(got.RawCerts[0], cert.RawCerts[0]) {
		t.Errorf("cert mismatch: got %x, want %x", got.RawCerts[0], cert.RawCerts[0])
	}
}

// ============================================================.
// messages.go — parseCertificateVerify error paths.
// ============================================================.

func TestParseCertificateVerify_TruncatedHash(t *testing.T) {
	t.Parallel()

	// Empty body — can't read hash byte.
	_, err := parseCertificateVerify(nil)
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

func TestParseCertificateVerify_TruncatedSig(t *testing.T) {
	t.Parallel()

	// hash=0x04, sig=0x01, but no sig_len or sig data.
	_, err := parseCertificateVerify([]byte{0x04, 0x01})
	if err == nil {
		t.Fatal("expected error for missing sig_len, got nil")
	}
}

func TestParseCertificateVerify_SigTruncated(t *testing.T) {
	t.Parallel()

	// hash=0x04, sig=0x01, sig_len=10 but only 2 bytes of sig data.
	_, err := parseCertificateVerify([]byte{0x04, 0x01, 0x00, 0x0A, 0xAA, 0xBB})
	if err == nil {
		t.Fatal("expected error for truncated sig, got nil")
	}
}

func TestParseCertificateVerify_HappyPath(t *testing.T) {
	t.Parallel()

	cv := &CertificateVerify{
		Algorithm: SigAndHash{Hash: 0x04, Sig: 0x01},
		Signature: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	body := cv.Marshal()

	got, err := parseCertificateVerify(body)
	if err != nil {
		t.Fatalf("parseCertificateVerify: %v", err)
	}

	if got.Algorithm != cv.Algorithm {
		t.Errorf("algorithm: got %v, want %v", got.Algorithm, cv.Algorithm)
	}

	if !bytes.Equal(got.Signature, cv.Signature) {
		t.Errorf("signature mismatch")
	}
}

// ============================================================.
// crypto.go — buildProtector: unsupported AEAD and MAC branches.
// ============================================================.

func TestBuildProtector_UnsupportedAEAD(t *testing.T) {
	t.Parallel()

	// Synthesise a suite with AEAD=true but an unrecognised cipher name.
	validSuite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-GCM-SHA256")
	fakeSuite := *validSuite

	fakeSuite.Cipher.Name = "AES-128-OCB" // not AES-GCM or ChaCha20.

	_, err := buildProtector(&fakeSuite, make([]byte, 16), nil, make([]byte, 4), nil)
	if err == nil {
		t.Fatal("expected errUnsupportedAEAD, got nil")
	}

	if !errors.Is(err, errUnsupportedAEAD) {
		t.Errorf("got %v, want errUnsupportedAEAD", err)
	}
}

func TestBuildProtector_UnsupportedMACLen(t *testing.T) {
	t.Parallel()

	// CBC suite with an unusual MAC length (not 20/32/48).
	validSuite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-SHA256")
	fakeSuite := *validSuite

	fakeSuite.MAC.MACLen = 24 // unsupported.

	_, err := buildProtector(&fakeSuite, make([]byte, 16), make([]byte, 24), nil, nil)
	if err == nil {
		t.Fatal("expected errUnsupportedMACLen, got nil")
	}

	if !errors.Is(err, errUnsupportedMACLen) {
		t.Errorf("got %v, want errUnsupportedMACLen", err)
	}
}

func TestBuildProtector_UnsupportedCBCCipher(t *testing.T) {
	t.Parallel()

	// CBC suite with an unrecognised cipher name.
	validSuite := mustFindSuiteByName(t, "ECDHE-RSA-AES128-SHA256")
	fakeSuite := *validSuite

	fakeSuite.Cipher.Name = "DES-CBC" // not AES.

	_, err := buildProtector(&fakeSuite, make([]byte, 8), make([]byte, 20), nil, nil)
	if err == nil {
		t.Fatal("expected errUnsupportedCBCCipher, got nil")
	}

	if !errors.Is(err, errUnsupportedCBCCipher) {
		t.Errorf("got %v, want errUnsupportedCBCCipher", err)
	}
}

func TestBuildProtector_SHA1MAC(t *testing.T) {
	t.Parallel()

	// Exercise the SHA-1 HMAC branch (MACLen=20).
	var suite *suites.Suite

	for _, s := range suites.All() {
		if !s.Cipher.AEAD && s.Cipher.Name == "AES-128-CBC" && s.MAC.MACLen == 20 {
			suite = s

			break
		}
	}

	if suite == nil {
		t.Skip("no AES-128-CBC/SHA-1 suite in registry")
	}

	prot, err := buildProtector(suite, make([]byte, suite.Cipher.KeyLen), make([]byte, suite.MAC.KeyLen), nil, nil)
	if err != nil {
		t.Fatalf("buildProtector SHA-1 CBC: %v", err)
	}

	if prot == nil {
		t.Error("expected non-nil protector")
	}
}

// ============================================================.
// client.go — computeKeyExchange: DHE dispatch.
// ============================================================.

func TestComputeKeyExchange_DHE(t *testing.T) {
	t.Parallel()

	rsaKey, cert, _ := newTestRSACert(t)

	var clientRandom, serverRandom [32]byte

	for i := range clientRandom {
		clientRandom[i] = byte(i + 1)
		serverRandom[i] = byte(i + 2)
	}

	dheBody := buildDHESKEBodyReal(t, rsaKey, clientRandom, serverRandom)

	suite := mustLookupSuite(t, "DHE-RSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	// Get the serverParams by verifying the SKE first.
	serverParams, err := c.verifyDHEServerKeyExchange(dheBody, cert)
	if err != nil {
		t.Fatalf("verifyDHEServerKeyExchange: %v", err)
	}

	preMaster, ckeBody, err := c.computeKeyExchange(cert, serverParams, nil)
	if err != nil {
		t.Fatalf("computeKeyExchange(DHE): %v", err)
	}

	if len(preMaster) == 0 {
		t.Error("preMaster should be non-empty")
	}

	if len(ckeBody) == 0 {
		t.Error("ckeBody should be non-empty")
	}
}

// ============================================================.
// client.go — sendCertificateVerify: unknown hash alg branch.
// ============================================================.

func TestSendCertificateVerify_UnknownHashAlg(t *testing.T) {
	t.Parallel()

	rsaKey, _, _ := newTestRSACert(t)

	layer, _ := makeRecordLayerWithCapture()

	c := &ClientState{
		params: ClientParams{
			Rand:         nil,
			Certificates: []ClientCertificate{{PrivateKey: rsaKey}},
		},
		layer:      layer,
		transcript: NewTranscript(),
	}

	// hash byte 0xFF is unknown — hashForSigAlg should return an error.
	alg := SigAndHash{Hash: 0xFF, Sig: 0x01}

	err := c.sendCertificateVerify(alg)
	if err == nil {
		t.Fatal("expected error for unknown hash alg, got nil")
	}

	if !errors.Is(err, errUnsupportedHashAlg) {
		t.Errorf("got %v, want errUnsupportedHashAlg", err)
	}
}

// ============================================================.
// client.go — recvCertificate: wrong message type.
// ============================================================.

func TestRecvCertificate_WrongMsgType(t *testing.T) {
	t.Parallel()

	// Send a ServerHelloDone instead of Certificate.
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shdRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	suite := mustLookupSuite(t, "AES128-SHA256")

	c.suite = suite

	_, _, err := c.recvCertificate()
	if err == nil {
		t.Fatal("expected error for wrong message type, got nil")
	}

	if !errors.Is(err, errExpectedCertificate) {
		t.Errorf("got %v, want errExpectedCertificate", err)
	}
}

func TestRecvCertificate_EmptyList(t *testing.T) {
	t.Parallel()

	// Send an empty Certificate message (zero certs in list).
	certMsg := &Certificate{}
	certRec := buildHSRecord(TypeCertificate, certMsg.Marshal())

	rw := &readWriteBuffer{r: bytes.NewBuffer(certRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	suite := mustLookupSuite(t, "AES128-SHA256")

	c.suite = suite

	_, _, err := c.recvCertificate()
	if err == nil {
		t.Fatal("expected errEmptyCertList, got nil")
	}

	if !errors.Is(err, errEmptyCertList) {
		t.Errorf("got %v, want errEmptyCertList", err)
	}
}

// ============================================================.
// client.go — recvServerFlight: SKE required for ECDHE but missing.
// ============================================================.

func TestRecvServerFlight_SKERequired_ECDHE(t *testing.T) {
	t.Parallel()

	// ECDHE suite but only SHD — no SKE. Should fail with errSKERequired.
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	suite := mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256")
	c := makeClientStateForFlight(t, shdRec, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("expected errSKERequired, got nil")
	}

	if !errors.Is(err, errSKERequired) {
		t.Errorf("got %v, want errSKERequired", err)
	}
}

func TestRecvServerFlight_DuplicateSKE(t *testing.T) {
	t.Parallel()

	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	skeBody := buildECDHESKEBody(t, priv, clientRandom, serverRandom)
	skeRec := buildHSRecord(TypeServerKeyExchange, skeBody)
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	// Two SKE records before SHD.
	wire := append(append(append([]byte{}, skeRec...), skeRec...), shdRec...)

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeClientStateForFlight(t, wire, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	_, err := c.recvServerFlight(cert)
	if err == nil {
		t.Fatal("expected errDuplicateSKE, got nil")
	}

	if !errors.Is(err, errDuplicateSKE) {
		t.Errorf("got %v, want errDuplicateSKE", err)
	}
}

func TestRecvServerFlight_UnexpectedMsgType(t *testing.T) {
	t.Parallel()

	// Send a ClientHello (type 0x01) in the server flight — should be rejected.
	body := buildMinimalClientHelloBytes()
	unexpectedRec := buildHSRecord(TypeClientHello, body)
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	wire := append(append([]byte{}, unexpectedRec...), shdRec...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA.
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	if err == nil {
		t.Fatal("expected errUnexpectedFlightMsg, got nil")
	}

	if !errors.Is(err, errUnexpectedFlightMsg) {
		t.Errorf("got %v, want errUnexpectedFlightMsg", err)
	}
}

// ============================================================.
// client.go — verifyECDHEServerKeyExchange error paths.
// ============================================================.

func TestVerifyECDHESKE_TooShort(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	_, err := c.verifyECDHEServerKeyExchange([]byte{0x03, 0x00}, cert)
	if err == nil {
		t.Fatal("expected errECDHESKETooShort, got nil")
	}

	if !errors.Is(err, errECDHESKETooShort) {
		t.Errorf("got %v, want errECDHESKETooShort", err)
	}
}

func TestVerifyECDHESKE_UnsupportedCurveType(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x01 (not 0x03 = named_curve).
	body := []byte{0x01, 0x00, 0x17, 0x00}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("expected errECDHEUnsupportedCT, got nil")
	}

	if !errors.Is(err, errECDHEUnsupportedCT) {
		t.Errorf("got %v, want errECDHEUnsupportedCT", err)
	}
}

func TestVerifyECDHESKE_BodyTruncatedAfterPoint(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x03, named_curve=0x0017, point_len=65, but only 2 bytes of point follow.
	// minECDHEBodyLen(4) + pointLen(65) + sigSectionMin(2) = 71 needed but only 6 provided.
	body := []byte{0x03, 0x00, 0x17, 0x41, 0xAA, 0xBB}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("expected errECDHEBodyTruncated, got nil")
	}

	if !errors.Is(err, errECDHEBodyTruncated) {
		t.Errorf("got %v, want errECDHEBodyTruncated", err)
	}
}

func TestVerifyECDHESKE_SigSectionTooShort(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x03, named_curve=0x0017, point_len=1, point=[0xFF].
	// sigData starts at offset 5. First body-truncation check requires
	// len(body) >= 4 + pointLen(1) + sigSectionMin(2) = 7 → must pass.
	// sigDataMin=4 requires sigData length >= 4.
	// We supply exactly 7 bytes so sigData has 2 bytes (< 4) → errECDHESigSectionShort.
	body := []byte{0x03, 0x00, 0x17, 0x01, 0xFF, 0x04, 0x01}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("expected errECDHESigSectionShort, got nil")
	}

	if !errors.Is(err, errECDHESigSectionShort) {
		t.Errorf("got %v, want errECDHESigSectionShort", err)
	}
}

func TestVerifyECDHESKE_SigTruncated(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x03, named_curve=0x0017, point_len=1, point=[0xFF].
	// sigData: hashAlg=0x04, sigAlg=0x01, sig_len=100, but only 1 byte of sig.
	body := []byte{0x03, 0x00, 0x17, 0x01, 0xFF, 0x04, 0x01, 0x00, 0x64, 0xAA}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	if err == nil {
		t.Fatal("expected errECDHESigTruncated, got nil")
	}

	if !errors.Is(err, errECDHESigTruncated) {
		t.Errorf("got %v, want errECDHESigTruncated", err)
	}
}
