// Package handshake provides TLS 1.2 handshake message marshaling/unmarshaling
// and the multi-hash transcript accumulator (RFC 5246 §7.4).
//
// Only wire-format work is done here. No TLS state machine, no key derivation.
package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// bitsPerByte is used in byte-extraction shift expressions to avoid magic-number warnings.
const (
	bitsPerByte   = 8
	bitsPerUint16 = 2 * bitsPerByte // 16 bits.
)

// Sentinel errors for wire-parsing failures.
var (
	errTruncated1 = errors.New("handshake: truncated: need 1 byte")
	errTruncated2 = errors.New("handshake: truncated: need 2 bytes")
	errPfxUint8   = errors.New("handshake: truncated length prefix (uint8)")
	errPfxUint16  = errors.New("handshake: truncated length prefix (uint16)")
	errPfxUint24  = errors.New("handshake: truncated length prefix (uint24)")
	errNeedBytes  = errors.New("handshake: truncated: insufficient bytes")
	errBodyShort  = errors.New("handshake: truncated body")
)

// readUint8 reads one byte from b and returns the value and remaining slice.
// Returns an error if b is empty.
func readUint8(b []byte) (uint8, []byte, error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("%w, have %d", errTruncated1, len(b))
	}

	return b[0], b[1:], nil
}

// readUint16 reads a big-endian uint16 from b.
func readUint16(b []byte) (uint16, []byte, error) {
	const need = 2 // uint16 is 2 bytes.

	if len(b) < need {
		return 0, nil, fmt.Errorf("%w, have %d", errTruncated2, len(b))
	}

	return binary.BigEndian.Uint16(b[:need]), b[need:], nil
}

// readBytes reads exactly n bytes from b.
func readBytes(b []byte, n int) ([]byte, []byte, error) {
	if len(b) < n {
		return nil, nil, fmt.Errorf("%w: need %d bytes, have %d", errNeedBytes, n, len(b))
	}

	return b[:n], b[n:], nil
}

// readLenPrefixed8 reads a uint8-length-prefixed blob.
func readLenPrefixed8(b []byte) ([]byte, []byte, error) {
	if len(b) < 1 {
		return nil, nil, errPfxUint8
	}

	length := int(b[0])

	b = b[1:]

	if len(b) < length {
		return nil, nil, fmt.Errorf("%w: declared %d bytes, have %d", errBodyShort, length, len(b))
	}

	return b[:length], b[length:], nil
}

// readLenPrefixed16 reads a uint16-length-prefixed blob.
func readLenPrefixed16(b []byte) ([]byte, []byte, error) {
	const pfxLen = 2 // uint16 prefix is 2 bytes.

	if len(b) < pfxLen {
		return nil, nil, errPfxUint16
	}

	length := int(binary.BigEndian.Uint16(b[:pfxLen]))

	b = b[pfxLen:]

	if len(b) < length {
		return nil, nil, fmt.Errorf("%w: declared %d bytes, have %d", errBodyShort, length, len(b))
	}

	return b[:length], b[length:], nil
}

// readLenPrefixed24 reads a 3-byte-length-prefixed blob.
func readLenPrefixed24(b []byte) ([]byte, []byte, error) {
	const pfxLen = 3 // uint24 prefix is 3 bytes.

	if len(b) < pfxLen {
		return nil, nil, errPfxUint24
	}

	length := int(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]))

	b = b[pfxLen:]

	if len(b) < length {
		return nil, nil, fmt.Errorf("%w: declared %d bytes, have %d", errBodyShort, length, len(b))
	}

	return b[:length], b[length:], nil
}

// appendUint8 appends a single byte.
func appendUint8(dst []byte, v uint8) []byte {
	return append(dst, v)
}

// appendUint16 appends a big-endian uint16.
func appendUint16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>bitsPerByte), byte(v))
}

// appendUint24 appends a 3-byte big-endian integer.
func appendUint24(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>bitsPerUint16), byte(v>>bitsPerByte), byte(v))
}

// appendLenPrefixed8 appends a uint8-length-prefixed blob.
// Caller must ensure len(data) <= 255; Go truncates the length on conversion,
// producing a malformed message for over-length inputs.
func appendLenPrefixed8(dst, data []byte) []byte {
	dst = appendUint8(dst, uint8(len(data)))
	return append(dst, data...)
}

// appendLenPrefixed16 appends a uint16-length-prefixed blob.
func appendLenPrefixed16(dst, data []byte) []byte {
	dst = appendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}
