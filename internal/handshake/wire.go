// Package handshake provides TLS 1.2 handshake message marshaling/unmarshaling
// and the multi-hash transcript accumulator (RFC 5246 §7.4).
//
// Only wire-format work is done here. No TLS state machine, no key derivation.
package handshake

import (
	"encoding/binary"
	"fmt"
)

// readUint8 reads one byte from b and returns the value and remaining slice.
// Returns an error if b is empty.
func readUint8(b []byte) (uint8, []byte, error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("handshake: truncated: need 1 byte, have %d", len(b))
	}
	return b[0], b[1:], nil
}

// readUint16 reads a big-endian uint16 from b.
func readUint16(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, fmt.Errorf("handshake: truncated: need 2 bytes, have %d", len(b))
	}
	return binary.BigEndian.Uint16(b[:2]), b[2:], nil
}

// readUint24 reads a 3-byte big-endian uint32 from b.
func readUint24(b []byte) (uint32, []byte, error) {
	if len(b) < 3 {
		return 0, nil, fmt.Errorf("handshake: truncated: need 3 bytes, have %d", len(b))
	}
	v := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	return v, b[3:], nil
}

// readBytes reads exactly n bytes from b.
func readBytes(b []byte, n int) ([]byte, []byte, error) {
	if len(b) < n {
		return nil, nil, fmt.Errorf("handshake: truncated: need %d bytes, have %d", n, len(b))
	}
	return b[:n], b[n:], nil
}

// readLenPrefixed8 reads a uint8-length-prefixed blob.
func readLenPrefixed8(b []byte) ([]byte, []byte, error) {
	if len(b) < 1 {
		return nil, nil, fmt.Errorf("handshake: truncated length prefix (uint8)")
	}
	length := int(b[0])
	b = b[1:]
	if len(b) < length {
		return nil, nil, fmt.Errorf("handshake: truncated body: declared %d bytes, have %d", length, len(b))
	}
	return b[:length], b[length:], nil
}

// readLenPrefixed16 reads a uint16-length-prefixed blob.
func readLenPrefixed16(b []byte) ([]byte, []byte, error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("handshake: truncated length prefix (uint16)")
	}
	length := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < length {
		return nil, nil, fmt.Errorf("handshake: truncated body: declared %d bytes, have %d", length, len(b))
	}
	return b[:length], b[length:], nil
}

// readLenPrefixed24 reads a 3-byte-length-prefixed blob.
func readLenPrefixed24(b []byte) ([]byte, []byte, error) {
	if len(b) < 3 {
		return nil, nil, fmt.Errorf("handshake: truncated length prefix (uint24)")
	}
	length := int(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]))
	b = b[3:]
	if len(b) < length {
		return nil, nil, fmt.Errorf("handshake: truncated body: declared %d bytes, have %d", length, len(b))
	}
	return b[:length], b[length:], nil
}

// appendUint8 appends a single byte.
func appendUint8(dst []byte, v uint8) []byte {
	return append(dst, v)
}

// appendUint16 appends a big-endian uint16.
func appendUint16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

// appendUint24 appends a 3-byte big-endian integer.
func appendUint24(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>16), byte(v>>8), byte(v))
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

// appendLenPrefixed24 appends a 3-byte-length-prefixed blob.
func appendLenPrefixed24(dst, data []byte) []byte {
	dst = appendUint24(dst, uint32(len(data)))
	return append(dst, data...)
}
