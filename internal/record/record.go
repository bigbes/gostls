package record

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// TLS 1.2 content type values (RFC 5246 §6.2.1).
const (
	ContentTypeChangeCipherSpec uint8 = 20
	ContentTypeAlert            uint8 = 21
	ContentTypeHandshake        uint8 = 22
	ContentTypeApplicationData  uint8 = 23
)

// tlsVersion is the only version this layer accepts on the wire.
const tlsVersion = uint16(0x0303)

// tlsMaxPlaintextLen is the maximum plaintext fragment length (RFC 5246 §6.2.1):
// 2^14 bytes.
const tlsMaxPlaintextLen = 1 << 14

// tlsMaxCiphertextOverhead is the maximum overhead (in bytes) above plaintext
// length allowed for a TLSCiphertext record (RFC 5246 §6.2.2).
const tlsMaxCiphertextOverhead = 2048

// tlsVersionHi is the high byte of tlsVersion (TLS 1.2 major version).
const tlsVersionHi = byte(tlsVersion >> 8)

// tlsVersionLo is the low byte of tlsVersion (TLS 1.2 minor version).
const tlsVersionLo = byte(tlsVersion & 0xFF)

// maxFragmentLen is the maximum allowed fragment length (RFC 5246 §6.2.2).
// For TLSCiphertext (encrypted): 2^14 + 2048.
const maxFragmentLen = tlsMaxPlaintextLen + tlsMaxCiphertextOverhead

// recordHeaderLen is the fixed size of a TLS record header.
const recordHeaderLen = 5

// recordVersionMajor is the major byte (3) shared by all TLS/SSL3 versions.
const recordVersionMajor = byte(0x03)

// recordVersionMinTLS10 is the minor byte of TLS 1.0 (0x0301), the lowest
// record-layer version accepted on incoming records.
const recordVersionMinTLS10 = byte(0x01)

// recordVersionByteShift is the bit shift to extract the high byte of a 16-bit
// record-header version.
const recordVersionByteShift = 8

// isAcceptedRecordVersion reports whether a record-header version is an accepted
// TLS 1.x version (0x0301 TLS 1.0 .. 0x0303 TLS 1.2). See ReadRecord for why the
// record-layer version is not pinned to 0x0303.
func isAcceptedRecordVersion(ver uint16) bool {
	return byte(ver>>recordVersionByteShift) == recordVersionMajor &&
		byte(ver) >= recordVersionMinTLS10 &&
		byte(ver) <= tlsVersionLo
}

// isKnownContentType returns true for the four valid TLS 1.2 content types.
func isKnownContentType(ct uint8) bool {
	switch ct {
	case ContentTypeChangeCipherSpec,
		ContentTypeAlert,
		ContentTypeHandshake,
		ContentTypeApplicationData:
		return true
	}

	return false
}

// newAESCipher is the cipher.Block constructor used by aeadProtector.
// Keeping it in this package avoids an import cycle — protection.go calls it
// by name but does not import "crypto/aes" directly.
func newAESCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// Layer is a TLS record reader/writer over an io.ReadWriter.
// It tracks separate send and receive sequence numbers and Protectors,
// allowing ChangeCipherSpec to swap them independently.
//
// The send-side fields (sendSeq, sendProt) and recv-side fields (recvSeq,
// recvProt) are disjoint: a concurrent WriteRecord and ReadRecord on the
// same Layer is safe. Concurrent same-side calls (two Writers or two
// Readers) are not safe. ChangeCipherSpec touches both sides and is
// handshake-only — it must not race with WriteRecord or ReadRecord.
type Layer struct {
	rw       io.ReadWriter
	sendSeq  uint64
	recvSeq  uint64
	sendProt Protector
	recvProt Protector
}

// NewLayer returns a Layer using nullProtector for both directions.
func NewLayer(rw io.ReadWriter) *Layer {
	return NewLayerWithSeq(rw, 0)
}

// NewLayerWithSeq returns a Layer with the given initial sequence number for
// both send and receive directions. Used in tests to verify overflow behaviour.
func NewLayerWithSeq(rw io.ReadWriter, initialSeq uint64) *Layer {
	null := nullProtector{}

	return &Layer{
		rw:       rw,
		sendSeq:  initialSeq,
		recvSeq:  initialSeq,
		sendProt: null,
		recvProt: null,
	}
}

// ChangeCipherSpec swaps the send and/or receive Protectors.
// Pass nil to leave a direction unchanged.
func (l *Layer) ChangeCipherSpec(send, recv Protector) {
	if send != nil {
		l.sendProt = send
		l.sendSeq = 0
	}

	if recv != nil {
		l.recvProt = recv
		l.recvSeq = 0
	}
}

// WriteRecord encrypts and writes a single TLS record.
// contentType must be one of the four known values. payload must not exceed 2^14 bytes.
func (l *Layer) WriteRecord(contentType uint8, payload []byte) error {
	if !isKnownContentType(contentType) {
		return fatalRecordError(fmt.Sprintf("unknown content type 0x%02x", contentType))
	}

	if len(payload) > tlsMaxPlaintextLen {
		return fatalRecordError("plaintext payload exceeds 2^14 bytes")
	}

	if l.sendSeq == math.MaxUint64 {
		return fatalRecordError("sequence number overflow")
	}

	// Build the 5-byte header template (length will be updated after Seal).
	hdr := [recordHeaderLen]byte{
		contentType,
		tlsVersionHi,
		tlsVersionLo,
		0, 0, // placeholder length.
	}

	dumpPlaintext("send", l.sendSeq, contentType, tlsVersion, payload)

	fragment, err := l.sendProt.Seal(l.sendSeq, hdr[:], payload)
	if err != nil {
		return err
	}

	// Write the actual 5-byte header with corrected length.
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(fragment)))

	if _, err := l.rw.Write(hdr[:]); err != nil {
		return err
	}

	if _, err := l.rw.Write(fragment); err != nil {
		return err
	}

	l.sendSeq++

	return nil
}

// ReadRecord reads and decrypts a single TLS record.
// Returns an error on truncated header, version mismatch, unknown content
// type, oversized fragment, or decryption failure. All errors are hard errors.
func (l *Layer) ReadRecord() (contentType uint8, payload []byte, err error) {
	if l.recvSeq == math.MaxUint64 {
		return 0, nil, fatalRecordError("sequence number overflow")
	}

	// Read 5-byte header.
	var hdr [recordHeaderLen]byte

	if _, err := io.ReadFull(l.rw, hdr[:]); err != nil {
		return 0, nil, err
	}

	ct := hdr[0]
	ver := binary.BigEndian.Uint16(hdr[1:3])
	length := binary.BigEndian.Uint16(hdr[3:5])

	if !isKnownContentType(ct) {
		return 0, nil, NewFatalAlertError(AlertIllegalParameter)
	}

	// Accept any TLS 1.x major-3 record version (0x0301..0x0303) on the wire.
	// RFC 5246 App. E permits a TLS 1.2 peer to stamp early records (notably the
	// first ServerHello flight) with {3,1}; crypto/tls likewise does not pin the
	// record-layer version. The negotiated protocol version is enforced
	// separately in the handshake layer via ServerHello.version.
	if !isAcceptedRecordVersion(ver) {
		return 0, nil, NewFatalAlertError(AlertProtocolVersion)
	}

	if int(length) > maxFragmentLen {
		return 0, nil, NewFatalAlertError(AlertRecordOverflow)
	}

	fragment := make([]byte, length)
	if _, err := io.ReadFull(l.rw, fragment); err != nil {
		return 0, nil, err
	}

	plain, err := l.recvProt.Open(l.recvSeq, hdr[:], fragment)
	if err != nil {
		return 0, nil, err
	}

	// A decrypted TLSPlaintext fragment must not exceed 2^14 bytes (RFC 5246
	// §6.2.1). The pre-decrypt check above bounds only the ciphertext
	// (2^14 + 2048); enforce the plaintext ceiling here so an upper layer never
	// receives an over-long fragment.
	if len(plain) > tlsMaxPlaintextLen {
		return 0, nil, NewFatalAlertError(AlertRecordOverflow)
	}

	dumpPlaintext("recv", l.recvSeq, ct, ver, plain)

	l.recvSeq++

	return ct, plain, nil
}
