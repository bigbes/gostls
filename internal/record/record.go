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

// maxFragmentLen is the maximum allowed fragment length (RFC 5246 §6.2.2).
// For TLSCiphertext (encrypted): 2^14 + 2048.
const maxFragmentLen = (1 << 14) + 2048

// recordHeaderLen is the fixed size of a TLS record header.
const recordHeaderLen = 5

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
	if len(payload) > (1 << 14) {
		return fatalRecordError("plaintext payload exceeds 2^14 bytes")
	}
	if l.sendSeq == math.MaxUint64 {
		return fatalRecordError("sequence number overflow")
	}

	// Build the 5-byte header template (length will be updated after Seal).
	hdr := [recordHeaderLen]byte{
		contentType,
		byte(tlsVersion >> 8),
		byte(tlsVersion & 0xFF),
		0, 0, // placeholder length
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
	if ver != tlsVersion {
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

	dumpPlaintext("recv", l.recvSeq, ct, ver, plain)

	l.recvSeq++
	return ct, plain, nil
}
