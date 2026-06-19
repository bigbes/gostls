//nolint:testpackage // white-box: uses unexported readHandshakeRecord and hsBuf
package handshake

import (
	"bytes"
	"testing"

	"github.com/bigbes/gostls/internal/record"
)

// hsRecord wraps a handshake payload in a TLS 1.2 record header.
func hsRecord(payload []byte) []byte {
	out := []byte{ //nolint:prealloc // fixed 5-byte header, appended to once below
		record.ContentTypeHandshake,
		0x03, 0x03, // TLS 1.2.
		byte(len(payload) >> 8), byte(len(payload)),
	}

	return append(out, payload...)
}

// TestReadHandshakeRecord_ReassemblesAcrossRecords verifies that a single
// handshake message split across two TLS records is reassembled (RFC 5246
// §6.2.1 fragmentation) — the case that previously failed with errHSBodyTruncated
// and broke large certificate chains.
func TestReadHandshakeRecord_ReassemblesAcrossRecords(t *testing.T) {
	t.Parallel()

	// Certificate (type 0x0B) with a 6-byte body.
	msg := []byte{0x0B, 0x00, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	// Split the message across two records, mid-body.
	stream := append(hsRecord(msg[:7]), hsRecord(msg[7:])...)

	rw := &readWriteBuffer{r: bytes.NewBuffer(stream), w: new(bytes.Buffer)}
	c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

	typ, body, err := c.readHandshakeRecord()
	if err != nil {
		t.Fatalf("readHandshakeRecord: %v", err)
	}

	if typ != Type(0x0B) {
		t.Errorf("type: got %d, want 0x0B", typ)
	}

	if !bytes.Equal(body, msg[4:]) {
		t.Errorf("body: got %x, want %x", body, msg[4:])
	}
}

// TestReadHandshakeRecord_DeframesCoalesced verifies that two handshake messages
// packed into one TLS record are returned one at a time — the case that
// previously silently dropped everything after the first message.
func TestReadHandshakeRecord_DeframesCoalesced(t *testing.T) {
	t.Parallel()

	msg1 := []byte{0x0B, 0x00, 0x00, 0x02, 0xAA, 0xBB} // Certificate, 2-byte body.
	msg2 := []byte{0x0E, 0x00, 0x00, 0x00}             // ServerHelloDone, empty body.

	rec := hsRecord(append(append([]byte{}, msg1...), msg2...))

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

	typ, body, err := c.readHandshakeRecord()
	if err != nil || typ != Type(0x0B) || !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Fatalf("msg1: typ=%d body=%x err=%v", typ, body, err)
	}

	typ, body, err = c.readHandshakeRecord()
	if err != nil || typ != Type(0x0E) || len(body) != 0 {
		t.Fatalf("msg2: typ=%d body=%x err=%v", typ, body, err)
	}
}
