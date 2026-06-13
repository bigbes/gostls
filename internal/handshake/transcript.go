package handshake

// Package handshake transcript.go — accumulates handshake message bytes;
// Sum(factory) computes the transcript hash on demand using the
// caller-supplied factory. No internal hash tracking; no Collapse.

import "hash"

// maxTranscriptBytes bounds the accumulated handshake transcript. A legitimate
// TLS 1.2 handshake — even with a deep certificate chain — is at most a few tens
// of KiB; this cap leaves generous headroom while preventing a malicious or
// buggy server from growing the buffer without limit (a memory-exhaustion DoS
// on the client). On overflow Write stops appending and Sum returns an error,
// which aborts the handshake before any transcript-derived value is trusted.
const maxTranscriptBytes = 256 * 1024

// Transcript accumulates the bytes of handshake messages for use in the PRF
// and CertificateVerify computation (RFC 5246 §7.4.9).
//
// Every call to Write appends its argument to an internal buffer.  Sum(factory)
// creates a fresh hash via factory(), feeds the accumulated buffer into it, and
// returns the resulting digest.  The buffer is never reset; successive calls to
// Sum with different factories each replay the full byte sequence independently.
//
// Accumulation is bounded by maxTranscriptBytes: once the buffer would exceed
// the cap, Write stops appending and marks the transcript overflowed, and every
// subsequent Sum returns an error so the handshake fails closed rather than
// trusting a truncated transcript or exhausting memory.
//
// There is no internal hash tracking, no identity state, and no Collapse
// method.  Two factories with identical BlockSize and Size (e.g. SHA-256 and a
// shape-matched fake) produce distinct digests because the factory itself, not
// its shape, determines the hash computation.
type Transcript struct {
	buf      []byte
	overflow bool
}

// NewTranscript returns a new, empty Transcript.
func NewTranscript() *Transcript {
	return &Transcript{}
}

// Write appends msg to the transcript buffer.  It is the caller's
// responsibility to pass the full 4-byte-enveloped handshake message
// (msg_type + uint24 length + body), as required by RFC 5246 §7.4.9.
//
// If appending msg would push the buffer past maxTranscriptBytes, Write appends
// nothing and marks the transcript overflowed; Sum then fails (see Overflowed).
func (t *Transcript) Write(msg []byte) {
	if t.overflow || len(t.buf)+len(msg) > maxTranscriptBytes {
		t.overflow = true

		return
	}

	t.buf = append(t.buf, msg...)
}

// Overflowed reports whether Write has rejected data because the transcript
// reached maxTranscriptBytes. Once true it stays true.
func (t *Transcript) Overflowed() bool { return t.overflow }

// Sum computes the transcript hash using factory.  It calls factory() to
// obtain a fresh hash instance, writes all buffered bytes into it, and returns
// the digest via h.Sum(nil).
//
// factory must not be nil.  If factory is nil, Sum returns
// errors.New("handshake: transcript: nil hash factory").
func (t *Transcript) Sum(factory func() hash.Hash) ([]byte, error) {
	if factory == nil {
		return nil, errNilHashFactory
	}

	if t.overflow {
		return nil, errTranscriptOverflow
	}

	h := factory()
	h.Write(t.buf)

	return h.Sum(nil), nil
}
