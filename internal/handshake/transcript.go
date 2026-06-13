package handshake

// Package handshake transcript.go — accumulates handshake message bytes;
// Sum(factory) computes the transcript hash on demand using the
// caller-supplied factory. No internal hash tracking; no Collapse.

import "hash"

// Transcript accumulates the bytes of handshake messages for use in the PRF
// and CertificateVerify computation (RFC 5246 §7.4.9).
//
// Every call to Write appends its argument to an internal buffer.  Sum(factory)
// creates a fresh hash via factory(), feeds the accumulated buffer into it, and
// returns the resulting digest.  The buffer is never reset; successive calls to
// Sum with different factories each replay the full byte sequence independently.
//
// There is no internal hash tracking, no identity state, and no Collapse
// method.  Two factories with identical BlockSize and Size (e.g. SHA-256 and a
// shape-matched fake) produce distinct digests because the factory itself, not
// its shape, determines the hash computation.
type Transcript struct {
	buf []byte
}

// NewTranscript returns a new, empty Transcript.
func NewTranscript() *Transcript {
	return &Transcript{}
}

// Write appends msg to the transcript buffer.  It is the caller's
// responsibility to pass the full 4-byte-enveloped handshake message
// (msg_type + uint24 length + body), as required by RFC 5246 §7.4.9.
func (t *Transcript) Write(msg []byte) {
	t.buf = append(t.buf, msg...)
}

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

	h := factory()
	h.Write(t.buf)

	return h.Sum(nil), nil
}
