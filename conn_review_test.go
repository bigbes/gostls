// Package gostls — regression tests for the deep-review hardening pass:
// Close-vs-Write liveness (no deadlock behind a stalled Write) and the
// consecutive-empty-record flood guard.
//
//nolint:testpackage // white-box: accesses unexported newConn, outMu, handshakeOK, errTooManyEmptyRecords.
package gostls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestConn_Close_DoesNotBlockOnHeldOutMu is the regression test for the Close
// deadlock: when a Write is in flight (holding outMu, stalled inside
// WriteRecord on a non-draining peer), Close must not block trying to acquire
// outMu for the close_notify alert. It must skip the alert (TryLock fails) and
// close the transport, which unblocks the Write. We simulate the in-flight
// Write by holding outMu directly.
func TestConn_Close_DoesNotBlockOnHeldOutMu(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	// Simulate a Write in flight: it has acquired outMu and is blocked writing.
	c.outMu.Lock()
	defer c.outMu.Unlock()

	done := make(chan error, 1)

	go func() { done <- c.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked waiting on outMu held by an in-flight Write")
	}

	// The transport must now be closed: a Read on the server side observes it.
	_ = server.SetReadDeadline(time.Now().Add(time.Second))

	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected server-side Read to fail after Close closed the transport")
	}
}

// TestConn_Close_UnblocksBlockedWrite exercises the end-to-end liveness path: a
// real Write blocked on a non-draining net.Pipe peer is unblocked by a
// concurrent Close, and neither call hangs.
func TestConn_Close_UnblocksBlockedWrite(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	writeDone := make(chan error, 1)

	go func() {
		// server never reads, so this Write blocks inside WriteRecord holding outMu.
		_, err := c.Write(bytes.Repeat([]byte{0x5A}, 4096))
		writeDone <- err
	}()

	// Give the Write goroutine time to acquire outMu and block on the transport.
	time.Sleep(100 * time.Millisecond)

	closeDone := make(chan error, 1)

	go func() { closeDone <- c.Close() }()

	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung while a Write was blocked")
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked Write should have returned an error once Close shut the transport")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Write stayed blocked after Close")
	}
}

// fakeReadConn is a net.Conn whose reads drain a fixed buffer and whose writes
// are discarded. Deadlines are no-ops. Used to feed a pre-baked record stream.
type fakeReadConn struct {
	r *bytes.Reader
}

func (f *fakeReadConn) Read(p []byte) (int, error)       { return f.r.Read(p) }
func (f *fakeReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeReadConn) Close() error                     { return nil }
func (f *fakeReadConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (f *fakeReadConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (f *fakeReadConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeReadConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeReadConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

// TestConn_Read_RejectsEmptyRecordFlood verifies that a flood of consecutive
// zero-length application_data records makes Read return an error rather than
// spinning forever (empty-record DoS guard).
func TestConn_Read_RejectsEmptyRecordFlood(t *testing.T) {
	t.Parallel()

	// Build maxEmptyRecords+1 empty application_data records (null protector).
	var buf bytes.Buffer
	for range maxEmptyRecords + 1 {
		buf.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x00}) // ct=23, ver=0x0303, len=0.
	}

	c := newConn(&fakeReadConn{r: bytes.NewReader(buf.Bytes())}, &Config{})
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	done := make(chan error, 1)

	go func() {
		_, err := c.Read(make([]byte, 16))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errTooManyEmptyRecords) {
			t.Fatalf("expected errTooManyEmptyRecords, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read spun on empty-record flood instead of returning an error")
	}
}

// TestConn_Read_EmptyRecordsThenData verifies the counter does not fire below
// the threshold: a few empty records followed by real data still delivers.
func TestConn_Read_EmptyRecordsThenData(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	for range maxEmptyRecords - 1 { // below the limit.
		buf.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x00})
	}

	buf.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x03}) // one 3-byte data record.
	buf.WriteString("hey")

	c := newConn(&fakeReadConn{r: bytes.NewReader(buf.Bytes())}, &Config{})
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	got := make([]byte, 16)

	n, err := c.Read(got)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Read: %v", err)
	}

	if string(got[:n]) != "hey" {
		t.Fatalf("got %q, want %q", got[:n], "hey")
	}
}
