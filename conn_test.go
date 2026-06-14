package gostls_test

import (
	"testing"
	"time"
)

// TestConn_ConcurrentReadWrite asserts that Read and Write on a post-handshake
// *Conn are callable concurrently from separate goroutines without deadlock.
//
// Invariant: "Read and Write must be callable concurrently from separate
// goroutines on the same connection without deadlock."
//
// Regression for a single-mutex shape in which Read held the one lock while
// blocked in layer.ReadRecord, starving any concurrent Write. The current
// split-lock shape (inMu for Read, outMu for Write) lets the writer proceed.
// The server drains (drain=true) so the Write is bounded only by lock
// contention, not by the pipe's flow control.
func TestConn_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, true)
	defer cleanup()

	// Reader goroutine: blocks in conn.Read because the draining server offers
	// no application data.
	readDone := make(chan error, 1)

	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)

		readDone <- err
	}()

	// Give the reader ~50 ms to reach its blocking point inside ReadRecord.
	time.Sleep(50 * time.Millisecond)

	// Writer goroutine: should complete independently of the blocked reader.
	// With the split inMu/outMu shape this returns immediately; under a shared
	// single lock held by Read, it would deadlock.
	writeDone := make(chan error, 1)

	go func() {
		_, err := conn.Write([]byte("hello"))

		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Errorf("Write returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("deadlock: Write did not complete within 1 s while Read was blocked")
	}

	// cleanup (deferred) closes the conn, which unblocks the reader; drain its
	// result so the goroutine does not outlive the test.
	t.Cleanup(func() { <-readDone })
}
