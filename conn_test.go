package gostls

import (
	"net"
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
func TestConn_ConcurrentReadWrite(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()

	// Build a *Conn on the client end. newConn initialises the record layer.
	c := newConn(clientEnd, &Config{})

	// Mark the handshake done without running a real handshake — Once is consumed with a no-op func; handshakeErr stays nil.
	c.handshakeOnce.Do(func() {})

	// Drainer: consume everything the client writes so that the pipe's write
	// end never blocks due to the pipe's internal buffer being full. Without
	// this, the Write could stall in the pipe rather than on lock contention,
	// which would make the test's assertion ambiguous.
	drainerDone := make(chan struct{})
	go func() {
		defer close(drainerDone)
		buf := make([]byte, 4096)
		for {
			_, err := serverEnd.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Reader goroutine: blocks in c.Read because the pipe has no application
	// data to offer (serverEnd only drains, never sends).
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := c.Read(buf)
		readDone <- err
	}()

	// Give the reader ~50 ms to reach its blocking point inside ReadRecord.
	time.Sleep(50 * time.Millisecond)

	// Writer goroutine: should complete independently of the blocked reader.
	// With the split inMu/outMu shape this returns immediately; under a
	// shared single lock held by Read, it would deadlock.
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("hello"))
		writeDone <- err
	}()

	// The writer must finish within 1 second.
	select {
	case err := <-writeDone:
		if err != nil {
			t.Errorf("Write returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("deadlock: Write did not complete within 1 s while Read was blocked")
	}

	// Cleanup: close the client end so the blocked reader's ReadRecord returns,
	// then drain readDone to avoid leaking the goroutine.
	_ = clientEnd.Close()
	<-readDone

	// Close the server end to unblock the drainer goroutine.
	_ = serverEnd.Close()
	<-drainerDone
}
