//nolint:testpackage // white-box: exercises unexported dumpPlaintext which is gated on an env var
package record

import (
	"os"
	"strings"
	"testing"
)

// TestDumpPlaintext_NoOp verifies that dumpPlaintext is a no-op when
// TLS_DEBUG_WIRE_LOG is unset (the common production path).
// Not parallel: manipulates shared package-level state and uses t.Setenv.
func TestDumpPlaintext_NoOp(t *testing.T) {
	// Ensure the env var is absent for this subtest.
	t.Setenv("TLS_DEBUG_WIRE_LOG", "")

	// Reset package-level state so this test runs clean regardless of order.
	wireDebugMu.Lock()

	prevFile := wireDebugFile
	prevFail := wireDebugOpenFail

	wireDebugFile = nil
	wireDebugOpenFail = false

	wireDebugMu.Unlock()

	t.Cleanup(func() {
		wireDebugMu.Lock()

		wireDebugFile = prevFile
		wireDebugOpenFail = prevFail

		wireDebugMu.Unlock()
	})

	// Must not panic, open any file, or write anything.
	dumpPlaintext("send", 0, 0x17, 0x0303, []byte("hello"))

	wireDebugMu.Lock()

	f := wireDebugFile

	wireDebugMu.Unlock()

	if f != nil {
		t.Error("dumpPlaintext with empty env var: wireDebugFile should remain nil")
	}
}

// TestDumpPlaintext_WritesToFile verifies that when TLS_DEBUG_WIRE_LOG points
// to a writable path, dumpPlaintext opens the file on first call and appends a
// correctly-formatted line on subsequent calls.
// Not parallel: manipulates shared package-level state and uses t.Setenv.
func TestDumpPlaintext_WritesToFile(t *testing.T) {
	tmp := t.TempDir()
	logPath := tmp + "/wire.log"

	t.Setenv("TLS_DEBUG_WIRE_LOG", logPath)

	// Snapshot and clear package-level file state so the open happens in this test.
	wireDebugMu.Lock()

	prevFile := wireDebugFile
	prevFail := wireDebugOpenFail

	wireDebugFile = nil
	wireDebugOpenFail = false

	wireDebugMu.Unlock()

	t.Cleanup(func() {
		// Close the file opened by dumpPlaintext before restoring state.
		wireDebugMu.Lock()

		if wireDebugFile != nil {
			_ = wireDebugFile.Close()
		}

		wireDebugFile = prevFile
		wireDebugOpenFail = prevFail

		wireDebugMu.Unlock()
	})

	payload := []byte{0xDE, 0xAD}
	dumpPlaintext("send", 42, 0x17, 0x0303, payload)
	dumpPlaintext("recv", 43, 0x15, 0x0303, payload)

	// Flush: sync the file so we can read it.
	wireDebugMu.Lock()

	f := wireDebugFile

	wireDebugMu.Unlock()

	if f == nil {
		t.Fatal("dumpPlaintext: wireDebugFile still nil after call with env var set")
	}

	if err := f.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)

	// Verify the lines contain expected fields.
	if !strings.Contains(content, "seq=42") {
		t.Errorf("log line missing seq=42:\n%s", content)
	}

	// 0x17 decimal is 23.
	if !strings.Contains(content, "type=23") {
		t.Errorf("log line missing type=23:\n%s", content)
	}

	if !strings.Contains(content, "hex=dead") {
		t.Errorf("log line missing hex=dead:\n%s", content)
	}

	if !strings.Contains(content, "recv") {
		t.Errorf("log line missing recv direction:\n%s", content)
	}

	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 log lines, got %d:\n%s", len(lines), content)
	}
}

// TestDumpPlaintext_OpenFailure verifies that an unwritable path causes a
// one-time stderr diagnostic and then silences further attempts (wireDebugOpenFail
// is set and subsequent calls are no-ops).
// Not parallel: manipulates shared package-level state and uses t.Setenv.
func TestDumpPlaintext_OpenFailure(t *testing.T) {
	// Use a path that is guaranteed to be unwritable (directory that does not exist).
	t.Setenv("TLS_DEBUG_WIRE_LOG", "/nonexistent/path/that/cannot/be/created/wire.log")

	wireDebugMu.Lock()

	prevFile := wireDebugFile
	prevFail := wireDebugOpenFail

	wireDebugFile = nil
	wireDebugOpenFail = false

	wireDebugMu.Unlock()

	t.Cleanup(func() {
		wireDebugMu.Lock()

		wireDebugFile = prevFile
		wireDebugOpenFail = prevFail

		wireDebugMu.Unlock()
	})

	// First call: should attempt open, fail, and set wireDebugOpenFail.
	dumpPlaintext("send", 0, 0x17, 0x0303, []byte("x"))

	wireDebugMu.Lock()

	fail := wireDebugOpenFail
	f := wireDebugFile

	wireDebugMu.Unlock()

	if !fail {
		t.Error("wireDebugOpenFail should be true after failed open")
	}

	if f != nil {
		t.Error("wireDebugFile should remain nil after failed open")
	}

	// Second call: must be a no-op (not attempt another open).
	dumpPlaintext("send", 1, 0x17, 0x0303, []byte("y"))

	wireDebugMu.Lock()

	fail2 := wireDebugOpenFail

	wireDebugMu.Unlock()

	if !fail2 {
		t.Error("wireDebugOpenFail should still be true on second call")
	}
}
