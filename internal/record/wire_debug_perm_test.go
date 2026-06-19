//nolint:testpackage // white-box: exercises unexported dumpPlaintext / wireDebug* state
package record

import (
	"os"
	"testing"
)

// TestDumpPlaintext_FileMode0600 verifies the wire-debug log is created with
// owner-only permissions (0600), not world-readable: it holds decrypted TLS
// plaintext.
// Not parallel: manipulates shared package-level state and uses t.Setenv.
func TestDumpPlaintext_FileMode0600(t *testing.T) {
	tmp := t.TempDir()
	logPath := tmp + "/wire.log"

	t.Setenv("TLS_DEBUG_WIRE_LOG", logPath)

	wireDebugMu.Lock()

	prevFile := wireDebugFile
	prevFail := wireDebugOpenFail

	wireDebugFile = nil
	wireDebugOpenFail = false

	wireDebugMu.Unlock()

	t.Cleanup(func() {
		wireDebugMu.Lock()

		if wireDebugFile != nil {
			_ = wireDebugFile.Close()
		}

		wireDebugFile = prevFile
		wireDebugOpenFail = prevFail

		wireDebugMu.Unlock()
	})

	dumpPlaintext("send", 0, 0x17, 0x0303, []byte("secret-plaintext"))

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat debug log: %v", err)
	}

	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("wire-debug log mode = %#o, want 0600 (owner-only)", got)
	}
}
