package record

import (
	"fmt"
	"os"
	"sync"
)

// wireDebugFilePerm is the permission mode for the debug log file. The log
// contains decrypted TLS plaintext, so it is created owner-only (0600) rather
// than world-readable.
const wireDebugFilePerm = 0o600

var (
	wireDebugMu       sync.Mutex
	wireDebugFile     *os.File
	wireDebugOpenFail bool // set once on open failure; prevents stderr spam.
)

// dumpPlaintext appends one human-readable line per record to the file named
// by TLS_DEBUG_WIRE_LOG. It is a no-op when that env var is unset.
//
// dir is "send" or "recv". seq is the sequence number the protector used.
// version is the two-byte TLS version from the record header (e.g. 0x0303).
//
// On first call the output file is opened with O_CREATE|O_APPEND|O_WRONLY and
// kept open for the process lifetime (debug-only tool). A single open failure
// writes one diagnostic line to stderr and then silences further attempts so
// that no TLS handshake is disrupted.
func dumpPlaintext(dir string, seq uint64, contentType uint8, version uint16, payload []byte) {
	path := os.Getenv("TLS_DEBUG_WIRE_LOG")
	if path == "" {
		return
	}

	wireDebugMu.Lock()
	defer wireDebugMu.Unlock()

	if wireDebugFile == nil && !wireDebugOpenFail {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, wireDebugFilePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TLS_DEBUG_WIRE_LOG: open %q failed: %v\n", path, err)

			wireDebugOpenFail = true

			return
		}

		wireDebugFile = f
	}

	if wireDebugOpenFail {
		return
	}

	_, _ = fmt.Fprintf(wireDebugFile, "%s seq=%d type=%d ver=%04x len=%d hex=%x\n",
		dir, seq, contentType, version, len(payload), payload)
}
