package handshake

import (
	"testing"
)

// TestAvailableSuites_IncludesChaCha20 asserts the three RFC 7905 suites are
// offered by the default client configuration.
func TestAvailableSuites_IncludesChaCha20(t *testing.T) {
	want := map[uint16]string{
		0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
		0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
		0xCCAA: "DHE-RSA-CHACHA20-POLY1305",
	}
	got := make(map[uint16]bool)
	for _, id := range AvailableSuites() {
		got[id] = true
	}
	for id, name := range want {
		if !got[id] {
			t.Errorf("AvailableSuites missing 0x%04X (%s)", id, name)
		}
	}
}
