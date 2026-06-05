package gostls_test

import (
	"testing"

	"github.com/bigbes/gostls"
)

// TestDialer_Default_BackendInUse asserts that the default (pure-Go) backend
// is compiled in when the openssl build tag is absent.
func TestDialer_Default_BackendInUse(t *testing.T) {
	if gostls.BackendTag() != "default" {
		t.Fatalf("expected backendTag %q, got %q", "default", gostls.BackendTag())
	}
	t.Logf("backend: %s", gostls.BackendTag())
}
