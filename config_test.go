//nolint:testpackage // white-box: tests unexported rootCAPool method on Config
package gostls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedPEM generates a minimal self-signed certificate and returns it
// PEM-encoded as a []byte.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	var buf bytes.Buffer

	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}

	return buf.Bytes()
}

func TestConfig_RootCAPool_PEMOnly(t *testing.T) {
	t.Parallel()

	pemBlock := selfSignedPEM(t)
	cfg := &Config{RootCAPEMs: [][]byte{pemBlock}}

	pool, err := cfg.rootCAPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestConfig_RootCAPool_BothSetErrors(t *testing.T) {
	t.Parallel()

	pemBlock := selfSignedPEM(t)
	existing := x509.NewCertPool()
	cfg := &Config{
		RootCAs:    existing,
		RootCAPEMs: [][]byte{pemBlock},
	}

	_, err := cfg.rootCAPool()
	if err == nil {
		t.Fatal("expected error when both RootCAs and RootCAPEMs are set")
	}
}

func TestConfig_RootCAPool_NeitherSetReturnsNil(t *testing.T) {
	t.Parallel()

	cfg := &Config{}

	pool, err := cfg.rootCAPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pool != nil {
		t.Fatal("expected nil pool when neither RootCAs nor RootCAPEMs is set")
	}
}
