//go:build gostengine

// Package gostls_test — real GOST TLS interop against an OpenSSL `s_server`
// driven by the GOST engine. This is the strongest validation of the GOST
// client path: it exercises the full handshake (GOST suite negotiation, GOST
// certificate verification via x509gost, VKO / 2018 key transport, the GOST
// PRF key schedule, and the CNT-IMIT / CTR-OMAC record protectors) against an
// independent implementation, not a self-referential Go server.
//
// It is gated behind the `gostengine` build tag and skips unless both an
// OpenSSL 3 binary and a loadable GOST engine are found, so the default
// pure-Go (`CGO_ENABLED=0 go test ./...`) build stays dependency-free:
//
//	go test -tags gostengine -run TestGOSTEngineInterop ./...
//
// Override discovery with OPENSSL_BIN and GOST_ENGINE_LIB. On macOS/Homebrew:
//
//	export OPENSSL_BIN=/opt/homebrew/opt/openssl@3/bin/openssl
//	export GOST_ENGINE_LIB=/opt/homebrew/Cellar/gost-engine@3.0.3/3.0.3/libexec/engines-3/gost.dylib
package gostls_test

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bigbes/gostcrypto/x509gost"

	"github.com/bigbes/gostls"
)

// openSSL TLS-1.2 GOST cipher names mapped to the gostls suite IDs the client
// must offer to negotiate them.
var gostEngineSuites = []struct {
	opensslCipher string
	gostlsSuiteID uint16
}{
	{"GOST2012-MAGMA-MAGMAOMAC", 0xC101},
	{"GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", 0xC100},
	{"GOST2012-GOST8912-GOST8912", 0xC102},
}

// engineCandidates are searched when GOST_ENGINE_LIB is unset.
var engineCandidates = []string{
	"/opt/homebrew/Cellar/gost-engine@3.0.3/3.0.3/libexec/engines-3/gost.dylib",
	"/usr/lib/x86_64-linux-gnu/engines-3/gost.so",
	"/usr/lib/aarch64-linux-gnu/engines-3/gost.so",
	"/usr/local/lib/engines-3/gost.so",
}

// opensslCandidates are searched when OPENSSL_BIN is unset.
var opensslCandidates = []string{
	"/opt/homebrew/opt/openssl@3/bin/openssl",
	"/usr/bin/openssl",
	"/usr/local/bin/openssl",
}

func firstExisting(env string, candidates []string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return ""
}

// gostEngineEnv locates the OpenSSL binary and GOST engine, writes an OpenSSL
// config that loads the engine, and returns (openssl, configPath). It skips the
// test if either is missing or the engine cannot be loaded.
func gostEngineEnv(ctx context.Context, t *testing.T, dir string) (openssl, conf string) {
	t.Helper()

	openssl = firstExisting("OPENSSL_BIN", opensslCandidates)
	if openssl == "" {
		t.Skip("openssl 3 binary not found (set OPENSSL_BIN)")
	}

	engine := firstExisting("GOST_ENGINE_LIB", engineCandidates)
	if engine == "" {
		t.Skip("GOST engine library not found (set GOST_ENGINE_LIB)")
	}

	conf = filepath.Join(dir, "gost.cnf")

	cfg := fmt.Sprintf(`openssl_conf = openssl_def
[openssl_def]
engines = engine_section
[engine_section]
gost = gost_section
[gost_section]
engine_id = gost
dynamic_path = %s
default_algorithms = ALL
`, engine)

	if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write engine config: %v", err)
	}

	// Confirm the engine actually loads on this host; skip (not fail) otherwise.
	probe := exec.CommandContext(ctx, openssl, "engine", "gost", "-t")

	probe.Env = append(os.Environ(), "OPENSSL_CONF="+conf)

	if out, err := probe.CombinedOutput(); err != nil || !strings.Contains(string(out), "available") {
		t.Skipf("GOST engine not loadable: %v\n%s", err, out)
	}

	return openssl, conf
}

// runOpenSSL runs an openssl subcommand with the GOST engine config loaded.
func runOpenSSL(ctx context.Context, t *testing.T, openssl, conf string, args ...string) {
	t.Helper()

	cmd := exec.CommandContext(ctx, openssl, args...)

	cmd.Env = append(os.Environ(), "OPENSSL_CONF="+conf)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// gostServerCert generates a self-signed GOST2012-256 server cert+key.
func gostServerCert(ctx context.Context, t *testing.T, openssl, conf, dir string) (certPEM, certPath, keyPath string) {
	t.Helper()

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	runOpenSSL(ctx, t, openssl, conf,
		"req", "-x509", "-newkey", "gost2012_256", "-pkeyopt", "paramset:A", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "1",
		"-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
	)

	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	return string(b), certPath, keyPath
}

// freePort returns a currently-free localhost TCP port.
func freePort(ctx context.Context, t *testing.T) int {
	t.Helper()

	var lc net.ListenConfig

	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}

	defer func() { _ = l.Close() }()

	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is %T, want *net.TCPAddr", l.Addr())
	}

	return tcpAddr.Port
}

// gostRoots parses the server cert PEM into a single-element GOST trust store.
func gostRoots(t *testing.T, certPEM string) []*x509gost.Certificate {
	t.Helper()

	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatal("server cert is not PEM")
	}

	c, err := x509gost.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse server GOST cert: %v", err)
	}

	return []*x509gost.Certificate{c}
}

func TestGOSTEngineInterop(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	openssl, conf := gostEngineEnv(ctx, t, dir)
	certPEM, certPath, keyPath := gostServerCert(ctx, t, openssl, conf, dir)
	roots := gostRoots(t, certPEM)

	for _, sc := range gostEngineSuites {
		t.Run(sc.opensslCipher, func(t *testing.T) {
			t.Parallel()

			port := freePort(ctx, t)
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

			// Launch an openssl s_server pinned to this one GOST cipher.
			srv := exec.CommandContext(ctx, openssl,
				"s_server", "-accept", strconv.Itoa(port),
				"-cert", certPath, "-key", keyPath,
				"-tls1_2", "-cipher", sc.opensslCipher, "-www",
			)

			srv.Env = append(os.Environ(), "OPENSSL_CONF="+conf)

			if err := srv.Start(); err != nil {
				t.Fatalf("start s_server: %v", err)
			}

			defer func() { _ = srv.Process.Kill(); _ = srv.Wait() }()

			// Wait for the listener.
			waitListen(ctx, t, addr)

			cfg := &gostls.Config{
				ServerName:   "localhost",
				GOSTRoots:    roots,
				CipherSuites: []uint16{sc.gostlsSuiteID},
			}
			dialer := &gostls.Dialer{Config: cfg}

			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			conn, err := dialer.DialContext(dialCtx, "tcp", addr)
			if err != nil {
				t.Fatalf("gostls dial/handshake against %s: %v", sc.opensslCipher, err)
			}

			defer func() { _ = conn.Close() }()

			// Round-trip application data over the GOST channel.
			if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			if !strings.Contains(line, "HTTP") {
				t.Fatalf("unexpected response %q", line)
			}

			t.Logf("GOST interop OK: %s -> %q", sc.opensslCipher, strings.TrimSpace(line))
		})
	}
}

// waitListen blocks until addr accepts a TCP connection or the deadline passes.
func waitListen(ctx context.Context, t *testing.T, addr string) {
	t.Helper()

	var d net.Dialer

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()

			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("s_server did not start listening on %s", addr)
}
