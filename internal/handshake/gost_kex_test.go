// Tests for the GOST key-exchange construction and verification paths:
// buildGOSTExchange, buildGOST2018Exchange, computeKeyExchange (GOST dispatch),
// and parseAndVerifyLeaf (GOST branches).
//
// All tests use static certificate fixtures from testdata/gostcerts/ and
// construct ClientState literals directly (white-box access).
//
//nolint:testpackage // white-box: accesses unexported buildGOSTExchange, buildGOST2018Exchange, and field c.gostLeaf
package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/bigbes/gostcrypto/x509gost"
	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// loadGOSTCert reads a PEM-encoded certificate from testdata/gostcerts/
// and parses it with x509gost.ParseCertificate. Fails the test on any error.
func loadGOSTCert(t *testing.T, name string) *x509gost.Certificate {
	t.Helper()

	pemBytes, err := os.ReadFile("testdata/gostcerts/" + name)
	if err != nil {
		t.Fatalf("loadGOSTCert %q: read file: %v", name, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("loadGOSTCert %q: no PEM block found", name)
	}

	gc, err := x509gost.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("loadGOSTCert %q: x509gost.ParseCertificate: %v", name, err)
	}

	return gc
}

// loadDER reads a PEM-encoded certificate and returns the raw DER bytes.
func loadDER(t *testing.T, name string) []byte {
	t.Helper()

	pemBytes, err := os.ReadFile("testdata/gostcerts/" + name)
	if err != nil {
		t.Fatalf("loadDER %q: read file: %v", name, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("loadDER %q: no PEM block found", name)
	}

	return block.Bytes
}

// newGOSTClientState builds a minimal ClientState suitable for GOST KEX tests.
// It uses a /dev/null record layer (writes discarded, reads EOF), sets the
// supplied suite and gostLeaf, and pre-populates clientRandom/serverRandom
// with non-zero bytes (VKO requires a non-zero UKM = clientRandom[:8]).
func newGOSTClientState(suite *suites.Suite, gostLeaf any) *ClientState {
	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)
	c := &ClientState{
		params:     ClientParams{InsecureSkipVerify: true, Rand: rand.Reader},
		layer:      layer,
		transcript: NewTranscript(),
		suite:      suite,
		gostLeaf:   gostLeaf,
	}

	// UKM = clientRandom[:8]; VKO rejects an all-zero UKM.
	for i := range c.clientRandom {
		c.clientRandom[i] = byte(i + 1)
		c.serverRandom[i] = byte(i + 33)
	}

	return c
}

// mustFindGOSTSuite looks up a suite by name and fatally fails if absent.
func mustFindGOSTSuite(t *testing.T, name string) *suites.Suite {
	t.Helper()

	for _, s := range suites.All() {
		if s.Name == name {
			return s
		}
	}

	t.Fatalf("GOST suite %q not found in registry", name)

	return nil
}

// TestBuildGOSTExchange_GOST2012_256_HappyPath verifies that buildGOSTExchange
// constructs a non-nil Exchange for a GOST2012-256 suite and that calling
// ClientKeyExchange on it produces a non-empty CKE blob (exercises VKO 2012 path).
func TestBuildGOSTExchange_GOST2012_256_HappyPath(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	// KX == KexGOST2012_256.
	suite := mustFindGOSTSuite(t, "GOST2012-GOST8912-GOST8912")

	c := newGOSTClientState(suite, gc)

	exchange, err := buildGOSTExchange(c)
	if err != nil {
		t.Fatalf("buildGOSTExchange(GOST2012_256): unexpected error: %v", err)
	}

	if exchange == nil {
		t.Fatal("buildGOSTExchange(GOST2012_256): returned nil exchange")
	}

	cke, preMaster, err := exchange.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange(GOST2012_256): %v", err)
	}

	if len(cke) == 0 {
		t.Error("ClientKeyExchange(GOST2012_256): cke blob is empty")
	}

	if len(preMaster) == 0 {
		t.Error("ClientKeyExchange(GOST2012_256): preMaster is empty")
	}
}

// TestBuildGOSTExchange_GOST2001_HappyPath verifies the VKO 2001 path using
// the GOST2001 fixture (GOST2001 pubkey, non-GOST signature).
func TestBuildGOSTExchange_GOST2001_HappyPath(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "server_gost2001.crt")

	if !gc.HasGOSTPubKey {
		t.Skip("server_gost2001.crt: HasGOSTPubKey is false — fixture mismatch")
	}

	// KX == KexGOST2001.
	suite := mustFindGOSTSuite(t, "GOST2001-GOST89-GOST89")

	c := newGOSTClientState(suite, gc)

	exchange, err := buildGOSTExchange(c)
	if err != nil {
		t.Fatalf("buildGOSTExchange(GOST2001): unexpected error: %v", err)
	}

	if exchange == nil {
		t.Fatal("buildGOSTExchange(GOST2001): returned nil exchange")
	}

	cke, preMaster, err := exchange.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange(GOST2001): %v", err)
	}

	if len(cke) == 0 {
		t.Error("ClientKeyExchange(GOST2001): cke blob is empty")
	}

	if len(preMaster) == 0 {
		t.Error("ClientKeyExchange(GOST2001): preMaster is empty")
	}
}

// TestBuildGOSTExchange_NonGOSTLeaf exercises the gostLeaf type-assertion error:
// passing a non-*x509gost.Certificate value triggers errGOSTNeedGOSTCert.
func TestBuildGOSTExchange_NonGOSTLeaf(t *testing.T) {
	t.Parallel()

	suite := mustFindGOSTSuite(t, "GOST2012-GOST8912-GOST8912")

	// gostLeaf is a plain string — type assertion must fail.
	c := newGOSTClientState(suite, "not a certificate")

	_, err := buildGOSTExchange(c)
	if err == nil {
		t.Fatal("buildGOSTExchange with non-GOST leaf: expected error, got nil")
	}

	if !errors.Is(err, errGOSTNeedGOSTCert) {
		t.Errorf("expected errGOSTNeedGOSTCert, got %v", err)
	}
}

// TestBuildGOSTExchange_NilLeaf exercises the gostLeaf nil case (nil typed as any).
func TestBuildGOSTExchange_NilLeaf(t *testing.T) {
	t.Parallel()

	suite := mustFindGOSTSuite(t, "GOST2012-GOST8912-GOST8912")
	c := newGOSTClientState(suite, nil)

	_, err := buildGOSTExchange(c)
	if err == nil {
		t.Fatal("buildGOSTExchange with nil leaf: expected error, got nil")
	}

	if !errors.Is(err, errGOSTNeedGOSTCert) {
		t.Errorf("expected errGOSTNeedGOSTCert, got %v", err)
	}
}

// TestBuildGOSTExchange_NonGOSTKXKind exercises the default branch: a KX kind
// that is not KexGOST2001/2012/2018 triggers errGOSTUnexpectedKXKind.
func TestBuildGOSTExchange_NonGOSTKXKind(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	// Build a fake suite that looks like GOST but has an RSA KX kind.
	base := mustFindGOSTSuite(t, "GOST2012-GOST8912-GOST8912")
	fake := *base

	// non-GOST KX falls into the default branch.
	fake.KX = suites.KexRSA

	c := newGOSTClientState(&fake, gc)

	_, err := buildGOSTExchange(c)
	if err == nil {
		t.Fatal("buildGOSTExchange with non-GOST KX kind: expected error, got nil")
	}

	if !errors.Is(err, errGOSTUnexpectedKXKind) {
		t.Errorf("expected errGOSTUnexpectedKXKind, got %v", err)
	}
}

// TestBuildGOST2018Exchange_Kuznyechik_HappyPath verifies that suite ID 0xC100
// (Kuznyechik) produces a non-nil exchange and a valid CKE blob.
func TestBuildGOST2018Exchange_Kuznyechik_HappyPath(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	// ID=0xC100, KX=KexGOST2018_256.
	suite := mustFindGOSTSuite(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")

	c := newGOSTClientState(suite, gc)

	exchange, err := buildGOST2018Exchange(c)
	if err != nil {
		t.Fatalf("buildGOST2018Exchange(Kuznyechik): unexpected error: %v", err)
	}

	if exchange == nil {
		t.Fatal("buildGOST2018Exchange(Kuznyechik): returned nil exchange")
	}

	cke, preMaster, err := exchange.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange(Kuznyechik): %v", err)
	}

	if len(cke) == 0 {
		t.Error("ClientKeyExchange(Kuznyechik): cke blob is empty")
	}

	if len(preMaster) == 0 {
		t.Error("ClientKeyExchange(Kuznyechik): preMaster is empty")
	}
}

// TestBuildGOST2018Exchange_Magma_HappyPath verifies that suite ID 0xC101
// (Magma) produces a non-nil exchange and a valid CKE blob.
func TestBuildGOST2018Exchange_Magma_HappyPath(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	// ID=0xC101, KX=KexGOST2018_256.
	suite := mustFindGOSTSuite(t, "GOST2012-MAGMA-MAGMAOMAC")

	c := newGOSTClientState(suite, gc)

	exchange, err := buildGOST2018Exchange(c)
	if err != nil {
		t.Fatalf("buildGOST2018Exchange(Magma): unexpected error: %v", err)
	}

	if exchange == nil {
		t.Fatal("buildGOST2018Exchange(Magma): returned nil exchange")
	}

	cke, preMaster, err := exchange.ClientKeyExchange(nil)
	if err != nil {
		t.Fatalf("ClientKeyExchange(Magma): %v", err)
	}

	if len(cke) == 0 {
		t.Error("ClientKeyExchange(Magma): cke blob is empty")
	}

	if len(preMaster) == 0 {
		t.Error("ClientKeyExchange(Magma): preMaster is empty")
	}
}

// TestBuildGOST2018Exchange_NonGOSTLeaf exercises the type-assertion guard for
// gostLeaf: a non-*x509gost.Certificate value triggers errGOST2018NeedGOSTCert.
func TestBuildGOST2018Exchange_NonGOSTLeaf(t *testing.T) {
	t.Parallel()

	suite := mustFindGOSTSuite(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
	c := newGOSTClientState(suite, "definitely not a cert")

	_, err := buildGOST2018Exchange(c)
	if err == nil {
		t.Fatal("buildGOST2018Exchange with non-GOST leaf: expected error, got nil")
	}

	if !errors.Is(err, errGOST2018NeedGOSTCert) {
		t.Errorf("expected errGOST2018NeedGOSTCert, got %v", err)
	}
}

// TestBuildGOST2018Exchange_UnexpectedSuiteID exercises the unknown suite ID
// branch: a suite ID that is neither 0xC100 nor 0xC101 triggers errGOST2018UnexpectedID.
func TestBuildGOST2018Exchange_UnexpectedSuiteID(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	// Borrow the Kuznyechik suite shape but override ID to something unknown.
	base := mustFindGOSTSuite(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
	fake := *base

	// 0xBEEF is not a recognised GOST 2018 suite ID.
	fake.ID = 0xBEEF

	c := newGOSTClientState(&fake, gc)

	_, err := buildGOST2018Exchange(c)
	if err == nil {
		t.Fatal("buildGOST2018Exchange with unexpected suite ID: expected error, got nil")
	}

	if !errors.Is(err, errGOST2018UnexpectedID) {
		t.Errorf("expected errGOST2018UnexpectedID, got %v", err)
	}
}

// TestComputeKeyExchange_GOST2012_256 verifies that computeKeyExchange routes
// into buildGOSTExchange for a GOST2012-256 suite and completes successfully.
func TestComputeKeyExchange_GOST2012_256(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	suite := mustFindGOSTSuite(t, "GOST2012-GOST8912-GOST8912")

	c := newGOSTClientState(suite, gc)

	preMaster, ckeBody, err := c.computeKeyExchange(gc.Stdlib, nil, nil)
	if err != nil {
		t.Fatalf("computeKeyExchange(GOST2012_256): %v", err)
	}

	if len(preMaster) == 0 {
		t.Error("computeKeyExchange(GOST2012_256): preMaster is empty")
	}

	if len(ckeBody) == 0 {
		t.Error("computeKeyExchange(GOST2012_256): ckeBody is empty")
	}
}

// TestComputeKeyExchange_GOST2018_Kuznyechik verifies the 2018 key-transport
// dispatch path (suite ID 0xC100) through computeKeyExchange.
func TestComputeKeyExchange_GOST2018_Kuznyechik(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")

	suite := mustFindGOSTSuite(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")

	c := newGOSTClientState(suite, gc)

	preMaster, ckeBody, err := c.computeKeyExchange(gc.Stdlib, nil, nil)
	if err != nil {
		t.Fatalf("computeKeyExchange(GOST2018/Kuznyechik): %v", err)
	}

	if len(preMaster) == 0 {
		t.Error("computeKeyExchange(GOST2018/Kuznyechik): preMaster is empty")
	}

	if len(ckeBody) == 0 {
		t.Error("computeKeyExchange(GOST2018/Kuznyechik): ckeBody is empty")
	}
}

// TestParseAndVerifyLeaf_GOST_SelfSigned verifies that a GOST-signed
// self-signed cert (IsGOST=true) validates when the cert itself is in
// GOSTRoots. On success gostLeaf must be set and the returned leaf non-nil.
func TestParseAndVerifyLeaf_GOST_SelfSigned(t *testing.T) {
	t.Parallel()

	gc := loadGOSTCert(t, "gost256_selfsigned.crt")
	der := loadDER(t, "gost256_selfsigned.crt")

	if !gc.IsGOST {
		t.Fatalf("gost256_selfsigned.crt: IsGOST is false — fixture mismatch")
	}

	c := &ClientState{
		params: ClientParams{
			InsecureSkipVerify: false,
			GOSTRoots:          []*x509gost.Certificate{gc},
			// gost256_selfsigned.crt has no SAN; leave ServerName empty to skip DNS check.
			ServerName: "",
		},
		transcript: NewTranscript(),
	}

	leaf, chains, err := parseAndVerifyLeaf(c, der)
	if err != nil {
		t.Fatalf("parseAndVerifyLeaf(GOST self-signed): %v", err)
	}

	if leaf == nil {
		t.Error("leaf should be non-nil after GOST verification")
	}

	// GOST chain: parseAndVerifyLeaf now surfaces the verified chain in stdlib
	// shape so VerifyPeerCertificate receives a non-nil verifiedChains argument.
	if len(chains) == 0 {
		t.Error("GOST path should return a non-nil verified chain")
	} else if len(chains[0]) == 0 || chains[0][0] == nil {
		t.Error("GOST verified chain should contain the leaf certificate")
	}

	// gostLeaf must have been set because gc.HasGOSTPubKey is true for a GOST cert.
	if c.gostLeaf == nil {
		t.Error("c.gostLeaf must be set after parsing a GOST cert")
	}

	if _, ok := c.gostLeaf.(*x509gost.Certificate); !ok {
		t.Errorf("c.gostLeaf has wrong type: %T", c.gostLeaf)
	}
}

// TestParseAndVerifyLeaf_GOST_EmptyRoots verifies that an empty GOSTRoots
// value causes ErrGOSTRootsRequired.
func TestParseAndVerifyLeaf_GOST_EmptyRoots(t *testing.T) {
	t.Parallel()

	der := loadDER(t, "gost256_selfsigned.crt")

	c := &ClientState{
		params: ClientParams{
			InsecureSkipVerify: false,
			// Empty slice must trigger ErrGOSTRootsRequired.
			GOSTRoots: []*x509gost.Certificate{},
		},
		transcript: NewTranscript(),
	}

	_, _, err := parseAndVerifyLeaf(c, der)
	if err == nil {
		t.Fatal("parseAndVerifyLeaf with empty GOSTRoots: expected error, got nil")
	}

	if !errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("expected ErrGOSTRootsRequired, got %v", err)
	}
}

// TestParseAndVerifyLeaf_GOST_NilRoots verifies that a nil GOSTRoots field
// also causes ErrGOSTRootsRequired (not a panic or wrong error).
func TestParseAndVerifyLeaf_GOST_NilRoots(t *testing.T) {
	t.Parallel()

	der := loadDER(t, "gost256_selfsigned.crt")

	c := &ClientState{
		params: ClientParams{
			InsecureSkipVerify: false,
			GOSTRoots:          nil,
		},
		transcript: NewTranscript(),
	}

	_, _, err := parseAndVerifyLeaf(c, der)
	if err == nil {
		t.Fatal("parseAndVerifyLeaf with nil GOSTRoots: expected error, got nil")
	}

	if !errors.Is(err, ErrGOSTRootsRequired) {
		t.Errorf("expected ErrGOSTRootsRequired, got %v", err)
	}
}

// TestParseAndVerifyLeaf_GOSTPubKey_NonGOSTSig tests the "mixed" case:
// server_gost.crt has a GOST2012-256 public key but is signed by an RSA CA.
// parseAndVerifyLeaf should set c.gostLeaf (HasGOSTPubKey=true) and then
// fall through to the stdlib verification path. InsecureSkipVerify avoids
// needing an RSA RootCAs pool.
func TestParseAndVerifyLeaf_GOSTPubKey_NonGOSTSig(t *testing.T) {
	t.Parallel()

	der := loadDER(t, "server_gost.crt")
	gc := loadGOSTCert(t, "server_gost.crt")

	// Confirm fixture properties: GOST pubkey, non-GOST signature.
	if !gc.HasGOSTPubKey {
		t.Fatalf("server_gost.crt: HasGOSTPubKey is false — fixture mismatch")
	}

	if gc.IsGOST {
		t.Fatalf("server_gost.crt: IsGOST is true — expected non-GOST signature")
	}

	c := &ClientState{
		params: ClientParams{
			InsecureSkipVerify: true,
		},
		transcript: NewTranscript(),
	}

	leaf, _, err := parseAndVerifyLeaf(c, der)
	if err != nil {
		t.Fatalf("parseAndVerifyLeaf(GOSTPubKey+RSAsig, skip verify): %v", err)
	}

	if leaf == nil {
		t.Error("leaf should be non-nil")
	}

	// gostLeaf must be set because gc.HasGOSTPubKey is true.
	if c.gostLeaf == nil {
		t.Error("c.gostLeaf must be set when HasGOSTPubKey is true")
	}

	if _, ok := c.gostLeaf.(*x509gost.Certificate); !ok {
		t.Errorf("c.gostLeaf has wrong type: %T", c.gostLeaf)
	}
}

// TestParseAndVerifyLeaf_GOSTChain_Leaf256SignedBy512 verifies that a chain
// (leaf256_signedby512.crt signed by ca512.crt) can be verified when both the
// leaf and CA are GOST-signed. ca512 is the root; it goes into GOSTRoots.
func TestParseAndVerifyLeaf_GOSTChain_Leaf256SignedBy512(t *testing.T) {
	t.Parallel()

	ca512 := loadGOSTCert(t, "ca512.crt")
	der := loadDER(t, "leaf256_signedby512.crt")

	gc := loadGOSTCert(t, "leaf256_signedby512.crt")
	if !gc.IsGOST {
		t.Fatalf("leaf256_signedby512.crt: IsGOST is false — fixture mismatch")
	}

	c := &ClientState{
		params: ClientParams{
			InsecureSkipVerify: false,
			GOSTRoots:          []*x509gost.Certificate{ca512},
			// Leaf CN is "gost256-leaf" with no SAN; leave ServerName empty to skip DNS check.
			ServerName: "",
		},
		transcript: NewTranscript(),
	}

	leaf, _, err := parseAndVerifyLeaf(c, der)
	if err != nil {
		t.Fatalf("parseAndVerifyLeaf(GOSTChain leaf256->ca512): %v", err)
	}

	if leaf == nil {
		t.Error("leaf should be non-nil after chain verification")
	}

	if c.gostLeaf == nil {
		t.Error("c.gostLeaf must be set for a GOST leaf cert")
	}
}
