// Coverage-gap tests (white-box) for the handshake package.
//
// These exercise unexported surface not reached by the existing suite:
//   - computeKeyExchange's full dispatch table over every KX kind (item 1);
//   - recvServerHello extension hardening (item 3);
//   - recvServerFlight rejection of an unsolicited NewSessionTicket (item 4);
//   - wrong-length Finished under a mismatched suite (item 5);
//   - fuzz targets for verifyECDHEServerKeyExchange, verifyDHEServerKeyExchange,
//     and readHandshakeRecord de-framing/reassembly (item 6).
//
// All expected values come from independent oracles (crypto/sha256, the wire
// format itself, and the suites key schedule); no value is derived from the
// code under test.
//
//nolint:testpackage // white-box: exercises unexported computeKeyExchange, recvServerHello, verify*.
package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// =============================================================================
// item 1 — computeKeyExchange dispatch table
// =============================================================================.

// buildDHEServerParams returns a valid dh_p || dh_g || dh_Ys params section
// (the exact shape verifyDHEServerKeyExchange hands to the key exchange), so a
// DHEExchange.ClientKeyExchange over it succeeds.
func buildDHEServerParams(t *testing.T) []byte {
	t.Helper()

	p, err := hex.DecodeString(ffdhe2048PHexKEX)
	if err != nil {
		t.Fatalf("decode ffdhe2048 prime: %v", err)
	}

	g := []byte{0x02}

	Ys := make([]byte, len(p))
	copy(Ys, p)

	Ys[len(Ys)-1] -= 3 // a valid value in (1, p-1).

	params := appendU16PrefixedSlice(nil, p)

	params = appendU16PrefixedSlice(params, g)
	params = appendU16PrefixedSlice(params, Ys)

	return params
}

// TestComputeKeyExchange_DispatchTable drives computeKeyExchange for every KX
// kind with a matching server key-exchange params blob and asserts a non-empty
// (preMaster, ckeBody) is produced — proving the switch routes each suite to the
// right ke.Exchange. The final row asserts an unknown KX kind fails closed.
func TestComputeKeyExchange_DispatchTable(t *testing.T) {
	t.Parallel()

	var cr, sr [32]byte
	for i := range cr {
		cr[i] = byte(i + 1)
		sr[i] = byte(i + 2)
	}

	type row struct {
		name    string
		setup   func(t *testing.T) (c *ClientState, cert *x509.Certificate, params []byte)
		wantErr error // nil means expect success.
	}

	rows := []row{
		{
			name: "ECDHE",
			setup: func(t *testing.T) (*ClientState, *x509.Certificate, []byte) {
				t.Helper()

				ecPriv, ecCert := newTestECDSACert(t)
				ske := buildECDHESKEBody(t, ecPriv, cr, sr)
				pointLen := int(ske[3])
				params := ske[:4+pointLen]

				c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256"))

				c.clientRandom, c.serverRandom = cr, sr

				return c, ecCert, params
			},
		},
		{
			name: "DHE",
			setup: func(t *testing.T) (*ClientState, *x509.Certificate, []byte) {
				t.Helper()

				_, rsaCert, _ := newTestRSACert(t)
				c := makeMinimalClientState(t, mustLookupSuite(t, "DHE-RSA-AES128-SHA256"))

				return c, rsaCert, buildDHEServerParams(t)
			},
		},
		{
			name: "RSA",
			setup: func(t *testing.T) (*ClientState, *x509.Certificate, []byte) {
				t.Helper()

				_, rsaCert, _ := newTestRSACert(t)
				c := makeMinimalClientState(t, mustLookupSuite(t, "AES128-SHA256"))

				return c, rsaCert, nil
			},
		},
		{
			name: "GOST2012_256",
			setup: func(t *testing.T) (*ClientState, *x509.Certificate, []byte) {
				t.Helper()

				gc := loadGOSTCert(t, "gost256_selfsigned.crt")
				c := newGOSTClientState(mustFindGOSTSuite(t, "GOST2012-GOST8912-GOST8912"), gc)

				return c, nil, nil
			},
		},
		{
			name: "GOST2018_256",
			setup: func(t *testing.T) (*ClientState, *x509.Certificate, []byte) {
				t.Helper()

				gc := loadGOSTCert(t, "gost256_selfsigned.crt")
				c := newGOSTClientState(mustFindGOSTSuite(t, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC"), gc)

				return c, nil, nil
			},
		},
		{
			name: "UnknownKX",
			setup: func(t *testing.T) (*ClientState, *x509.Certificate, []byte) {
				t.Helper()

				_, cert, _ := newTestRSACert(t)
				valid := mustLookupSuite(t, "AES128-SHA256")
				fake := *valid

				fake.KX = suites.KexKind(0xEE) // out-of-range.

				c := makeMinimalClientState(t, &fake)

				return c, cert, nil
			},
			wantErr: errUnknownKXKind,
		},
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, cert, params := tc.setup(t)

			preMaster, ckeBody, err := c.computeKeyExchange(cert, params, nil)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("computeKeyExchange(%s): got err %v, want %v", tc.name, err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("computeKeyExchange(%s): unexpected error: %v", tc.name, err)
			}

			if len(preMaster) == 0 {
				t.Errorf("computeKeyExchange(%s): empty preMaster", tc.name)
			}

			if len(ckeBody) == 0 {
				t.Errorf("computeKeyExchange(%s): empty ckeBody", tc.name)
			}
		})
	}
}

// =============================================================================
// item 3 — ServerHello extension hardening
// =============================================================================.

// appendReviewExt appends one extension (uint16 type + uint16 body_len + body).
func appendReviewExt(dst []byte, extType uint16, body []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, extType)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(body)))

	return append(dst, body...)
}

// buildSHBodyWithExtList builds a ServerHello body carrying the given raw
// extension-list bytes (already the concatenation of individual extensions).
func buildSHBodyWithExtList(random [32]byte, suiteID uint16, extList []byte) []byte {
	body := buildRawServerHelloBody(random, suiteID, 0x0303, 0x00)

	body = binary.BigEndian.AppendUint16(body, uint16(len(extList)))

	return append(body, extList...)
}

// runRecvServerHello feeds a ServerHello body through the record layer and the
// state machine, returning recvServerHello's error.
func runRecvServerHello(t *testing.T, body []byte, params ClientParams) error {
	t.Helper()

	rec := buildHSRecord(TypeServerHello, body)
	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	c := NewClientState(record.NewLayer(rw), params)

	return c.recvServerHello()
}

// TestRecvServerHello_UnsolicitedExtension_Rejected verifies that a ServerHello
// echoing an extension the client never offered (server_name, when no SNI was
// sent) is rejected via the state-machine path with errSHUnofferedExt
// (RFC 5246 §7.4.1.4).
func TestRecvServerHello_UnsolicitedExtension_Rejected(t *testing.T) {
	t.Parallel()

	suite := mustLookupSuite(t, "AES128-SHA256")

	var random [32]byte

	extList := appendReviewExt(nil, extServerName, nil) // empty server_name echo.
	body := buildSHBodyWithExtList(random, suite.ID, extList)

	// ServerName is empty -> server_name was never offered.
	err := runRecvServerHello(t, body, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})
	if !errors.Is(err, errSHUnofferedExt) {
		t.Fatalf("unsolicited server_name: got %v, want errSHUnofferedExt", err)
	}
}

// TestRecvServerHello_DuplicateOfferedExtension_Rejected verifies that a
// ServerHello carrying the SAME extension type twice is rejected, even when the
// type was offered (RFC 5246 §7.4.1.4: "There MUST NOT be more than one
// extension of the same type").
func TestRecvServerHello_DuplicateOfferedExtension_Rejected(t *testing.T) {
	t.Parallel()

	suite := mustLookupSuite(t, "AES128-SHA256")

	var random [32]byte

	// Two renegotiation_info extensions (offered, empty body).
	extList := appendReviewExt(nil, extRenegotiationInfo, []byte{0x00})

	extList = appendReviewExt(extList, extRenegotiationInfo, []byte{0x00})

	body := buildSHBodyWithExtList(random, suite.ID, extList)

	err := runRecvServerHello(t, body, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
	})
	if !errors.Is(err, errDuplicateExtension) {
		t.Fatalf("duplicate renegotiation_info: want errDuplicateExtension, got %v", err)
	}
}

// TestRecvServerHello_NonEmptySNIEcho_Rejected verifies that a non-empty
// server_name echo in the ServerHello is rejected (RFC 6066 §3 requires the
// ServerHello server_name extension_data to be empty).
func TestRecvServerHello_NonEmptySNIEcho_Rejected(t *testing.T) {
	t.Parallel()

	suite := mustLookupSuite(t, "AES128-SHA256")

	var random [32]byte

	// A well-formed non-empty server_name body (RFC 6066 ClientHello shape).
	extList := appendReviewExt(nil, extServerName, marshalServerName("example.com"))
	body := buildSHBodyWithExtList(random, suite.ID, extList)

	err := runRecvServerHello(t, body, ClientParams{
		Rand:               rand.Reader,
		OfferedSuites:      []uint16{suite.ID},
		InsecureSkipVerify: true,
		ServerName:         "example.com", // offered -> server_name is in the allowed set.
	})
	if !errors.Is(err, errServerHelloNonEmptySNI) {
		t.Fatalf("non-empty SNI echo: want errServerHelloNonEmptySNI, got %v", err)
	}
}

// =============================================================================
// item 4 — unsolicited NewSessionTicket
// =============================================================================.

// typeNewSessionTicket is handshake type 4 (RFC 5077). The gostls client never
// offers session tickets and has no Type constant for it, so it must be
// rejected wherever it appears. Kept as an untyped constant (not a Type) so it
// does not extend the Type enum and trip the exhaustive linter on the package's
// switches over Type.
const typeNewSessionTicket = 4

// TestRecvServerFlight_NewSessionTicket_Rejected verifies that a NewSessionTicket
// injected into the server flight is rejected (never silently consumed).
func TestRecvServerFlight_NewSessionTicket_Rejected(t *testing.T) {
	t.Parallel()

	nstRec := buildHSRecord(typeNewSessionTicket, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	shdRec := buildHSRecord(TypeServerHelloDone, nil)
	wire := append(append([]byte{}, nstRec...), shdRec...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA: no SKE expected.
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	if !errors.Is(err, errUnexpectedFlightMsg) {
		t.Fatalf("NewSessionTicket in flight: got %v, want errUnexpectedFlightMsg", err)
	}
}

// TestParseMessage_NewSessionTicket_UnknownType verifies the lower-level parser
// rejects handshake type 4 with errUnknownMsgType (the errUnknownMsgType path).
func TestParseMessage_NewSessionTicket_UnknownType(t *testing.T) {
	t.Parallel()

	env := buildEnvelope(typeNewSessionTicket, []byte{0xAA, 0xBB})

	_, _, err := ParseMessage(env)
	if !errors.Is(err, errUnknownMsgType) {
		t.Fatalf("ParseMessage(type 4): got %v, want errUnknownMsgType", err)
	}
}

// =============================================================================
// item 5 — wrong-length Finished under a mismatched suite
// =============================================================================.

// TestParseFinished_WrongLengthRejected verifies parseFinished rejects any
// verify_data length other than the two legal values (12 or 32).
func TestParseFinished_WrongLengthRejected(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 1, 11, 13, 16, 31, 33, 48} {
		env := buildEnvelope(TypeFinished, make([]byte, n))

		_, _, err := ParseMessage(env)
		if !errors.Is(err, errFinishedVerifyLen) {
			t.Errorf("parseFinished(len=%d): got %v, want errFinishedVerifyLen", n, err)
		}
	}
}

// TestFinished_MismatchedSuiteLengthFailsVerify feeds a 32-byte (GOST-shaped)
// Finished into a suite whose verify_data is 12 bytes: parseFinished accepts the
// 32-byte body, but the constant-time comparison against the correctly-sized
// expected value fails because the lengths differ — the exact rejection the
// server-Finished check relies on. Oracle: suites.FinishedVerifyData produces
// the 12-byte expected value for a non-GOST suite.
func TestFinished_MismatchedSuiteLengthFailsVerify(t *testing.T) {
	t.Parallel()

	suite := mustLookupSuite(t, "AES128-SHA256") // 12-byte verify_data.

	// A structurally valid 32-byte Finished (allowed by parseFinished).
	msg, _, err := ParseMessage(buildEnvelope(TypeFinished, make([]byte, 32)))
	if err != nil {
		t.Fatalf("ParseMessage(32-byte Finished): unexpected error: %v", err)
	}

	fin, ok := msg.(*Finished)
	if !ok {
		t.Fatalf("expected *Finished, got %T", msg)
	}

	masterSecret := make([]byte, 48)
	transcriptHash := make([]byte, 32)

	expected, err := suites.FinishedVerifyData(suite, masterSecret, "server finished", transcriptHash)
	if err != nil {
		t.Fatalf("FinishedVerifyData: %v", err)
	}

	if len(expected) != 12 {
		t.Fatalf("expected 12-byte verify_data for %s, got %d", suite.Name, len(expected))
	}

	if suites.EqualVerifyData(fin.VerifyData, expected) {
		t.Fatal("32-byte Finished unexpectedly matched a 12-byte verify_data")
	}
}

// =============================================================================
// item 6 — fuzz targets (must never panic on attacker-controlled bytes)
// =============================================================================.

// newFuzzClientState builds a throwaway ClientState with a working record layer
// (so c.fatal can emit its alert) for the chosen suite.
func newFuzzClientState(tb testing.TB, suiteName string) *ClientState {
	tb.Helper()

	suite := (*suites.Suite)(nil)

	for _, s := range suites.All() {
		if s.Name == suiteName {
			suite = s

			break
		}
	}

	if suite == nil {
		tb.Fatalf("suite %q not found", suiteName)
	}

	rw := &readWriteBuffer{r: new(bytes.Buffer), w: new(bytes.Buffer)}
	c := NewClientState(record.NewLayer(rw), ClientParams{InsecureSkipVerify: true, Rand: rand.Reader})

	c.suite = suite

	return c
}

// FuzzVerifyECDHEServerKeyExchange feeds arbitrary bodies to the ECDHE
// ServerKeyExchange parser with a fixed cert. Contract: never panic — malformed
// input must return an error, not a slice-bounds crash.
func FuzzVerifyECDHEServerKeyExchange(f *testing.F) {
	// Degenerate seeds spanning the length guards in verifyECDHEServerKeyExchange:
	// empty, a bare curve header, and a header claiming a 65-byte uncompressed
	// point the body does not contain. The mutator grows these to reach the
	// signature-parsing and verification branches.
	f.Add([]byte(nil))
	f.Add([]byte{0x03, 0x00, 0x17, 0x00})
	f.Add([]byte{0x03, 0x00, 0x17, 0x41, 0x04})

	f.Fuzz(func(t *testing.T, body []byte) {
		c := newFuzzClientState(t, "ECDHE-ECDSA-AES128-SHA256")
		_, ecCert := newTestECDSACert(t)

		// Contract: must not panic. err/nil are both acceptable.
		_, _ = c.verifyECDHEServerKeyExchange(body, ecCert)
	})
}

// FuzzVerifyDHEServerKeyExchange feeds arbitrary bodies to the DHE
// ServerKeyExchange parser with a fixed RSA cert. Contract: never panic.
func FuzzVerifyDHEServerKeyExchange(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01, 0xFF, 0x00, 0x01, 0x02})
	// Structurally valid DHE params that parse through dh_p / dh_g / dh_Ys and
	// reach the signature-section slicing (hashAlg, sigAlg, sig_len, sig). These
	// seeds exercise the deep branch that the trivial seeds above never reach:
	// dh_p(00 02|00 03) dh_g(00 01|02) dh_Ys(00 01|04) hash(04) sig(01) len(00 04) sig(AA BB CC DD).
	f.Add([]byte{
		0x00, 0x02, 0x00, 0x03,
		0x00, 0x01, 0x02,
		0x00, 0x01, 0x04,
		0x04, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
	})
	// A longer-field variant with a sig_len that overruns (exercises the
	// signature-truncation bound) and a different hash/sig pair.
	f.Add([]byte{
		0x00, 0x03, 0x00, 0x00, 0x05,
		0x00, 0x01, 0x02,
		0x00, 0x02, 0x00, 0x07,
		0x06, 0x01, 0x00, 0x40, 0x11, 0x22,
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		c := newFuzzClientState(t, "DHE-RSA-AES128-SHA256")
		_, rsaCert, _ := newTestRSACert(t)

		_, _ = c.verifyDHEServerKeyExchange(body, rsaCert)
	})
}

// FuzzReadHandshakeRecord chops an arbitrary byte stream into the transport of a
// record layer and drives readHandshakeRecord's de-framing/reassembly. Contract:
// never panic, always terminate, and never let the reassembly buffer grow past
// the documented cap (no unbounded growth).
func FuzzReadHandshakeRecord(f *testing.F) {
	// A well-formed handshake record and a coalesced/split pair as seeds.
	f.Add(hsRecord([]byte{0x0E, 0x00, 0x00, 0x00})) // ServerHelloDone.
	f.Add(append(hsRecord([]byte{0x0B, 0x00, 0x00, 0x02}), hsRecord([]byte{0xAA, 0xBB})...))
	f.Add([]byte{0x16, 0x03, 0x03, 0xFF, 0xFF}) // truncated record header.
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, stream []byte) {
		rw := &readWriteBuffer{r: bytes.NewBuffer(append([]byte(nil), stream...)), w: new(bytes.Buffer)}
		c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

		// Each successful call consumes >= 4 bytes; an error terminates the loop.
		// Cap iterations defensively so a bug that fails to make progress is a
		// test timeout rather than an infinite loop.
		maxIters := len(stream) + 8
		for range maxIters {
			_, _, err := c.readHandshakeRecord()
			if err != nil {
				break
			}

			if len(c.hsBuf) > maxHandshakeMsg {
				t.Fatalf("hsBuf grew past cap: %d > %d", len(c.hsBuf), maxHandshakeMsg)
			}
		}

		if len(c.hsBuf) > maxHandshakeMsg {
			t.Fatalf("hsBuf grew past cap after loop: %d > %d", len(c.hsBuf), maxHandshakeMsg)
		}
	})
}
