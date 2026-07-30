package record_test

// covgap_review_test.go closes four record-layer coverage gaps:
//
//  1. Per-Protector round-trip fuzz targets (Open(Seal(x)) == x for arbitrary
//     x, and Open on arbitrary/corrupted fragment bytes never panics). Only
//     FuzzReadRecord existed before.
//  2. Constant-time error EQUIVALENCE: a CBC record with a bad MAC and a CBC
//     record with bad padding must both return exactly AlertBadRecordMAC — an
//     indistinguishable error value (Lucky13 requirement). lucky13_test.go
//     only covered panic-safety of the oversized-padding-byte case.
//  3. Concurrent Read+Write on one Layer over a net.Pipe loopback, exercised
//     under -race, pinning the documented disjoint send/recv halves contract
//     (record.go:84-92).
//  4. AEAD binds the sequence number: a record sealed at seq=1 must not open
//     at seq=0 (proves seq is in the AAD).
//
// All checks are property / round-trip / negative — no external KAT is used or
// invented; every expected value comes from the package's own Seal→Open
// inverse relationship or from the documented error contract.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostls/internal/record"
)

// covHdr is a 5-byte TLS 1.2 application_data record header. Every Protector
// reads only hdr[0:3] (type + version) for MAC/AAD construction; the two length
// bytes are placeholders, matching how record.Layer hands the template to Seal.
var covHdr = []byte{0x17, 0x03, 0x03, 0x00, 0x00}

// ---- Protector factories ---------------------------------------------------.
//
// Each returns a FRESH protector with fixed test keys. Round-trip and
// concurrency tests build a separate sender and receiver instance, mirroring a
// real TLS session where each direction owns independent state (this matters
// for the stateful GOST 28147 CNT+IMIT protector).

func newCBCProt(tb testing.TB) record.Protector {
	tb.Helper()

	p, err := record.NewCBCHMACProtector(
		aes.NewCipher, sha256.New,
		bytes.Repeat([]byte{0x01}, 16), // AES-128 enc key.
		bytes.Repeat([]byte{0x02}, 32), // HMAC-SHA256 mac key.
	)
	if err != nil {
		tb.Fatalf("NewCBCHMACProtector: %v", err)
	}

	return p
}

func newGCMProt(tb testing.TB) record.Protector {
	tb.Helper()

	p, err := record.NewAEADProtector(
		bytes.Repeat([]byte{0x03}, 16), // AES-128-GCM key.
		[]byte{0x0A, 0x0B, 0x0C, 0x0D}, // 4-byte salt.
	)
	if err != nil {
		tb.Fatalf("NewAEADProtector: %v", err)
	}

	return p
}

func newChaChaProt(tb testing.TB) record.Protector {
	tb.Helper()

	p, err := record.NewChaCha20Poly1305Protector(
		bytes.Repeat([]byte{0x04}, 32), // 32-byte key.
		bytes.Repeat([]byte{0x05}, 12), // 12-byte write IV.
	)
	if err != nil {
		tb.Fatalf("NewChaCha20Poly1305Protector: %v", err)
	}

	return p
}

func newGOST28147Prot(tb testing.TB) record.Protector {
	tb.Helper()

	p, err := record.NewGOST28147Protector(
		bytes.Repeat([]byte{0x06}, 32), // 32-byte enc key.
		bytes.Repeat([]byte{0x07}, 32), // 32-byte mac key.
		bytes.Repeat([]byte{0x08}, 8),  // 8-byte IV.
		gost.SboxTC26Z,
	)
	if err != nil {
		tb.Fatalf("NewGOST28147Protector: %v", err)
	}

	return p
}

func newKuznyechikProt(tb testing.TB) record.Protector {
	tb.Helper()

	p, err := record.NewKuznyechikCTROMACProtector(
		bytes.Repeat([]byte{0x09}, 32), // 32-byte enc key.
		bytes.Repeat([]byte{0x0A}, 32), // 32-byte mac key.
		bytes.Repeat([]byte{0x0B}, 8),  // 8-byte IV.
	)
	if err != nil {
		tb.Fatalf("NewKuznyechikCTROMACProtector: %v", err)
	}

	return p
}

func newMagmaProt(tb testing.TB) record.Protector {
	tb.Helper()

	p, err := record.NewMagmaCTROMACProtector(
		bytes.Repeat([]byte{0x0C}, 32), // 32-byte enc key.
		bytes.Repeat([]byte{0x0D}, 32), // 32-byte mac key.
		bytes.Repeat([]byte{0x0E}, 4),  // 4-byte IV.
	)
	if err != nil {
		tb.Fatalf("NewMagmaCTROMACProtector: %v", err)
	}

	return p
}

// ---- Gap 1: per-Protector round-trip fuzz ----------------------------------.

// fuzzProtectorRoundTrip is the shared body for every FuzzProtectorRoundTrip_*
// target. For arbitrary (seq, data) it asserts that a fresh receiver Opens what
// a fresh sender Sealed and recovers the exact plaintext, and that Open never
// panics on arbitrary or corrupted fragment bytes (an error is acceptable — a
// crash is not). The oracle is the Seal→Open inverse relationship itself; no
// external KAT is used.
func fuzzProtectorRoundTrip(f *testing.F, newProt func(testing.TB) record.Protector) {
	f.Helper()
	f.Add(uint64(0), []byte("hello record layer"))
	f.Add(uint64(1), []byte{})
	f.Add(uint64(0xffffffff), []byte{0x00})
	f.Add(uint64(1)<<40, bytes.Repeat([]byte{0xAB}, 130))

	f.Fuzz(func(t *testing.T, seq uint64, data []byte) {
		sealed, err := newProt(t).Seal(seq, covHdr, data)
		if err != nil {
			t.Fatalf("Seal(seq=%d, len=%d): %v", seq, len(data), err)
		}

		got, err := newProt(t).Open(seq, covHdr, sealed)
		if err != nil {
			t.Fatalf("Open of own Seal (seq=%d, len=%d): %v", seq, len(data), err)
		}

		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch (seq=%d): got %x, want %x", seq, got, data)
		}

		// Open on arbitrary bytes must not panic (error is fine).
		_, _ = newProt(t).Open(seq, covHdr, data)

		// Open on a corrupted fragment must not panic (should error).
		if len(sealed) > 0 {
			corrupt := append([]byte(nil), sealed...)

			corrupt[len(corrupt)-1] ^= 0xFF

			_, _ = newProt(t).Open(seq, covHdr, corrupt)
		}
	})
}

func FuzzProtectorRoundTrip_CBCHMAC(f *testing.F) {
	fuzzProtectorRoundTrip(f, newCBCProt)
}

func FuzzProtectorRoundTrip_AEADGCM(f *testing.F) {
	fuzzProtectorRoundTrip(f, newGCMProt)
}

func FuzzProtectorRoundTrip_ChaCha20Poly1305(f *testing.F) {
	fuzzProtectorRoundTrip(f, newChaChaProt)
}

func FuzzProtectorRoundTrip_GOST28147(f *testing.F) {
	fuzzProtectorRoundTrip(f, newGOST28147Prot)
}

func FuzzProtectorRoundTrip_KuznyechikCTROMAC(f *testing.F) {
	fuzzProtectorRoundTrip(f, newKuznyechikProt)
}

func FuzzProtectorRoundTrip_MagmaCTROMAC(f *testing.F) {
	fuzzProtectorRoundTrip(f, newMagmaProt)
}

// TestProtectorRoundTrip_Deterministic exercises the same round-trip property
// with a fixed table so the coverage lands even without the fuzz engine (which
// `go test` does not drive by default). Each Protector gets several sizes and
// sequence numbers.
func TestProtectorRoundTrip_Deterministic(t *testing.T) {
	t.Parallel()

	factories := map[string]func(testing.TB) record.Protector{
		"CBCHMAC":           newCBCProt,
		"AEADGCM":           newGCMProt,
		"ChaCha20Poly1305":  newChaChaProt,
		"GOST28147":         newGOST28147Prot,
		"KuznyechikCTROMAC": newKuznyechikProt,
		"MagmaCTROMAC":      newMagmaProt,
	}

	seqs := []uint64{0, 1, 63, 64, 255, 4096}
	sizes := []int{0, 1, 15, 16, 17, 64, 200}

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, seq := range seqs {
				for _, size := range sizes {
					plain := make([]byte, size)
					for i := range plain {
						plain[i] = byte(i*7 + int(seq))
					}

					sealed, err := factory(t).Seal(seq, covHdr, plain)
					if err != nil {
						t.Fatalf("seq=%d size=%d Seal: %v", seq, size, err)
					}

					got, err := factory(t).Open(seq, covHdr, sealed)
					if err != nil {
						t.Fatalf("seq=%d size=%d Open: %v", seq, size, err)
					}

					if !bytes.Equal(got, plain) {
						t.Fatalf("seq=%d size=%d round-trip mismatch: got %x, want %x",
							seq, size, got, plain)
					}
				}
			}
		})
	}
}

// ---- Gap 2: constant-time error EQUIVALENCE (bad MAC vs bad padding) --------.

// cbcEncryptZeroIV CBC-encrypts buf under encKey with an all-zero IV and returns
// IV || ciphertext — the exact fragment layout cbcHMACProtector.Open expects.
func cbcEncryptZeroIV(tb testing.TB, encKey, buf []byte) []byte {
	tb.Helper()

	block, err := aes.NewCipher(encKey)
	if err != nil {
		tb.Fatalf("aes.NewCipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	ct := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, buf)

	return append(append([]byte(nil), iv...), ct...)
}

// TestCBCHMAC_ErrorEquivalence_BadMAC_vs_BadPadding proves the Lucky13
// requirement: a CBC record with a valid-padding-but-wrong-MAC and a CBC record
// with malformed padding are rejected with the SAME error value — fatal
// AlertBadRecordMAC — so an attacker cannot distinguish the two failure modes.
//
// The two fragments are hand-built as decrypted buffers and CBC-encrypted, so
// the exact post-decrypt content (and thus which check fails) is deterministic:
//   - badMAC: 5 plaintext bytes, a 32-byte zero MAC (wrong), then 11 padding
//     bytes of value 10 (well-formed padding of length 10) → padding OK, MAC bad.
//   - badPad: last byte claims padding length 5 while the preceding bytes are 0
//     → padding malformed (the MAC is never validly checked).
func TestCBCHMAC_ErrorEquivalence_BadMAC_vs_BadPadding(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x01}, 16)
	macKey := bytes.Repeat([]byte{0x02}, 32)

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	if err != nil {
		t.Fatalf("NewCBCHMACProtector: %v", err)
	}

	// buf layout is 3 AES blocks = 48 bytes: plain(5) || mac(32) || pad(11).
	badMAC := make([]byte, 48)
	for i := range 5 {
		badMAC[i] = 0xAB // plaintext.
	}

	// badMAC[5:37] left as zeros → wrong MAC.
	for i := 37; i < 48; i++ {
		badMAC[i] = 0x0A // padLen=10 → 11 trailing bytes of value 10 = valid padding.
	}

	// buf layout: all zeros except a final length byte that lies about the
	// padding, so extractCBCPadding rejects it.
	badPad := make([]byte, 48)

	badPad[47] = 0x05 // claims 5 padding bytes, but badPad[42:47] are 0 → malformed.

	_, errMAC := prot.Open(0, covHdr, cbcEncryptZeroIV(t, encKey, badMAC))
	_, errPad := prot.Open(0, covHdr, cbcEncryptZeroIV(t, encKey, badPad))

	assertBadRecordMAC(t, "bad-MAC", errMAC)
	assertBadRecordMAC(t, "bad-padding", errPad)

	// The whole point of the Lucky13 mitigation: the two errors are the same
	// observable value.
	if errMAC.Error() != errPad.Error() {
		t.Errorf("error values distinguishable: bad-MAC=%q, bad-padding=%q",
			errMAC.Error(), errPad.Error())
	}
}

// assertBadRecordMAC fails the test unless err is a fatal AlertBadRecordMAC.
func assertBadRecordMAC(t *testing.T, label string, err error) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: expected error, got nil", label)
	}

	var ae *record.AlertError
	if !errors.As(err, &ae) {
		t.Fatalf("%s: expected *record.AlertError, got %T: %v", label, err, err)
	}

	if ae.Level != record.AlertLevelFatal || ae.Description != record.AlertBadRecordMAC {
		t.Errorf("%s: got AlertError{Level:%d, Description:%d}, want fatal BadRecordMAC",
			label, ae.Level, ae.Description)
	}
}

// ---- Gap 3: concurrent Read+Write over one Layer (-race) -------------------.

// TestLayer_ConcurrentReadWrite_Race drives WriteRecord and ReadRecord on the
// SAME Layer concurrently, over a net.Pipe loopback, with the same protector
// installed both directions. It pins the documented contract (record.go:84-92)
// that the send half (sendSeq/sendProt) and the recv half (recvSeq/recvProt)
// are disjoint and safe under concurrency. Run under -race, any accidental
// cross-half sharing is reported; the value comparisons confirm round-trip
// correctness in both directions.
//
// Wiring: L wraps c1, peer wraps c2 (net.Pipe cross-connects the two).
//
//	G1: L.WriteRecord   → c1 → c2 → peer.ReadRecord :G2   (A→B stream)
//	G3: peer.WriteRecord→ c2 → c1 → L.ReadRecord    :G4   (B→A stream)
//
// L is touched by G1 (send half) and G4 (recv half); peer by G2 and G3. AES-GCM
// is stateless per record (bound to seq), so independent sender/receiver
// instances stay in lockstep as long as records are delivered in order — which
// the synchronous, single-reader pipe guarantees.
func TestLayer_ConcurrentReadWrite_Race(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()

	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	// Safety net: never let a logic bug hang the suite forever.
	deadline := time.Now().Add(30 * time.Second)
	if err := c1.SetDeadline(deadline); err != nil {
		t.Fatalf("c1.SetDeadline: %v", err)
	}

	if err := c2.SetDeadline(deadline); err != nil {
		t.Fatalf("c2.SetDeadline: %v", err)
	}

	layerL := record.NewLayer(c1)
	layerL.ChangeCipherSpec(newGCMProt(t), newGCMProt(t))

	peer := record.NewLayer(c2)
	peer.ChangeCipherSpec(newGCMProt(t), newGCMProt(t))

	const n = 64

	aToB := make([][]byte, n)
	bToA := make([][]byte, n)

	for i := range n {
		aToB[i] = fmt.Appendf(nil, "A->B record #%d payload", i)
		bToA[i] = fmt.Appendf(nil, "B->A record #%d payload", i)
	}

	gotAtB := make([][]byte, n)
	gotBtA := make([][]byte, n)

	var wg sync.WaitGroup

	wg.Add(4)

	// G1: L sends the A→B stream.
	go func() {
		defer wg.Done()

		for i := range n {
			if err := layerL.WriteRecord(record.ContentTypeApplicationData, aToB[i]); err != nil {
				t.Errorf("L.WriteRecord[%d]: %v", i, err)

				return
			}
		}
	}()

	// G2: peer receives the A→B stream.
	go func() {
		defer wg.Done()

		for i := range n {
			_, p, err := peer.ReadRecord()
			if err != nil {
				t.Errorf("peer.ReadRecord[%d]: %v", i, err)

				return
			}

			gotAtB[i] = p
		}
	}()

	// G3: peer sends the B→A stream.
	go func() {
		defer wg.Done()

		for i := range n {
			if err := peer.WriteRecord(record.ContentTypeApplicationData, bToA[i]); err != nil {
				t.Errorf("peer.WriteRecord[%d]: %v", i, err)

				return
			}
		}
	}()

	// G4: L receives the B→A stream.
	go func() {
		defer wg.Done()

		for i := range n {
			_, p, err := layerL.ReadRecord()
			if err != nil {
				t.Errorf("L.ReadRecord[%d]: %v", i, err)

				return
			}

			gotBtA[i] = p
		}
	}()

	wg.Wait()

	for i := range n {
		if !bytes.Equal(gotAtB[i], aToB[i]) {
			t.Errorf("A->B[%d]: got %q, want %q", i, gotAtB[i], aToB[i])
		}

		if !bytes.Equal(gotBtA[i], bToA[i]) {
			t.Errorf("B->A[%d]: got %q, want %q", i, gotBtA[i], bToA[i])
		}
	}
}

// ---- Gap 4: AEAD binds the sequence number ---------------------------------.

// TestAEAD_BindsSequenceNumber proves the record sequence number is part of the
// AEAD additional data: a record sealed at seq=1 opens cleanly at seq=1 but is
// rejected at seq=0. For AES-GCM the on-wire explicit nonce carries seq=1, so
// the GCM nonce is identical at both open attempts — only the AAD's seq differs,
// isolating the failure to the AAD binding. ChaCha20-Poly1305 (no wire nonce)
// binds seq through both nonce and AAD; it is included as a second AEAD.
func TestAEAD_BindsSequenceNumber(t *testing.T) {
	t.Parallel()

	cases := map[string]func(testing.TB) record.Protector{
		"AES-GCM":           newGCMProt,
		"ChaCha20-Poly1305": newChaChaProt,
	}

	for name, factory := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			plain := []byte("sequence-bound payload")

			sealed, err := factory(t).Seal(1, covHdr, plain)
			if err != nil {
				t.Fatalf("Seal(seq=1): %v", err)
			}

			// Sanity: the same record opens at its own sequence number.
			got, err := factory(t).Open(1, covHdr, sealed)
			if err != nil {
				t.Fatalf("Open(seq=1) of seq=1 record: %v", err)
			}

			if !bytes.Equal(got, plain) {
				t.Fatalf("Open(seq=1): got %x, want %x", got, plain)
			}

			// The record must NOT open under a different sequence number.
			_, err = factory(t).Open(0, covHdr, sealed)
			assertBadRecordMAC(t, "Open(seq=0) of seq=1 record", err)
		})
	}
}
