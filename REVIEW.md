# gostls deep correctness review — 2026-07-02

An in-depth, per-subsystem correctness/security review of the pure-Go TLS 1.2
GOST client. Five adversarial reviews (handshake state machine, key exchange,
record layer, suites/key-schedule, public API) were cross-checked by hand and
every actionable finding was verified with a concrete test case.

## Bottom line

The cryptographic core and the protocol state machine are **correct and
well-hardened**. Independently verified as sound: the Finished exchange
(transcript composition, constant-time `verify_data`), the ServerKeyExchange
signature binding, the Lucky13-constant-time CBC path (a faithful, correctly
branchless port of `crypto/tls`), the GOST CNT+IMIT and CTR-ACPKM+OMAC record
protection (validated against gost-engine etalons), VKO/GOST-2018 key agreement
(validated against live Tarantool-EE 3.5.0), the PRF and key schedule, record
framing/bounds, and the secure-by-default configuration (verification on, empty
`ServerName` fails closed).

No CRITICAL finding. The one HIGH is a liveness bug (deadlock), not a crypto
break. The remaining items are hardening, protocol-completeness, interop, and
test-coverage gaps.

---

## Fixed in this pass (with regression tests)

| Sev | Area | Defect | Fix | Test |
|---|---|---|---|---|
| **HIGH** | `conn.go` | `Close` acquired `outMu` with a plain `Lock`; a post-handshake `Write` stalled on a non-draining peer holds `outMu`, so `Close` deadlocks forever and never closes the transport that would unblock the Write. | `Close` now `TryLock`s `outMu` (skips close_notify if a Write holds it) and bounds the close_notify write with a 5s deadline. | `TestConn_Close_DoesNotBlockOnHeldOutMu`, `TestConn_Close_UnblocksBlockedWrite` |
| **MED** | `conn.go` | `Read` spun forever on a flood of consecutive zero-length application_data records (empty-record DoS). | Bound consecutive empty records to `maxEmptyRecords` (32), then error. | `TestConn_Read_RejectsEmptyRecordFlood`, `TestConn_Read_EmptyRecordsThenData` |
| **MED** | `internal/suites/suite.go` | `All()` ranged over a map → the default ClientHello cipher-suite order was randomized every handshake, silently discarding the client's stated preference and making the wire non-reproducible. | Preserve registration order via a `registryOrder` slice; `All()` returns a copy of it. | `TestSuites_All_DeterministicOrder` |
| **MED** | `internal/ke/dhe.go` | DHE accepted any server prime ≥1024 bits — the standardized 1024-bit groups are broken by precomputation (Logjam / CVE-2015-4000). | Raise the floor to 2048 bits (the client advertises only ffdhe2048/ffdhe3072). | `TestDHE_Rejects_1024BitPrime` |
| **MED** | `internal/handshake/client.go` | SKE signature dispatched purely on the wire `sigAlg` byte; the suite's `Auth` kind was never consulted, so an ECDHE-**RSA** suite could be authenticated with an ECDSA signature (algorithm confusion). | Added `skeSigAlgMatchesAuth`; both SKE verify paths now reject a sig-alg/auth mismatch. | `TestRecvServerFlight_SKE_SigAuthMismatch` |
| **MED** | `internal/suites/*` | `gost_suites.go`, `gost_detect_gost.go`, `engine_detect_noengine.go` relied on non-constraint filename suffixes; when the `openssl_gost_engine` counterpart lands it would double-register suite IDs → `panic`. | Added `//go:build !openssl_gost_engine` to the three files (verified the default and `-tags openssl_gost_engine` builds still compile). | build-verified |
| MED→LOW | `internal/suites/keyschedule.go` | Exported `KeyExpansion` derived 16-byte CBC `write_IV`s from the key block — TLS 1.0 behavior, wrong for TLS 1.2 (CBC uses a fresh per-record explicit IV). Dead in production (bypassed by `expandKeysManual`) but an exported footgun enshrined by a green test. | `keyBlockIVLen` returns 0 for CBC, matching the production path. | updated `TestKeySchedule_KeyExpansion` |
| LOW | `internal/record/record.go` | Decrypted plaintext length was never bounded to 2¹⁴ (only the ciphertext was), so an ~18 KB fragment was accepted. | Reject `len(plain) > 2¹⁴` with `record_overflow`. | `TestRecord_Rejects_OversizedPlaintext` |
| LOW | `internal/record/record.go` | Incoming record version was pinned to exactly `0x0303`, rejecting RFC 5246 App. E-legal `{3,1}` early records (interop). | Accept `0x0301..0x0303`; negotiated version still enforced in the handshake. | `TestRecord_Accepts_LegacyRecordVersion`, updated `TestRecord_Rejects_VersionMismatch` |
| LOW | `internal/handshake/client.go` | Handshake bytes coalesced after the server Finished were silently discarded. | Reject non-empty `hsBuf` after the server Finished (mirrors the client-CCS guard). | (mirrors tested guard; driven test recommended — see below) |
| LOW | `internal/handshake/messages.go` | `parseCertificateRequest` ignored trailing bytes after `certificate_authorities`. | Reject trailing bytes (matches the other strict parsers). | `TestParseMessage_CertificateRequest_TrailingBytes` |
| LOW | `internal/handshake/extensions.go` | `parseRenegotiationInfo` accepted trailing bytes after `renegotiated_connection` (RFC 5746 §3.2). | Reject trailing bytes. | `TestParseRenegotiationInfo_TrailingBytes` |
| LOW | `internal/handshake/types.go` | `ParseMessage(HelloRequest)` returned a `*ServerHelloDone` (type confusion). | Added a distinct `HelloRequest` type with empty-body validation. | `TestParseMessage_HelloRequest_IsDistinctType`, `_NonEmptyBody` |
| LOW | `internal/ke/vkogost.go` | VKO2012 path lacked the KEK-length and wrap-output-length guards the VKO2001 path has (defense-in-depth against a dependency regression). | Added length guards before the fixed-offset slicing. | covered by existing round-trip |
| LOW | `internal/suites/gost_suites.go` | Stale doc comments claimed Kuznyechik IV=16 / Magma IV=8 (actual 8 / 4). | Corrected the comments. | — |

All packages: `go build`, `go vet`, `go test` (incl. `-race` on the new conn
tests) pass under `CGO_ENABLED=0`.

---

## Not a bug (verified, do not "fix")

- **DHE premaster is left-padded to `len(p)`, not stripped.** RFC 5246 §8.1.2
  literally says strip leading zeros, but modern OpenSSL/NSS and RFC 7919 §5.4
  pad to `len(p)`, which the client already does (and a test enshrines). The
  padding convention is the safer, interoperable one; stripping would be a
  regression against modern servers. Left as-is with the 2048-bit floor added.
- **ECDHE curve acceptance.** The client advertises X25519, P-256/384/521 and
  ffdhe2048/3072; `curveByID` accepts exactly the four EC curves it advertises,
  so there is no "unadvertised curve" gap. `crypto/ecdh` validates points
  on-curve and rejects the identity.

---

## Deferred (documented, not changed this pass)

Ordered by value. None is a live security break for the client.

### Protocol completeness
- **No fatal alert sent to the peer on a record-layer decrypt/MAC failure**
  (RFC 5246 §7.2.2). The client detects the tamper and fails closed locally, but
  the peer sees only (at most) a `close_notify` warning. MED as RFC conformance;
  not a client-side security hole. Would require plumbing the record-layer
  `AlertError` code into a best-effort alert write on the error path.
- **Extended Master Secret (RFC 7627) is not offered.** No triple-handshake
  *detection*; practical risk is low here because there is no resumption and no
  renegotiation (both are rejected). MED interop (some servers require EMS).
  A real feature: offer `0x0017`, derive the master secret over `session_hash`
  when echoed.

### Hardening / correctness
- **DHE FFDHE allowlist** (stronger than the 2048 floor): byte-compare the
  server's `p`/`g` against the advertised ffdhe2048/ffdhe3072 constants and
  reject a custom/trapdoored prime. Deferred to avoid transcribing 2048/3072-bit
  primes without a dedicated KAT (the existing 3072 test constant looks
  malformed — verify before reuse).
- **ServerHello accepts client-only extensions** (`supported_groups`,
  `ec_point_formats`, `signature_algorithms`). Content is ignored, so cosmetic;
  restrict the ServerHello allow-set to `{renegotiation_info, server_name}`.
- **SNI carries IP literals** (`dialer_default.go`), which RFC 6066 §3 forbids.
  Needs splitting the SNI name from the verification name in `ClientParams`
  (verification via IP SAN still works). LOW interop.
- **`ConnectionState` is a dead struct** — declared, never populated, no
  accessor. Either wire it (retain the negotiated suite/version from the
  handshake) or delete it.
- **`Config.Rand` is not threaded into DHE** (ECDHE/RSA honor it; DHE always uses
  `crypto/rand`). Consistency/deterministic-test gap; production-safe.
- **Warning alerts abort the handshake.** Real servers send warning-level
  `unrecognized_name`; `crypto/tls` tolerates a bounded number. Fail-closed, so
  interop-only.
- **Empty-`ServerName` guard lives only in `conn.go`**, not in
  `parseAndVerifyChain`; add it there as defense-in-depth for direct
  `handshake.NewClientState` callers.
- **`wire_debug.go`**: the 0600 mode only applies on file creation; a
  pre-existing world-readable target or symlink is not tightened. Opt-in debug
  tool; `O_NOFOLLOW` is not portable via `os`, so left to the operator.
- **No write-side sticky error** on `record.Layer` mirroring the read side; the
  connection must not be reused after a write error (currently the caller's
  responsibility).
- **Secrets are not zeroized** (premaster, master secret, key block) — they live
  until GC. Hardening only.

### Test / fuzz coverage to add
- **KAT vectors** (currently self-derived, i.e. self-consistent not conformance):
  published IETF TLS 1.2 PRF vectors (SHA-256/384); offline HMAC-Streebog-256 and
  HMAC-GOSTR341194 P_hash KATs (extract from `tmp/engine/`); a gost-engine oracle
  vector for GOST-2018 (the test has a `TODO(phase5)`); an external VKO2012_256
  vector (only a round-trip exists today).
- **Fuzz**: `verifyECDHEServerKeyExchange` / `verifyDHEServerKeyExchange`
  (hand-rolled length arithmetic over attacker bytes, not reached by
  `ParseMessage`); `readHandshakeRecord` reassembly; per-protector
  `Open(Seal(x))==x` round-trip.
- **Driven tests**: server Finished with a coalesced trailing HelloRequest
  (exercises the new `hsBuf` guard end-to-end); a wrong-length (12↔32) Finished
  under a mismatched suite; a concurrent `Read`+`Write` `-race` test for the
  record-layer disjoint-halves contract.
- **Missing 512-bit GOST-2012 param set** (`VKO2012_512`) appears unimplemented;
  confirm whether any target server uses a 512-bit key.

### Not defects (by design, noted so they are not re-chased)
TLS 1.3, session resumption/tickets, renegotiation, ALPN, OCSP/SCT, client cert
chains, and a server role are all intentionally out of scope and fail closed.

---

## Second pass — coverage-gap tests + two more fixes

A follow-up multi-agent run wrote tests for the coverage gaps catalogued above
(write → adversarial mutation-verify → completeness ledger), added as
`covgap_review_test.go` in each package. Highlights: the `computeKeyExchange`
dispatch table, `Transcript.Sum` edge cases, unsolicited/duplicate ServerHello
extension rejection, per-protector `Open(Seal(x))==x` fuzz for all six record
protectors, a concurrent Read+Write `-race` test, AEAD sequence-number binding,
a differential TLS 1.2 PRF oracle (independent P_hash reimplementation), and
DHE/GOST-2018 property tests against independent primitives (`math/big`, raw
Streebog) — **no self-referential KATs**. KATs with no reachable independent
oracle (GOST-2018 composite, GOST PRF chained P_hash) were honestly deferred
rather than faked, because the only oracle is GPL gogost across the license
boundary.

That run surfaced two real RFC-hygiene bugs, now **fixed** (tests assert
rejection):
- ServerHello accepting a **duplicate extension type** (RFC 5246 §7.4.1.4) —
  `parseExtensions` now rejects repeats (`errDuplicateExtension`).
- ServerHello accepting a **non-empty `server_name` echo** (RFC 6066 §3) —
  `parseServerHello` now rejects it (`errServerHelloNonEmptySNI`).

Still deferred: the ServerHello allow-set is not narrowed to reject *offered but
ServerHello-invalid* extension types (`supported_groups` etc.), and the DHE
FFDHE exact allowlist, EMS, fatal-alert-to-peer, and the KAT oracles above.
