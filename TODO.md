# TODO — gostls

See **`REVIEW.md`** for the full 2026-07-02 deep-review findings (what was fixed
and what remains). This file tracks the still-open items only.

## Corrected since the last revision (no longer open)

- `Transcript.buf` **is** now capped (`maxTranscriptBytes = 256 KiB`,
  `internal/handshake/transcript.go`) — the old "unbounded" note is stale.
- The record-layer parser **has** a fuzz target (`FuzzReadRecord`,
  `internal/record/fuzz_test.go`); the DHE/GOST-DER parsers have fuzz targets in
  `internal/ke/fuzz_test.go`. The old "no record fuzz" note is stale.
- The `openssl_gost_engine` double-registration hazard is now guarded by
  `//go:build !openssl_gost_engine` on the default-backend files (still needs the
  cross-tag invariant test when the counterpart lands — see below).
- Post-decrypt plaintext is now bounded to 2¹⁴; the record version is now lenient
  (0x0301–0x0303) for interop.

## Under-tested (still open)

- **`internal/handshake/transcript_test.go`**: `Sum` on an empty transcript,
  `Sum` idempotence, and `Write` interleaved with `Sum`.
- **`computeKeyExchange` KX dispatch** (`internal/handshake/client.go`): no unit
  test over every `(suite.KX, server message type)` combination; covered only by
  live-EE runs.
- **`record.Layer` disjoint-halves**: concurrent `WriteRecord`+`ReadRecord`
  safety is a contract-by-doc; add a `-race` loopback test.
- **KAT gaps** (self-derived, not conformance): published IETF TLS 1.2 PRF
  vectors; offline HMAC-Streebog-256 / HMAC-GOSTR341194 P_hash KATs; a
  gost-engine oracle vector for GOST-2018 (`gost2018_test.go` `TODO(phase5)`); an
  external VKO2012_256 vector.
- **Fuzz gaps**: `verifyECDHEServerKeyExchange` / `verifyDHEServerKeyExchange`
  (attacker-driven length arithmetic, not reached by `ParseMessage`);
  `readHandshakeRecord` reassembly; per-protector `Open(Seal(x))==x` round-trip.
- **Driven tests**: coalesced trailing HelloRequest after the server Finished
  (exercises the new `hsBuf` guard end-to-end); wrong-length Finished under a
  mismatched suite.
- **No benchmarks** anywhere in the module.

## Structural / features (see REVIEW.md “Deferred”)

- Cross-tag invariant test for the future `gost_suites_openssl_engine.go`
  (same ID/Name sets modulo intentional exceptions).
- Fatal alert to the peer on record-layer errors (RFC 5246 §7.2.2).
- Extended Master Secret (RFC 7627).
- DHE FFDHE exact-allowlist (stronger than the current 2048-bit floor).
- `ConnectionState` accessor (currently a dead struct).
- Thread `Config.Rand` into DHE for consistency.
- `VKO2012_512` (512-bit GOST-2012 param set) — confirm whether any target
  server needs it.
- **TLS 1.3** — out of scope; the module is TLS 1.2 only (documented in
  `config.go`).
