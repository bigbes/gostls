# TODO — gostls

Carried over from `gostcrypto/TODO.md` (pre-split monorepo notes),
re-verified against this module 2026-06-10.

## Under-tested

- **`internal/handshake/transcript_test.go`** covers happy path, nil factory,
  and shape-collision regression. Missing: `Sum` on an empty transcript
  (before any `Write`), `Sum` idempotence (two back-to-back calls return
  identical bytes), `Write` interleaved with `Sum` calls.
- **`computeKeyExchange` KX dispatch** (`internal/handshake/client.go`
  ~722-753) has no unit test — covered only transitively by live-EE
  integration runs. A table-driven test over every `(suite.KX, server message
  type)` combination would prevent the latent `unknown KX kind` class of bug
  that previously survived from Phase 6 to Phase 10.
- **`Transcript.buf` is unbounded** (`internal/handshake/transcript.go`).
  A pathological handshake that Writes without bound would OOM. Real max is a
  few KB; no cap, no cap test. Acceptable today, but worth a cap before ever
  accepting untrusted server input on a long-lived handshake.
- **`record.Layer` disjoint-halves claim** (`internal/record/record.go:50-57`):
  "concurrent WriteRecord + ReadRecord safe; same-side not safe" is a
  contract-by-doc — no race test exercises either half.
- **Fuzz/bench gaps**: `FuzzParseMessage` and `FuzzParseExtensions` exist; the
  record-layer parser has no fuzz target, and there are no benchmarks anywhere
  in the module (transcript buffer-and-replay cost confirmed theoretically,
  never measured).

## Structural

- **`internal/suites/gost_suites.go` references a future
  `gost_suites_openssl_engine.go`** that does not exist yet. When it lands, no
  process or test enforces that both register the same ID/Name sets — add a
  cross-tag invariant test (same IDs modulo intentional exceptions) to catch
  silent backend divergence.
- **TLS 1.3** — out of scope; the module is TLS 1.2 only (documented in
  `config.go`).
