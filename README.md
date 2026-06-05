# gostls

A pure-Go TLS 1.2 client with **GOST cipher suites**, shaped like
`crypto/tls`: `Dialer`, `Conn`, `Config`. It speaks the ordinary AES /
ECDHE / ChaCha20-Poly1305 suites *and* the GOST suites (GOST 28147-89,
Kuznyechik / Magma CTR-OMAC, VKO / GOST-2018 key exchange) that the standard
library does not.

**Pure-Go, BSD-2-Clause, `CGO_ENABLED=0`.** It is the pure-Go backend for the
go-tlsdialer-shaped dialer; the alternative cgo OpenSSL backend lives in that
separate dialer module.

This module was extracted from `go.bigb.es/tlsdialer`.

## Layout

```
gostls/                 package gostls — crypto/tls-shaped Dialer / Conn / Config
  config.go conn.go dialer.go suites.go
  internal/handshake/   client state machine
  internal/ke/          key exchange (ECDHE / DHE / RSA; VKO GOST 2001/2012; GOST-2018)
  internal/record/      record layer (null / CBC-HMAC / AEAD / ChaCha20 / GOST CNT-IMIT)
  internal/suites/      suite registry, key schedule, PRF (incl. GOST suites)
```

GOST primitives are provided by
[`gostcrypto`](https://github.com/bigbes/gostcrypto); GOST X.509 by its
`x509gost` subpackage. gostls supplies the *TLS protocol* use of them (the GOST
PRFs, the CTR-ACPKM record mode, the VKO/GOST-2018 key-exchange glue).

## Build & test

`gostcrypto` is co-developed and wired in by a `replace` directive, so check it
out as a sibling directory (`../gostcrypto`):

```sh
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
```

## Licensing

BSD-2-Clause; links zero GPL code. Depends on `gostcrypto` (BSD-2-Clause),
`filippo.io/bigmod`, and `golang.org/x/crypto`. See [NOTICE](NOTICE).
