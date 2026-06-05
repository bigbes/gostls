package gostls

import (
	"context"
	"net"
)

// backendTag identifies which backend was compiled in.
// Used by tests to assert the correct code path is linked.
const backendTag = "default"

// BackendTag returns a string identifying the TLS backend compiled into this
// binary: "default" for the pure-Go backend, "openssl" for the CGO backend.
func BackendTag() string { return backendTag }

// dialBackend implements the pure-Go TLS backend.
// It dials a raw TCP connection using netDialer (or a zero-value net.Dialer
// if nil), then performs the TLS 1.2 handshake implemented in this package.
func dialBackend(ctx context.Context, network, addr string, netDialer *net.Dialer, cfg *Config) (net.Conn, error) {
	nd := netDialer
	if nd == nil {
		nd = &net.Dialer{}
	}

	rawConn, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := newConn(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return tlsConn, nil
}
