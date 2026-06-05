package gostls

import (
	"context"
	"net"
)

// Dialer dials TLS connections. Its API mirrors crypto/tls.Dialer.
type Dialer struct {
	// NetDialer is the underlying network dialer used to establish the TCP
	// (or other) connection before the TLS handshake. If nil, a zero-value
	// net.Dialer is used.
	NetDialer *net.Dialer

	// Config is the TLS configuration applied to each new connection.
	// If nil, a zero-value Config is used (which requires InsecureSkipVerify
	// or a matching RootCAs + ServerName to succeed).
	Config *Config
}

// DialContext connects to addr using the network dialer, then performs a TLS
// handshake and returns the fully negotiated connection.
//
// The returned net.Conn is a *Conn. The handshake is completed before
// DialContext returns.
//
// ctx controls the lifetime of the dial; it is not propagated to subsequent
// Read/Write calls on the returned Conn.
//
// gostls is the pure-Go TLS backend (CGO_ENABLED=0 compatible). The OpenSSL
// backend lives in the separate go-tlsdialer module, which selects between
// gostls and OpenSSL.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	cfg := d.Config
	if cfg == nil {
		cfg = &Config{}
	}
	return dialBackend(ctx, network, addr, d.NetDialer, cfg)
}
