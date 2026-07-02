package handshake

import (
	"crypto/x509"
	"fmt"
)

// Protocol field widths and limits used in message parsing/marshaling.
const (
	// randomLen is the TLS client/server random field size (RFC 5246 §7.4.1.2).
	tlsRandomLen = 32

	// maxSessionIDLen is the maximum session_id length (RFC 5246 §7.4.1.2).
	maxSessionIDLen = 32

	// certEntryOverhead is the number of prefix bytes per cert in a Certificate message:
	// one uint24 length field.
	certEntryOverhead = sizeUint24

	// certListOverhead is the outer uint24 length prefix in a Certificate message.
	certListOverhead = sizeUint24
)

// ClientHello is the TLS 1.2 ClientHello message (RFC 5246 §7.4.1.2).
type ClientHello struct {
	Version            uint16
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8

	// Extensions — only the subset defined in extensions.go is supported.
	ServerName           string
	SupportedGroups      []uint16
	ECPointFormats       []uint8
	SignatureAlgorithms  []SigAndHash
	ExtendedMasterSecret bool
	RenegotiationInfo    bool
}

func (m *ClientHello) Type() Type { return TypeClientHello }

// Marshal serializes the ClientHello body (without the 4-byte handshake envelope).
func (m *ClientHello) Marshal() []byte {
	var out []byte

	out = appendUint16(out, m.Version)
	out = append(out, m.Random[:]...)

	// session_id: uint8 length + data; max 32 bytes (RFC 5246 §7.4.1.2).
	// Caller must not exceed 32 bytes; the parser rejects > 32 bytes on receipt.
	out = appendLenPrefixed8(out, m.SessionID)

	// cipher_suites: uint16 length (in bytes) + uint16 values.
	csLen := uint16(pairSize * len(m.CipherSuites))

	out = appendUint16(out, csLen)

	for _, cs := range m.CipherSuites {
		out = appendUint16(out, cs)
	}

	// compression_methods: uint8 length + bytes.
	out = appendLenPrefixed8(out, m.CompressionMethods)

	// extensions (optional).
	ext := parsedExtensions{
		ServerName:           m.ServerName,
		SupportedGroups:      m.SupportedGroups,
		ECPointFormats:       m.ECPointFormats,
		SignatureAlgorithms:  m.SignatureAlgorithms,
		ExtendedMasterSecret: m.ExtendedMasterSecret,
		RenegotiationInfo:    m.RenegotiationInfo,
	}
	if extBytes := marshalExtensions(ext); extBytes != nil {
		out = append(out, extBytes...)
	}

	return out
}

// parseClientHello parses a ClientHello from the raw body (no 4-byte envelope).
func parseClientHello(b []byte) (*ClientHello, error) {
	var m ClientHello

	// client_version (uint16).
	v, rest, err := readUint16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ClientHello version: %w", err)
	}

	m.Version = v
	b = rest

	// random[32].
	rawRandom, rest, err := readBytes(b, tlsRandomLen)
	if err != nil {
		return nil, fmt.Errorf("handshake: ClientHello random: %w", err)
	}

	copy(m.Random[:], rawRandom)

	b = rest

	// session_id: uint8 length prefix, max 32.
	sid, rest, err := readLenPrefixed8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ClientHello session_id: %w", err)
	}

	if len(sid) > maxSessionIDLen {
		return nil, fmt.Errorf("%w: %d", errCHSessionIDTooLong, len(sid))
	}

	if len(sid) > 0 {
		m.SessionID = append([]byte(nil), sid...)
	}

	b = rest

	// cipher_suites: uint16 byte-length prefix + uint16 values.
	csBytes, rest, err := readLenPrefixed16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ClientHello cipher_suites: %w", err)
	}

	if len(csBytes)%2 != 0 {
		return nil, fmt.Errorf("%w: %d", errCHCSOddByteCount, len(csBytes))
	}

	if len(csBytes) < pairSize {
		return nil, errCHCSAtLeastOne
	}

	m.CipherSuites = make([]uint16, len(csBytes)/pairSize)
	for i := range m.CipherSuites {
		m.CipherSuites[i] = uint16(csBytes[pairSize*i])<<bitsPerByte | uint16(csBytes[pairSize*i+1])
	}

	b = rest

	// compression_methods: uint8 length + bytes; at least one (null).
	cm, rest, err := readLenPrefixed8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ClientHello compression_methods: %w", err)
	}

	if len(cm) == 0 {
		return nil, errCHCMAtLeastOne
	}

	m.CompressionMethods = append([]uint8(nil), cm...)
	b = rest

	// extensions (optional — present only if bytes remain).
	if len(b) > 0 {
		extList, rest, err := readLenPrefixed16(b)
		if err != nil {
			return nil, fmt.Errorf("handshake: ClientHello extensions: %w", err)
		}

		if len(rest) != 0 {
			return nil, fmt.Errorf("%w: %d bytes", errCHTrailingData, len(rest))
		}

		ext, _, err := parseExtensions(extList)
		if err != nil {
			return nil, err
		}

		m.ServerName = ext.ServerName
		m.SupportedGroups = ext.SupportedGroups
		m.ECPointFormats = ext.ECPointFormats
		m.SignatureAlgorithms = ext.SignatureAlgorithms
		m.ExtendedMasterSecret = ext.ExtendedMasterSecret
		m.RenegotiationInfo = ext.RenegotiationInfo
	}

	return &m, nil
}

// ServerHello is the TLS 1.2 ServerHello message (RFC 5246 §7.4.1.3).
type ServerHello struct {
	Version           uint16
	Random            [32]byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8

	// Extensions.
	ExtendedMasterSecret bool
	RenegotiationInfo    bool

	// ExtensionTypes lists the extension type codes present in the message, in
	// the order received, so the caller can verify the server only returned
	// extensions the client offered (RFC 5246 §7.4.1.4).
	ExtensionTypes []uint16
}

func (m *ServerHello) Type() Type { return TypeServerHello }

// Marshal serializes the ServerHello body.
func (m *ServerHello) Marshal() []byte {
	var out []byte

	out = appendUint16(out, m.Version)
	out = append(out, m.Random[:]...)

	// session_id: uint8 length + data; max 32 bytes (RFC 5246 §7.4.1.3).
	// Caller must not exceed 32 bytes; the parser rejects > 32 bytes on receipt.
	out = appendLenPrefixed8(out, m.SessionID)
	out = appendUint16(out, m.CipherSuite)
	out = appendUint8(out, m.CompressionMethod)

	ext := parsedExtensions{
		ExtendedMasterSecret: m.ExtendedMasterSecret,
		RenegotiationInfo:    m.RenegotiationInfo,
	}
	if extBytes := marshalExtensions(ext); extBytes != nil {
		out = append(out, extBytes...)
	}

	return out
}

// parseServerHello parses a ServerHello from the raw body.
func parseServerHello(b []byte) (*ServerHello, error) {
	var m ServerHello

	v, rest, err := readUint16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ServerHello version: %w", err)
	}

	m.Version = v
	b = rest

	rawRandom, rest, err := readBytes(b, tlsRandomLen)
	if err != nil {
		return nil, fmt.Errorf("handshake: ServerHello random: %w", err)
	}

	copy(m.Random[:], rawRandom)

	b = rest

	sid, rest, err := readLenPrefixed8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ServerHello session_id: %w", err)
	}

	if len(sid) > maxSessionIDLen {
		return nil, fmt.Errorf("%w: %d", errSHSessionIDTooLong, len(sid))
	}

	if len(sid) > 0 {
		m.SessionID = append([]byte(nil), sid...)
	}

	b = rest

	cs, rest, err := readUint16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ServerHello cipher_suite: %w", err)
	}

	m.CipherSuite = cs
	b = rest

	cm, rest, err := readUint8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: ServerHello compression_method: %w", err)
	}

	m.CompressionMethod = cm
	b = rest

	if len(b) > 0 {
		extList, rest, err := readLenPrefixed16(b)
		if err != nil {
			return nil, fmt.Errorf("handshake: ServerHello extensions: %w", err)
		}

		if len(rest) != 0 {
			return nil, fmt.Errorf("%w: %d bytes", errSHTrailingData, len(rest))
		}

		ext, seen, err := parseExtensions(extList)
		if err != nil {
			return nil, err
		}

		// The ServerHello server_name extension_data MUST be empty (RFC 6066 §3):
		// a non-empty host_name echo is a protocol violation.
		if ext.ServerName != "" {
			return nil, errServerHelloNonEmptySNI
		}

		m.ExtendedMasterSecret = ext.ExtendedMasterSecret
		m.RenegotiationInfo = ext.RenegotiationInfo
		m.ExtensionTypes = seen
	}

	return &m, nil
}

// Certificate is the TLS 1.2 Certificate message (RFC 5246 §7.4.2).
// The certificate_list uses 24-bit length prefixes both for the outer list
// and for each individual certificate.
type Certificate struct {
	// Certificates holds parsed *x509.Certificate values when available.
	// May be nil if the certs were not parsed (e.g. raw test data).
	Certificates []*x509.Certificate

	// RawCerts holds the DER-encoded certificates as received on the wire.
	// This is the authoritative source for marshaling and is always populated.
	RawCerts [][]byte
}

func (m *Certificate) Type() Type { return TypeCertificate }

// Marshal serializes the Certificate body.
func (m *Certificate) Marshal() []byte {
	// Compute total inner length first.
	innerLen := 0
	for _, c := range m.RawCerts {
		innerLen += certEntryOverhead + len(c) // uint24 len + cert bytes.
	}

	out := make([]byte, 0, certListOverhead+innerLen)

	out = appendUint24(out, uint32(innerLen))

	for _, c := range m.RawCerts {
		out = appendUint24(out, uint32(len(c)))
		out = append(out, c...)
	}

	return out
}

// parseCertificate parses a Certificate message body.
func parseCertificate(b []byte) (*Certificate, error) {
	var m Certificate

	// Outer 24-bit length prefix.
	listBytes, rest, err := readLenPrefixed24(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: Certificate list: %w", err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes", errCertTrailingData, len(rest))
	}

	for len(listBytes) > 0 {
		certBytes, rest, err := readLenPrefixed24(listBytes)
		if err != nil {
			return nil, fmt.Errorf("handshake: Certificate entry: %w", err)
		}

		if len(certBytes) == 0 {
			return nil, errCertEntryZeroLen
		}

		m.RawCerts = append(m.RawCerts, append([]byte(nil), certBytes...))
		listBytes = rest
	}

	return &m, nil
}

// ServerKeyExchange is the TLS 1.2 ServerKeyExchange message (RFC 5246 §7.4.3).
// The body is suite-dependent and treated as an opaque blob at this layer.
// Phase 5 parses the inner structure per key-exchange algorithm.
type ServerKeyExchange struct {
	Body []byte
}

func (m *ServerKeyExchange) Type() Type { return TypeServerKeyExchange }

func (m *ServerKeyExchange) Marshal() []byte {
	return append([]byte(nil), m.Body...)
}

func parseServerKeyExchange(b []byte) *ServerKeyExchange {
	return &ServerKeyExchange{Body: append([]byte(nil), b...)}
}

// HelloRequest is the TLS 1.2 HelloRequest message (RFC 5246 §7.4.1.1). It has
// a zero-length body. A conforming client never accepts it mid-handshake (the
// state machine rejects it); it is modeled as its own type so ParseMessage does
// not alias it onto ServerHelloDone, which would be a type-confusion footgun for
// any direct caller.
type HelloRequest struct{}

func (m *HelloRequest) Type() Type      { return TypeHelloRequest }
func (m *HelloRequest) Marshal() []byte { return nil }

func parseHelloRequest(b []byte) (*HelloRequest, error) {
	if len(b) != 0 {
		return nil, fmt.Errorf("%w, got %d bytes", errHelloRequestNonEmptyBody, len(b))
	}

	return &HelloRequest{}, nil
}

// ServerHelloDone is the TLS 1.2 ServerHelloDone message (RFC 5246 §7.4.5).
// It has a zero-length body.
type ServerHelloDone struct{}

func (m *ServerHelloDone) Type() Type      { return TypeServerHelloDone }
func (m *ServerHelloDone) Marshal() []byte { return nil }

func parseServerHelloDone(b []byte) (*ServerHelloDone, error) {
	if len(b) != 0 {
		return nil, fmt.Errorf("%w, got %d bytes", errSHDNonEmptyBody, len(b))
	}

	return &ServerHelloDone{}, nil
}

// CertificateRequest is the TLS 1.2 CertificateRequest message (RFC 5246 §7.4.4).
// This message is sent by the server when it requires client authentication.
// The client never sends this message; Marshal returns nil.
type CertificateRequest struct {
	CertificateTypes       []uint8
	SupportedSignatureAlgs []SigAndHash
	CertificateAuthorities [][]byte
}

func (m *CertificateRequest) Type() Type { return TypeCertificateRequest }

// Marshal returns nil — the client never sends CertificateRequest.
func (m *CertificateRequest) Marshal() []byte { return nil }

// parseCertificateRequest parses a CertificateRequest body (no 4-byte envelope).
// Wire format (RFC 5246 §7.4.4):
//
//	certificate_types<1..2^8-1>  — uint8 length prefix + type bytes
//	supported_signature_algorithms<2..2^16-1> — uint16 byte-length prefix + SigAndHash pairs
//	certificate_authorities<0..2^16-1> — uint16 byte-length prefix + {uint16 dn_len + DER}*
func parseCertificateRequest(b []byte) (*CertificateRequest, error) {
	var m CertificateRequest

	// certificate_types: uint8 length prefix.
	typesBytes, rest, err := readLenPrefixed8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: CertificateRequest certificate_types: %w", err)
	}

	m.CertificateTypes = append([]uint8(nil), typesBytes...)
	b = rest

	// supported_signature_algorithms: uint16 byte-length prefix.
	sigAlgsBytes, rest, err := readLenPrefixed16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: CertificateRequest supported_signature_algorithms: %w", err)
	}

	if len(sigAlgsBytes)%2 != 0 {
		return nil, fmt.Errorf("%w: %d", errCRSAOddByteCount, len(sigAlgsBytes))
	}

	m.SupportedSignatureAlgs = make([]SigAndHash, len(sigAlgsBytes)/pairSize)
	for i := range m.SupportedSignatureAlgs {
		m.SupportedSignatureAlgs[i] = SigAndHash{
			Hash: sigAlgsBytes[pairSize*i],
			Sig:  sigAlgsBytes[pairSize*i+1],
		}
	}

	b = rest

	// certificate_authorities: uint16 byte-length prefix + list of {uint16 len, DER}.
	casBytes, tail, err := readLenPrefixed16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: CertificateRequest certificate_authorities: %w", err)
	}

	// Reject trailing bytes after certificate_authorities, matching the strict
	// parsing of the other handshake messages (no silent acceptance of garbage).
	if len(tail) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after CertificateRequest",
			errTrailingHandshakeBytes, len(tail))
	}

	for len(casBytes) > 0 {
		dn, rest, err := readLenPrefixed16(casBytes)
		if err != nil {
			return nil, fmt.Errorf("handshake: CertificateRequest certificate_authorities entry: %w", err)
		}

		m.CertificateAuthorities = append(m.CertificateAuthorities, append([]byte(nil), dn...))
		casBytes = rest
	}

	return &m, nil
}

// ClientKeyExchange is the TLS 1.2 ClientKeyExchange message (RFC 5246 §7.4.7).
// The body is suite-dependent and treated as an opaque blob at this layer.
type ClientKeyExchange struct {
	Body []byte
}

func (m *ClientKeyExchange) Type() Type { return TypeClientKeyExchange }

func (m *ClientKeyExchange) Marshal() []byte {
	return append([]byte(nil), m.Body...)
}

func parseClientKeyExchange(b []byte) *ClientKeyExchange {
	return &ClientKeyExchange{Body: append([]byte(nil), b...)}
}

// CertificateVerify is the TLS 1.2 CertificateVerify message (RFC 5246 §7.4.8).
// Format: SignatureAndHashAlgorithm (2 bytes) + uint16 signature length + signature.
type CertificateVerify struct {
	Algorithm SigAndHash
	Signature []byte
}

func (m *CertificateVerify) Type() Type { return TypeCertificateVerify }

func (m *CertificateVerify) Marshal() []byte {
	var out []byte

	out = appendUint8(out, m.Algorithm.Hash)
	out = appendUint8(out, m.Algorithm.Sig)
	out = appendLenPrefixed16(out, m.Signature)

	return out
}

func parseCertificateVerify(b []byte) (*CertificateVerify, error) {
	var m CertificateVerify

	hashByte, rest, err := readUint8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: CertificateVerify hash: %w", err)
	}

	m.Algorithm.Hash = hashByte
	b = rest

	sigByte, rest, err := readUint8(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: CertificateVerify sig: %w", err)
	}

	m.Algorithm.Sig = sigByte
	b = rest

	sig, _, err := readLenPrefixed16(b)
	if err != nil {
		return nil, fmt.Errorf("handshake: CertificateVerify signature: %w", err)
	}

	m.Signature = append([]byte(nil), sig...)

	return &m, nil
}

// Finished is the TLS 1.2 Finished message (RFC 5246 §7.4.9).
// verify_data is 12 bytes for standard TLS 1.2. For GOST 2018 key-exchange
// suites (0xC100 / 0xC101) it is 32 bytes
// (ssl/t1_enc.c:tls1_final_finish_mac).
type Finished struct {
	VerifyData []byte
}

func (m *Finished) Type() Type { return TypeFinished }

func (m *Finished) Marshal() []byte {
	out := make([]byte, len(m.VerifyData))
	copy(out, m.VerifyData)

	return out
}

func parseFinished(b []byte) (*Finished, error) {
	if len(b) != 12 && len(b) != 32 {
		return nil, fmt.Errorf("%w, have %d", errFinishedVerifyLen, len(b))
	}

	return &Finished{VerifyData: append([]byte(nil), b...)}, nil
}
