package handshake

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/bigbes/gostls/internal/ke"
	"github.com/bigbes/gostls/internal/record"
	"github.com/bigbes/gostls/internal/suites"
)

// ClientCertificate holds a client certificate and its private key for mutual
// TLS authentication. It mirrors tls.Certificate in structure but is internal
// to the handshake package.
type ClientCertificate struct {
	// RawCertificate holds the DER-encoded certificate. Must be non-empty when
	// used for authentication.
	RawCertificate []byte
	// PrivateKey is the private key corresponding to the certificate's public
	// key. Must be *rsa.PrivateKey or *ecdsa.PrivateKey.
	PrivateKey crypto.PrivateKey
	// Certificate is the parsed certificate (optional; parsed from RawCertificate
	// on demand if nil).
	Certificate *x509.Certificate
}

// clientSigAlgsAdvertised is the single source of truth for the
// SignatureAlgorithms extension sent in ClientHello. selectClientSigAlg iterates
// this list to find the first entry that the server also supports and is
// compatible with the client key. sendClientHello references the same slice.
var clientSigAlgsAdvertised = []SigAndHash{
	{Hash: 0x04, Sig: 0x01}, // rsa_pkcs1_sha256
	{Hash: 0x05, Sig: 0x01}, // rsa_pkcs1_sha384
	{Hash: 0x04, Sig: 0x03}, // ecdsa_secp256r1_sha256
	{Hash: 0x05, Sig: 0x03}, // ecdsa_secp384r1_sha384
	{Hash: 0x02, Sig: 0x01}, // rsa_pkcs1_sha1 (legacy fallback)
}

// availableCipherNames is the set of cipher names negotiable by the default
// client configuration. GOST suites are registered in every build (clean-room
// backend) but are not included in this default set; applications requesting
// GOST must set Config.CipherSuites explicitly.
var availableCipherNames = map[string]bool{
	"AES-128-CBC":       true,
	"AES-256-CBC":       true,
	"AES-128-GCM":       true,
	"AES-256-GCM":       true,
	"CHACHA20-POLY1305": true,
}

// AvailableSuites returns the list of cipher suite IDs that can be negotiated
// in this phase, filtered to the cipher families listed in availableCipherNames.
func AvailableSuites() []uint16 {
	all := suites.All()
	ids := make([]uint16, 0, len(all))
	for _, s := range all {
		if availableCipherNames[s.Cipher.Name] {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// ClientParams carries the inputs the client state machine needs.
type ClientParams struct {
	// Rand is the source of randomness for client random and ephemeral keys.
	Rand io.Reader

	// ServerName is sent in the SNI extension (if non-empty).
	ServerName string

	// OfferedSuites is the list of cipher suite IDs to offer. Must not be empty.
	OfferedSuites []uint16

	// RootCAs is the trust store for certificate verification. If nil, the
	// platform default is used.
	RootCAs *x509.CertPool

	// InsecureSkipVerify skips certificate verification when true.
	InsecureSkipVerify bool

	// VerifyPeerCertificate is called after normal cert verification.
	VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error

	// GOSTRoots is the trust store for GOST-signed server certificates.
	// It must be a []*x509gost.Certificate. Typed as any so the field's
	// signature does not force every importer of this package to depend on
	// x509gost; cert_gost.go type-asserts it.
	GOSTRoots any

	// Certificates contains client certificates for mutual TLS authentication.
	// When the server sends a CertificateRequest, the first entry is offered.
	// If empty or no supported signature algorithm is found, an empty Certificate
	// message is sent (which is legal per RFC 5246 §7.4.6).
	Certificates []ClientCertificate
}

// ClientState holds the mutable state for a client handshake.
type ClientState struct {
	params     ClientParams
	layer      *record.Layer
	transcript *Transcript

	clientRandom [32]byte
	serverRandom [32]byte
	suite        *suites.Suite
	masterSecret []byte

	// certReq is populated when the server sends a CertificateRequest during
	// the server flight (between Certificate and ServerHelloDone). It is nil
	// when no CertificateRequest was received. Phase 3 consults this field to
	// decide whether to emit a client Certificate + CertificateVerify.
	certReq *CertificateRequest

	// clientCertSent is true when sendClientCertificate emitted a non-empty
	// Certificate message. Step 8.5 in Handshake() only calls
	// sendCertificateVerify when this is true.
	clientCertSent bool

	// clientSigAlg is the SignatureAndHashAlgorithm chosen by selectClientSigAlg
	// for the CertificateVerify. Only valid when clientCertSent is true.
	clientSigAlg SigAndHash

	// gostLeaf holds the parsed *x509gost.Certificate for the server leaf when
	// the certificate is GOST-signed. Populated by parseAndVerifyLeaf; typed as
	// any so this struct's definition does not force an x509gost import on
	// every importer of the package.
	gostLeaf any

	// Set after handshake completes.
	done bool
}

// NewClientState creates a new client handshake state machine.
func NewClientState(layer *record.Layer, params ClientParams) *ClientState {
	return &ClientState{
		params:     params,
		layer:      layer,
		transcript: NewTranscript(),
	}
}

// Handshake runs the full TLS 1.2 client handshake.
// On success, layer is fully configured for application data.
// On failure, a fatal alert has been sent and the error is returned.
func (c *ClientState) Handshake() error {
	// Step 1: send ClientHello.
	if err := c.sendClientHello(); err != nil {
		return err
	}

	// Step 2: receive ServerHello.
	if err := c.recvServerHello(); err != nil {
		return err
	}

	// Step 3: receive Certificate.
	serverCert, serverCertMsg, err := c.recvCertificate()
	if err != nil {
		return err
	}

	// Step 4: receive optional ServerKeyExchange, optional CertificateRequest,
	// and ServerHelloDone. RFC 5246 §7.3 ordering: SKE (if any) must precede
	// CertificateRequest; each may appear at most once.
	serverKeyExchParams, err := c.recvServerFlight(serverCert)
	if err != nil {
		return err
	}

	// Step 5: build the Exchange and compute pre-master secret.
	preMaster, ckeBody, err := c.computeKeyExchange(serverCert, serverKeyExchParams, serverCertMsg.RawCerts)
	if err != nil {
		return err
	}

	// Step 6: derive master secret.
	masterSecret, err := suites.MasterSecret(c.suite, preMaster, c.clientRandom[:], c.serverRandom[:])
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: master secret: %w", err))
	}
	c.masterSecret = masterSecret

	// Step 7: key expansion and protector assembly.
	km, sendProt, recvProt, err := c.expandKeys()
	if err != nil {
		return err
	}
	_ = km

	// Step 7.5: if the server sent a CertificateRequest, emit client Certificate
	// (possibly empty). selectClientSigAlg is called once here; sendClientCertificate
	// uses the same result internally. If a non-empty cert was sent, record the
	// chosen alg for Step 8.5.
	if c.certReq != nil {
		alg, _ := c.selectClientSigAlg()
		sent, err := c.sendClientCertificate()
		if err != nil {
			return err
		}
		if sent {
			c.clientCertSent = true
			c.clientSigAlg = alg
		}
	}

	// Step 8: send ClientKeyExchange.
	cke := &ClientKeyExchange{Body: ckeBody}
	ckeEnv := MarshalMessage(cke)
	if err := c.layer.WriteRecord(record.ContentTypeHandshake, ckeEnv); err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: send ClientKeyExchange: %w", err))
	}
	c.transcript.Write(ckeEnv)

	// Step 8.5: emit CertificateVerify if a non-empty client Certificate was sent.
	// Invariant: CertVerify is emitted iff a non-empty client cert was emitted.
	if c.clientCertSent {
		if err := c.sendCertificateVerify(c.clientSigAlg); err != nil {
			return err
		}
	}

	// Step 9: send ChangeCipherSpec.
	if err := c.layer.WriteRecord(record.ContentTypeChangeCipherSpec, []byte{1}); err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: send CCS: %w", err))
	}
	// Install send protector.
	c.layer.ChangeCipherSpec(sendProt, nil)

	// Step 10: send Finished.
	transcriptHash, err := c.transcript.Sum(c.suite.PRF.Hash)
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: transcript sum for client Finished: %w", err))
	}
	clientVerifyData, err := suites.FinishedVerifyData(c.suite, masterSecret, "client finished", transcriptHash)
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: client finished verify_data: %w", err))
	}
	clientFinished := Finished{VerifyData: clientVerifyData}
	clientFinishedEnv := MarshalMessage(&clientFinished)
	if err := c.layer.WriteRecord(record.ContentTypeHandshake, clientFinishedEnv); err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: send client Finished: %w", err))
	}
	c.transcript.Write(clientFinishedEnv)

	// Step 11: receive server ChangeCipherSpec.
	for {
		recvCT, recvPayload, err := c.layer.ReadRecord()
		if err != nil {
			return c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: read server CCS: %w", err))
		}
		if recvCT == record.ContentTypeChangeCipherSpec {
			if len(recvPayload) != 1 || recvPayload[0] != 1 {
				return c.fatal(record.AlertUnexpectedMessage, fmt.Errorf("tls: malformed CCS payload"))
			}
			break
		}
		// Unexpected record type.
		return c.fatal(record.AlertUnexpectedMessage,
			fmt.Errorf("tls: expected ChangeCipherSpec, got content type %d", recvCT))
	}
	// Install recv protector after receiving server CCS.
	c.layer.ChangeCipherSpec(nil, recvProt)

	// Step 12: receive server Finished.
	serverFinishedType, serverFinishedPayload, err := c.readHandshakeRecord()
	if err != nil {
		return c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: read server Finished: %w", err))
	}
	if serverFinishedType != TypeFinished {
		return c.fatal(record.AlertUnexpectedMessage,
			fmt.Errorf("tls: expected Finished, got type %d", serverFinishedType))
	}
	serverFinishedMsg, _, err := ParseMessage(buildEnvelope(TypeFinished, serverFinishedPayload))
	if err != nil {
		return c.fatal(record.AlertDecryptError, fmt.Errorf("tls: parse server Finished: %w", err))
	}
	serverFinished := serverFinishedMsg.(*Finished)

	// Compute expected server Finished using transcript BEFORE the server Finished message.
	serverTranscriptHash, err := c.transcript.Sum(c.suite.PRF.Hash)
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: transcript sum for server Finished: %w", err))
	}
	expectedServerVerifyData, err := suites.FinishedVerifyData(c.suite, masterSecret, "server finished", serverTranscriptHash)
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: server finished verify_data: %w", err))
	}

	if !suites.EqualVerifyData(serverFinished.VerifyData[:], expectedServerVerifyData) {
		return c.fatal(record.AlertDecryptError, fmt.Errorf("tls: server Finished verify_data mismatch"))
	}
	c.transcript.Write(buildEnvelope(TypeFinished, serverFinishedPayload))

	c.done = true
	return nil
}

// sendClientHello builds and sends the ClientHello message.
func (c *ClientState) sendClientHello() error {
	var random [32]byte
	if _, err := io.ReadFull(c.params.Rand, random[:]); err != nil {
		return fmt.Errorf("tls: generate client random: %w", err)
	}
	c.clientRandom = random

	hello := &ClientHello{
		Version:            0x0303,
		Random:             random,
		SessionID:          nil,
		CipherSuites:       c.params.OfferedSuites,
		CompressionMethods: []uint8{0},
		ServerName:         c.params.ServerName,
		SupportedGroups: []uint16{
			0x001D, // X25519
			0x0017, // secp256r1 (P-256)
			0x0018, // secp384r1 (P-384)
			0x0019, // secp521r1 (P-521)
			0x0100, // ffdhe2048 (RFC 7919)
			0x0101, // ffdhe3072 (RFC 7919)
		},
		ECPointFormats:       []uint8{0x00}, // uncompressed only
		SignatureAlgorithms:  clientSigAlgsAdvertised,
		ExtendedMasterSecret: false, // deferred: see Phase 10
		RenegotiationInfo:    true,  // RFC 5746 initial handshake marker
	}

	env := MarshalMessage(hello)
	if err := c.layer.WriteRecord(record.ContentTypeHandshake, env); err != nil {
		return fmt.Errorf("tls: send ClientHello: %w", err)
	}
	c.transcript.Write(env)
	return nil
}

// recvServerHello reads and validates the ServerHello.
func (c *ClientState) recvServerHello() error {
	msgType, payload, err := c.readHandshakeRecord()
	if err != nil {
		return c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: read ServerHello: %w", err))
	}
	if msgType != TypeServerHello {
		return c.fatal(record.AlertUnexpectedMessage, fmt.Errorf("tls: expected ServerHello, got type %d", msgType))
	}

	msg, _, err := ParseMessage(buildEnvelope(TypeServerHello, payload))
	if err != nil {
		return c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: parse ServerHello: %w", err))
	}
	sh := msg.(*ServerHello)

	// Verify version = TLS 1.2.
	if sh.Version != 0x0303 {
		return c.fatal(record.AlertProtocolVersion,
			fmt.Errorf("tls: server selected version 0x%04x, want 0x0303", sh.Version))
	}

	// Verify the chosen cipher suite was offered.
	offered := slices.Contains(c.params.OfferedSuites, sh.CipherSuite)
	if !offered {
		return c.fatal(record.AlertIllegalParameter,
			fmt.Errorf("tls: server chose cipher suite 0x%04x which was not offered", sh.CipherSuite))
	}

	// Look up the suite.
	suite, ok := suites.Lookup(sh.CipherSuite)
	if !ok {
		return c.fatal(record.AlertIllegalParameter,
			fmt.Errorf("tls: server chose unknown cipher suite 0x%04x", sh.CipherSuite))
	}
	c.suite = suite

	// Verify compression = null.
	if sh.CompressionMethod != 0 {
		return c.fatal(record.AlertIllegalParameter,
			fmt.Errorf("tls: server chose non-null compression method %d", sh.CompressionMethod))
	}

	// Server extensions must be a subset of what we offered or are expected.
	// We allow: renegotiation_info (empty, RFC 5746).
	// We did not offer extended_master_secret, so reject if server sends it.
	if sh.ExtendedMasterSecret {
		return c.fatal(record.AlertUnsupportedExtension,
			fmt.Errorf("tls: server sent extended_master_secret extension but we did not offer it"))
	}

	c.serverRandom = sh.Random

	c.transcript.Write(buildEnvelope(TypeServerHello, payload))
	return nil
}

// recvCertificate reads and validates the server Certificate message.
func (c *ClientState) recvCertificate() (*x509.Certificate, *Certificate, error) {
	msgType, payload, err := c.readHandshakeRecord()
	if err != nil {
		return nil, nil, c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: read Certificate: %w", err))
	}
	if msgType != TypeCertificate {
		return nil, nil, c.fatal(record.AlertUnexpectedMessage,
			fmt.Errorf("tls: expected Certificate, got type %d", msgType))
	}

	msg, _, err := ParseMessage(buildEnvelope(TypeCertificate, payload))
	if err != nil {
		return nil, nil, c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: parse Certificate: %w", err))
	}
	certMsg := msg.(*Certificate)

	if len(certMsg.RawCerts) == 0 {
		return nil, nil, c.fatal(record.AlertBadCertificate,
			fmt.Errorf("tls: server sent empty certificate list"))
	}

	// Parse the leaf certificate and verify the chain. parseAndVerifyLeaf is
	// x509gost-aware: GOST-signed certs are parsed/verified via x509gost, other
	// certs fall back to stdlib x509.
	leafCert, verifiedChains, err := parseAndVerifyLeaf(c, certMsg.RawCerts[0])
	if err != nil {
		return nil, nil, c.fatal(record.AlertBadCertificate, fmt.Errorf("tls: %w", err))
	}

	if c.params.VerifyPeerCertificate != nil {
		if err := c.params.VerifyPeerCertificate(certMsg.RawCerts, verifiedChains); err != nil {
			return nil, nil, c.fatal(record.AlertBadCertificate,
				fmt.Errorf("tls: VerifyPeerCertificate: %w", err))
		}
	}

	c.transcript.Write(buildEnvelope(TypeCertificate, payload))
	return leafCert, certMsg, nil
}

// recvServerFlight reads the server flight after Certificate:
// an optional ServerKeyExchange, an optional CertificateRequest, and the
// mandatory ServerHelloDone. RFC 5246 §7.3 ordering is enforced:
//   - ServerKeyExchange (if present) must appear before CertificateRequest.
//   - Each message may appear at most once.
//
// On success, serverKeyExchParams holds the opaque SKE params (nil if no SKE
// was received) and c.certReq is set if a CertificateRequest was received.
// The post-loop SKE-required check enforces that suites needing SKE (ECDHE,
// DHE) actually received one.
func (c *ClientState) recvServerFlight(serverCert *x509.Certificate) (serverKeyExchParams []byte, err error) {
	var sawSKE, sawCertReq bool

flight:
	for {
		ct, payload, err := c.readHandshakeRecord()
		if err != nil {
			return nil, c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: read server flight: %w", err))
		}

		switch ct {
		case TypeServerKeyExchange:
			if sawSKE {
				return nil, c.fatal(record.AlertUnexpectedMessage,
					fmt.Errorf("tls: duplicate ServerKeyExchange in server flight"))
			}
			if sawCertReq {
				return nil, c.fatal(record.AlertUnexpectedMessage,
					fmt.Errorf("tls: ServerKeyExchange received after CertificateRequest (out of order)"))
			}
			sawSKE = true

			msg, _, err := ParseMessage(buildEnvelope(TypeServerKeyExchange, payload))
			if err != nil {
				return nil, c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: parse ServerKeyExchange: %w", err))
			}
			ske := msg.(*ServerKeyExchange)
			c.transcript.Write(buildEnvelope(TypeServerKeyExchange, payload))

			serverKeyExchParams, err = c.verifyServerKeyExchange(ske.Body, serverCert)
			if err != nil {
				return nil, err
			}

		case TypeCertificateRequest:
			if sawCertReq {
				return nil, c.fatal(record.AlertUnexpectedMessage,
					fmt.Errorf("tls: duplicate CertificateRequest in server flight"))
			}
			sawCertReq = true

			msg, _, err := ParseMessage(buildEnvelope(TypeCertificateRequest, payload))
			if err != nil {
				return nil, c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: parse CertificateRequest: %w", err))
			}
			c.certReq = msg.(*CertificateRequest)
			c.transcript.Write(buildEnvelope(TypeCertificateRequest, payload))

		case TypeServerHelloDone:
			msg, _, err := ParseMessage(buildEnvelope(TypeServerHelloDone, payload))
			if err != nil {
				return nil, c.fatal(record.AlertHandshakeFailure, fmt.Errorf("tls: parse ServerHelloDone: %w", err))
			}
			_ = msg
			c.transcript.Write(buildEnvelope(TypeServerHelloDone, payload))
			// SHD is the terminal message of the server flight.
			break flight

		default:
			return nil, c.fatal(record.AlertUnexpectedMessage,
				fmt.Errorf("tls: unexpected message type %d in server flight", ct))
		}
	}

	// Post-loop: enforce that ECDHE and DHE suites received a ServerKeyExchange.
	if !sawSKE {
		switch c.suite.KX {
		case suites.KexRSA, suites.KexGOST2001, suites.KexGOST2012_256, suites.KexGOST2018_256:
			// No ServerKeyExchange expected — server cert carries the static
			// key material (RSA transport, or VKO/key-transport per RFC 9189 §4 /
			// RFC 9367 — GOST 2018 is key-transport, server cert provides the
			// recipient public key for kexp15 wrapping).
		default:
			return nil, c.fatal(record.AlertUnexpectedMessage,
				fmt.Errorf("tls: ServerKeyExchange required for %s but not received", c.suite.Name))
		}
	}

	return serverKeyExchParams, nil
}

// verifyServerKeyExchange verifies the ServerKeyExchange signature and
// returns the opaque server params that will be passed to the key exchange.
// For ECDHE: returns the curve_type || named_curve || point section (without signature).
// For DHE: returns the dh_p || dh_g || dh_Ys section (without signature).
func (c *ClientState) verifyServerKeyExchange(body []byte, cert *x509.Certificate) ([]byte, error) {
	switch c.suite.KX {
	case suites.KexECDHE:
		return c.verifyECDHEServerKeyExchange(body, cert)
	case suites.KexDHE:
		return c.verifyDHEServerKeyExchange(body, cert)
	default:
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: unexpected ServerKeyExchange for suite %s (KX=%d)", c.suite.Name, c.suite.KX))
	}
}

// verifyECDHEServerKeyExchange parses and verifies an ECDHE ServerKeyExchange.
// Wire format per RFC 4492 §5.4:
//
//	ECCurveType curve_type  (1 byte, must be 3 = named_curve)
//	NamedCurve named_curve  (2 bytes)
//	uint8 point_len
//	ECPoint point           (point_len bytes)
//	SignatureAndHashAlgorithm  (2 bytes)
//	uint16 sig_len
//	signature               (sig_len bytes)
func (c *ClientState) verifyECDHEServerKeyExchange(body []byte, cert *x509.Certificate) ([]byte, error) {
	if len(body) < 4 {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: ECDHE ServerKeyExchange too short: %d bytes", len(body)))
	}

	curveType := body[0]
	if curveType != 3 {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: ECDHE ServerKeyExchange: unsupported curve_type %d", curveType))
	}

	namedCurve := binary.BigEndian.Uint16(body[1:3])
	pointLen := int(body[3])
	if len(body) < 4+pointLen+2 {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: ECDHE ServerKeyExchange: body truncated after point"))
	}
	// server params = curve_type || named_curve || point_len || point (for the key exchange)
	serverParams := body[:4+pointLen]

	// Parse signature.
	sigData := body[4+pointLen:]
	if len(sigData) < 4 {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: ECDHE ServerKeyExchange: signature section too short"))
	}
	hashAlg := sigData[0]
	sigAlg := sigData[1]
	sigLen := int(binary.BigEndian.Uint16(sigData[2:4]))
	if len(sigData) < 4+sigLen {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: ECDHE ServerKeyExchange: signature truncated"))
	}
	sig := sigData[4 : 4+sigLen]

	// Build signed data: clientRandom || serverRandom || curve_type || named_curve || point_len || point
	// (RFC 4492 §5.4: the signature covers client_random + server_random + ServerECDHParams)
	// ServerECDHParams is the entire params section: curve_type || named_curve || public.
	signed := make([]byte, 32+32+len(serverParams))
	copy(signed[:32], c.clientRandom[:])
	copy(signed[32:64], c.serverRandom[:])
	copy(signed[64:], serverParams)

	if err := verifySignature(cert, hashAlg, sigAlg, signed, sig); err != nil {
		return nil, c.fatal(record.AlertDecryptError,
			fmt.Errorf("tls: ECDHE ServerKeyExchange signature verification: %w", err))
	}

	// named_curve is not in the 4-byte point header; for ke.ECDHEExchange we need:
	// curve_type (1) || named_curve (2) || point_len (1) || point (point_len)
	_ = namedCurve
	return serverParams, nil
}

// verifyDHEServerKeyExchange parses and verifies a DHE ServerKeyExchange.
// Wire format per RFC 5246 §7.4.3:
//
//	dh_p  opaque<1..2^16-1>   (2-byte length prefix)
//	dh_g  opaque<1..2^16-1>   (2-byte length prefix)
//	dh_Ys opaque<1..2^16-1>   (2-byte length prefix)
//	SignatureAndHashAlgorithm  (2 bytes)
//	uint16 sig_len
//	signature                  (sig_len bytes)
func (c *ClientState) verifyDHEServerKeyExchange(body []byte, cert *x509.Certificate) ([]byte, error) {
	// Parse dh_p, dh_g, dh_Ys (2-byte length-prefixed each).
	pBytes, rest, err := readU16LenPrefixedBuf(body)
	if err != nil {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: DHE ServerKeyExchange: parse dh_p: %w", err))
	}
	gBytes, rest, err := readU16LenPrefixedBuf(rest)
	if err != nil {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: DHE ServerKeyExchange: parse dh_g: %w", err))
	}
	YsBytes, rest, err := readU16LenPrefixedBuf(rest)
	if err != nil {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: DHE ServerKeyExchange: parse dh_Ys: %w", err))
	}

	// serverParams is everything before the signature.
	serverParamsLen := len(body) - len(rest)
	serverParams := body[:serverParamsLen]

	// Parse signature.
	if len(rest) < 4 {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: DHE ServerKeyExchange: signature section too short"))
	}
	hashAlg := rest[0]
	sigAlg := rest[1]
	sigLen := int(binary.BigEndian.Uint16(rest[2:4]))
	if len(rest) < 4+sigLen {
		return nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: DHE ServerKeyExchange: signature truncated"))
	}
	sig := rest[4 : 4+sigLen]

	// Signed data: clientRandom || serverRandom || ServerDHParams.
	signed := make([]byte, 32+32+len(serverParams))
	copy(signed[:32], c.clientRandom[:])
	copy(signed[32:64], c.serverRandom[:])
	copy(signed[64:], serverParams)

	if err := verifySignature(cert, hashAlg, sigAlg, signed, sig); err != nil {
		return nil, c.fatal(record.AlertDecryptError,
			fmt.Errorf("tls: DHE ServerKeyExchange signature verification: %w", err))
	}

	// Re-encode the DHE params for ke.DHEExchange: dh_p || dh_g || dh_Ys (2-byte len-prefixed).
	// serverParams already has this form directly from the wire.
	_ = pBytes
	_ = gBytes
	_ = YsBytes
	return serverParams, nil
}

// readU16LenPrefixedBuf reads a uint16-length-prefixed field from buf.
func readU16LenPrefixedBuf(buf []byte) (data, rest []byte, err error) {
	if len(buf) < 2 {
		return nil, nil, fmt.Errorf("truncated: need 2 bytes for length prefix, have %d", len(buf))
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	buf = buf[2:]
	if len(buf) < n {
		return nil, nil, fmt.Errorf("truncated: need %d bytes, have %d", n, len(buf))
	}
	return buf[:n], buf[n:], nil
}

// verifySignature verifies a TLS 1.2 digital signature over signed using
// cert's public key. hashAlg and sigAlg are the RFC 5246 algorithm byte values.
func verifySignature(cert *x509.Certificate, hashAlg, sigAlg uint8, signed, sig []byte) error {
	// Use hashForSigAlg — single source of truth for the hash-byte dispatch.
	cryptoHash, err := hashForSigAlg(hashAlg)
	if err != nil {
		return err
	}
	h := cryptoHash.New()
	h.Write(signed)
	digest := h.Sum(nil)

	switch sigAlg {
	case 0x01: // rsa
		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("cert public key is not RSA (got %T)", cert.PublicKey)
		}
		return verifyRSASignature(rsaPub, hashAlg, digest, sig)
	case 0x03: // ecdsa
		ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("cert public key is not ECDSA (got %T)", cert.PublicKey)
		}
		return verifyECDSASignature(ecPub, digest, sig)
	default:
		return fmt.Errorf("unsupported signature algorithm 0x%02x", sigAlg)
	}
}

// computeKeyExchange runs the key exchange for the chosen suite.
// Returns (preMaster, ckeBody, error).
func (c *ClientState) computeKeyExchange(cert *x509.Certificate, serverParams []byte, rawCerts [][]byte) ([]byte, []byte, error) {
	var exchange ke.Exchange
	switch c.suite.KX {
	case suites.KexECDHE:
		exchange = ke.NewECDHEExchangeWithRand(c.params.Rand)
	case suites.KexDHE:
		exchange = ke.NewDHEExchange(nil)
	case suites.KexRSA:
		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, c.fatal(record.AlertBadCertificate,
				fmt.Errorf("tls: RSA key exchange but cert has %T public key", cert.PublicKey))
		}
		exchange = ke.NewRSAExchangeWithRand(c.params.Rand, rsaPub)
	case suites.KexGOST2001, suites.KexGOST2012_256, suites.KexGOST2018_256:
		e, err := buildGOSTExchange(c)
		if err != nil {
			return nil, nil, c.fatal(record.AlertHandshakeFailure, err)
		}
		exchange = e
	default:
		return nil, nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: unknown KX kind %d for suite %s", c.suite.KX, c.suite.Name))
	}

	ckeBody, preMaster, err := exchange.ClientKeyExchange(serverParams)
	if err != nil {
		return nil, nil, c.fatal(record.AlertHandshakeFailure,
			fmt.Errorf("tls: ClientKeyExchange: %w", err))
	}
	return preMaster, ckeBody, nil
}

// hashForSigAlg maps a TLS hash algorithm byte (RFC 5246 §7.4.1.4.1) to the
// corresponding crypto.Hash. Used by both verifySignature and the sign path in
// sendCertificateVerify.
func hashForSigAlg(hashByte uint8) (crypto.Hash, error) {
	switch hashByte {
	case 0x02:
		return crypto.SHA1, nil
	case 0x04:
		return crypto.SHA256, nil
	case 0x05:
		return crypto.SHA384, nil
	case 0x06:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm 0x%02x", hashByte)
	}
}

// selectClientSigAlg iterates clientSigAlgsAdvertised and returns the first
// entry that:
//  1. Appears in c.certReq.SupportedSignatureAlgs, and
//  2. Is compatible with c.params.Certificates[0].PrivateKey.
//
// Compatibility rules:
//   - *rsa.PrivateKey → sig 0x01 (rsa_pkcs1)
//   - *ecdsa.PrivateKey with P-256 → {hash 0x04, sig 0x03} (sha256+ecdsa)
//   - *ecdsa.PrivateKey with P-384 → {hash 0x05, sig 0x03} (sha384+ecdsa)
//
// Returns (alg, true) on match; (zero, false) when no match is possible.
func (c *ClientState) selectClientSigAlg() (SigAndHash, bool) {
	if c.certReq == nil || len(c.params.Certificates) == 0 {
		return SigAndHash{}, false
	}
	key := c.params.Certificates[0].PrivateKey

	// Determine which (hash, sig) combinations the key supports.
	keyCompatible := func(alg SigAndHash) bool {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			_ = k
			return alg.Sig == 0x01 // rsa_pkcs1
		case *ecdsa.PrivateKey:
			switch alg.Sig {
			case 0x03: // ecdsa
				switch k.Curve {
				case elliptic.P256():
					return alg.Hash == 0x04 // sha256
				case elliptic.P384():
					return alg.Hash == 0x05 // sha384
				}
			}
			return false
		default:
			return false
		}
	}

	// Build a set of server-supported algs for O(1) lookup.
	serverHas := make(map[SigAndHash]bool, len(c.certReq.SupportedSignatureAlgs))
	for _, sa := range c.certReq.SupportedSignatureAlgs {
		serverHas[sa] = true
	}

	// Iterate our advertised list in order; return the first match.
	for _, alg := range clientSigAlgsAdvertised {
		if serverHas[alg] && keyCompatible(alg) {
			return alg, true
		}
	}
	return SigAndHash{}, false
}

// sendClientCertificate emits the client Certificate handshake message.
//
//   - If len(c.params.Certificates) == 0 or selectClientSigAlg returned false:
//     emits an empty Certificate message and returns (false, nil).
//   - Otherwise: emits a single-entry Certificate with Certificates[0].RawCertificate
//     and returns (true, nil).
//
// The message is appended to the transcript in either case.
func (c *ClientState) sendClientCertificate() (sent bool, err error) {
	alg, algOK := c.selectClientSigAlg()
	_ = alg

	var certMsg *Certificate
	if !algOK || len(c.params.Certificates) == 0 {
		// Empty Certificate — legal per RFC 5246 §7.4.6.
		certMsg = &Certificate{}
	} else {
		certMsg = &Certificate{
			RawCerts: [][]byte{c.params.Certificates[0].RawCertificate},
		}
	}

	env := MarshalMessage(certMsg)
	if writeErr := c.layer.WriteRecord(record.ContentTypeHandshake, env); writeErr != nil {
		return false, c.fatal(record.AlertInternalError, fmt.Errorf("tls: send client Certificate: %w", writeErr))
	}
	c.transcript.Write(env)

	return algOK && len(c.params.Certificates) > 0, nil
}

// sendCertificateVerify signs the current transcript with the client's private
// key using alg, emits the CertificateVerify message, and appends it to the
// transcript.
//
// The digest is computed over the transcript *before* the CertificateVerify
// itself is appended (invariant per RFC 5246 §7.4.8).
func (c *ClientState) sendCertificateVerify(alg SigAndHash) error {
	cryptoHash, err := hashForSigAlg(alg.Hash)
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: CertificateVerify: %w", err))
	}

	digest, err := c.transcript.Sum(cryptoHash.New)
	if err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: CertificateVerify transcript sum: %w", err))
	}

	key := c.params.Certificates[0].PrivateKey
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(c.params.Rand, k, cryptoHash, digest)
		if err != nil {
			return c.fatal(record.AlertInternalError, fmt.Errorf("tls: CertificateVerify RSA sign: %w", err))
		}
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(c.params.Rand, k, digest)
		if err != nil {
			return c.fatal(record.AlertInternalError, fmt.Errorf("tls: CertificateVerify ECDSA sign: %w", err))
		}
	default:
		return c.fatal(record.AlertInternalError,
			fmt.Errorf("tls: CertificateVerify: unsupported key type %T", key))
	}

	cv := &CertificateVerify{Algorithm: alg, Signature: sig}
	env := MarshalMessage(cv)
	if err := c.layer.WriteRecord(record.ContentTypeHandshake, env); err != nil {
		return c.fatal(record.AlertInternalError, fmt.Errorf("tls: send CertificateVerify: %w", err))
	}
	c.transcript.Write(env)
	return nil
}

// expandKeys derives the key material and constructs send/recv Protectors.
func (c *ClientState) expandKeys() (*suites.KeyMaterial, record.Protector, record.Protector, error) {
	// For CBC suites: FixedIVLen in the suite is 16 (block size), but TLS 1.2 CBC
	// uses a random per-record IV, not one from key expansion. We temporarily zero
	// FixedIVLen for key expansion purposes.
	//
	// AEAD suites and GOST 28147-89 CNT both draw the implicit IV from the
	// key block (AEAD salt for GCM/ChaCha20; RFC 9189 §4.2 fixed IV for GOST CNT).
	// The RFC 9367 Kuznyechik/Magma CTR+OMAC suites are also marked AEAD=true
	// (integrated MAC) so they share the AEAD path here.
	ivLen := c.suite.Cipher.FixedIVLen
	// For non-AEAD stream-like or stream+MAC ciphers (GOST28147-CNT,
	// KUZNYECHIK-CTR-OMAC, MAGMA-CTR-OMAC) the implicit IV comes from the
	// key block. For CBC suites it does not — IV is a random per-record
	// explicit nonce. Treat only CBC as "no IV in key block".
	isCBC := !c.suite.Cipher.AEAD &&
		c.suite.Cipher.Name != "GOST28147-CNT" &&
		c.suite.Cipher.Name != "KUZNYECHIK-CTR-OMAC" &&
		c.suite.Cipher.Name != "MAGMA-CTR-OMAC"
	if isCBC {
		ivLen = 0
	}

	// Compute total key material needed.
	macKeyLen := c.suite.MAC.KeyLen
	encKeyLen := c.suite.Cipher.KeyLen
	totalLen := 2*macKeyLen + 2*encKeyLen + 2*ivLen
	if totalLen == 0 {
		return nil, nil, nil, c.fatal(record.AlertInternalError,
			fmt.Errorf("tls: key expansion total length is zero for suite %s", c.suite.Name))
	}

	// Use KeyExpansion. Note: KeyExpansion in suites uses suite.Cipher.FixedIVLen
	// directly. For CBC suites we need to override; compute manually.
	km, err := expandKeysManual(c.suite, c.masterSecret, c.clientRandom[:], c.serverRandom[:], ivLen)
	if err != nil {
		return nil, nil, nil, c.fatal(record.AlertInternalError,
			fmt.Errorf("tls: key expansion: %w", err))
	}

	sendProt, err := buildProtector(c.suite, km.ClientEncKey, km.ClientMACKey, km.ClientIV, c.params.Rand)
	if err != nil {
		return nil, nil, nil, c.fatal(record.AlertInternalError,
			fmt.Errorf("tls: build send protector: %w", err))
	}
	recvProt, err := buildProtector(c.suite, km.ServerEncKey, km.ServerMACKey, km.ServerIV, c.params.Rand)
	if err != nil {
		return nil, nil, nil, c.fatal(record.AlertInternalError,
			fmt.Errorf("tls: build recv protector: %w", err))
	}

	return km, sendProt, recvProt, nil
}

// fatal sends a fatal alert and returns an error wrapping the cause.
func (c *ClientState) fatal(alertDesc uint8, cause error) error {
	alertBody := record.EncodeAlert(record.AlertLevelFatal, alertDesc)
	// Best effort: ignore write error since we're already in an error path.
	_ = c.layer.WriteRecord(record.ContentTypeAlert, alertBody)
	return cause
}

// readHandshakeRecord reads records until a handshake record is found.
// Alert records are decoded and returned as errors.
func (c *ClientState) readHandshakeRecord() (Type, []byte, error) {
	for {
		ct, payload, err := c.layer.ReadRecord()
		if err != nil {
			return 0, nil, err
		}
		switch ct {
		case record.ContentTypeHandshake:
			if len(payload) < 4 {
				return 0, nil, fmt.Errorf("tls: handshake record too short: %d bytes", len(payload))
			}
			msgType := Type(payload[0])
			bodyLen := uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
			if uint32(len(payload)) < 4+bodyLen {
				return 0, nil, fmt.Errorf("tls: handshake body truncated: declared %d, have %d", bodyLen, len(payload)-4)
			}
			return msgType, payload[4 : 4+bodyLen], nil
		case record.ContentTypeAlert:
			if len(payload) < 2 {
				return 0, nil, fmt.Errorf("tls: alert record truncated")
			}
			level, desc := record.DecodeAlert(payload)
			return 0, nil, fmt.Errorf("tls: received alert level=%d desc=%d", level, desc)
		default:
			return 0, nil, fmt.Errorf("tls: unexpected record type %d during handshake", ct)
		}
	}
}

// buildEnvelope wraps a body with the 4-byte handshake envelope.
func buildEnvelope(msgType Type, body []byte) []byte {
	env := make([]byte, 4+len(body))
	env[0] = byte(msgType)
	env[1] = byte(len(body) >> 16)
	env[2] = byte(len(body) >> 8)
	env[3] = byte(len(body))
	copy(env[4:], body)
	return env
}

// expandKeysManual performs key expansion with an explicit ivLen override.
// This allows CBC suites to use ivLen=0 while keeping the suite's MAC/enc lengths.
func expandKeysManual(suite *suites.Suite, masterSecret, clientRandom, serverRandom []byte, ivLen int) (*suites.KeyMaterial, error) {
	// seed is server_random || client_random per RFC 5246 §6.3.
	seed := make([]byte, 64)
	copy(seed[:32], serverRandom)
	copy(seed[32:], clientRandom)

	macKeyLen := suite.MAC.KeyLen
	encKeyLen := suite.Cipher.KeyLen
	totalLen := 2*macKeyLen + 2*encKeyLen + 2*ivLen
	if totalLen == 0 {
		return nil, fmt.Errorf("key expansion total length is zero")
	}

	keyBlock, err := suites.PRF(suite.PRF.Hash, masterSecret, []byte("key expansion"), seed, totalLen)
	if err != nil {
		return nil, err
	}

	km := &suites.KeyMaterial{}
	off := 0
	if macKeyLen > 0 {
		km.ClientMACKey = keyBlock[off : off+macKeyLen]
		off += macKeyLen
		km.ServerMACKey = keyBlock[off : off+macKeyLen]
		off += macKeyLen
	}
	km.ClientEncKey = keyBlock[off : off+encKeyLen]
	off += encKeyLen
	km.ServerEncKey = keyBlock[off : off+encKeyLen]
	off += encKeyLen
	if ivLen > 0 {
		km.ClientIV = keyBlock[off : off+ivLen]
		off += ivLen
		km.ServerIV = keyBlock[off : off+ivLen]
	}

	return km, nil
}
