package handshake

import "errors"

// Sentinel errors used throughout the handshake package. Dynamic context
// (version numbers, suite IDs, type bytes, lengths) is added by callers via
// fmt.Errorf("...: %w", errXxx) so that errors.Is / errors.As still works.

// Transcript.
var errNilHashFactory = errors.New("handshake: transcript: nil hash factory")

// errTranscriptOverflow is returned by Transcript.Sum once the accumulated
// handshake bytes have exceeded maxTranscriptBytes (memory-exhaustion guard).
var errTranscriptOverflow = errors.New("tls: handshake transcript exceeded maximum size")

// ParseMessage / message envelope.
var (
	errMsgHeaderTruncated = errors.New("handshake: truncated message header (need 4 bytes)")
	errMsgBodyTruncated   = errors.New("handshake: truncated message body")
	errUnknownMsgType     = errors.New("handshake: unknown message type")
)

// Extension parsing.
var (
	errExtHeaderTruncated = errors.New("handshake: truncated extension header (need 4 bytes)")
	errExtBodyTruncated   = errors.New("handshake: extension body truncated")
	errExtUnknown         = errors.New("handshake: unknown extension")

	errSNITruncatedListLen    = errors.New("handshake: server_name: truncated list length")
	errSNIListLenExceeds      = errors.New("handshake: server_name: list length exceeds available bytes")
	errSNITruncatedEntry      = errors.New("handshake: server_name: truncated name entry")
	errSNINameLenExceeds      = errors.New("handshake: server_name: host_name length exceeds list length")
	errSNIUnsupportedNameType = errors.New(
		"handshake: server_name: unsupported name_type (only host_name=0x00 is supported)",
	)

	errSGTruncatedListLen = errors.New("handshake: supported_groups: truncated list length")
	errSGListLenExceeds   = errors.New("handshake: supported_groups: list length exceeds available bytes")
	errSGOddListLen       = errors.New("handshake: supported_groups: odd list length (must be even)")

	errEPFTruncatedListLen = errors.New("handshake: ec_point_formats: truncated list length")
	errEPFListLenExceeds   = errors.New("handshake: ec_point_formats: list length exceeds available bytes")

	errSATruncatedListLen = errors.New("handshake: signature_algorithms: truncated list length")
	errSAListLenExceeds   = errors.New("handshake: signature_algorithms: list length exceeds available bytes")
	errSAOddListLen       = errors.New("handshake: signature_algorithms: odd list length (must be even)")

	errEMSNonEmptyBody      = errors.New("handshake: extended_master_secret: expected empty body")
	errRITruncatedBody      = errors.New("handshake: renegotiation_info: truncated body")
	errRIDeclaredLenExceeds = errors.New(
		"handshake: renegotiation_info: declared length exceeds available bytes",
	)
	errRINonEmpty = errors.New(
		"handshake: renegotiation_info: non-empty renegotiated_connection; renegotiation is not supported",
	)
	errRITrailingBytes = errors.New(
		"handshake: renegotiation_info: trailing bytes after renegotiated_connection",
	)
)

// Message parsing.
var (
	errCHSessionIDTooLong       = errors.New("handshake: ClientHello session_id length exceeds 32")
	errCHCSOddByteCount         = errors.New("handshake: ClientHello cipher_suites has odd byte count")
	errCHCSAtLeastOne           = errors.New("handshake: ClientHello cipher_suites must have at least one suite")
	errCHCMAtLeastOne           = errors.New("handshake: ClientHello compression_methods must have at least one method")
	errSHSessionIDTooLong       = errors.New("handshake: ServerHello session_id length exceeds 32")
	errCertEntryZeroLen         = errors.New("handshake: Certificate entry has zero length")
	errSHDNonEmptyBody          = errors.New("handshake: ServerHelloDone body must be empty")
	errHelloRequestNonEmptyBody = errors.New("handshake: HelloRequest body must be empty")
	errCRSAOddByteCount         = errors.New(
		"handshake: CertificateRequest supported_signature_algorithms has odd byte count",
	)
	errFinishedVerifyLen = errors.New("handshake: Finished: verify_data length must be 12 or 32")

	errCHTrailingData   = errors.New("handshake: ClientHello: trailing bytes after extensions")
	errSHTrailingData   = errors.New("handshake: ServerHello: trailing bytes after extensions")
	errCertTrailingData = errors.New("handshake: Certificate: trailing bytes after certificate_list")
	// errTrailingHandshakeBytes reports unexpected bytes after a fully-parsed
	// handshake message body (e.g. CertificateRequest).
	errTrailingHandshakeBytes = errors.New("handshake: trailing bytes after message body")
)

// TLS client state machine errors.
var (
	errMalformedCCS          = errors.New("tls: malformed CCS payload")
	errExpectedCCS           = errors.New("tls: expected ChangeCipherSpec")
	errExpectedFinished      = errors.New("tls: expected Finished")
	errFinishedMismatch      = errors.New("tls: server Finished verify_data mismatch")
	errExpectedServerHello   = errors.New("tls: expected ServerHello")
	errBadVersion            = errors.New("tls: server selected wrong version")
	errSuiteNotOffered       = errors.New("tls: server chose cipher suite which was not offered")
	errUnknownSuite          = errors.New("tls: server chose unknown cipher suite")
	errNonNullCompression    = errors.New("tls: server chose non-null compression method")
	errUnexpectedEMS         = errors.New("tls: server sent extended_master_secret extension but we did not offer it")
	errSHUnofferedExt        = errors.New("tls: server sent a ServerHello extension that was not offered")
	errExpectedCertificate   = errors.New("tls: expected Certificate")
	errEmptyCertList         = errors.New("tls: server sent empty certificate list")
	errDuplicateSKE          = errors.New("tls: duplicate ServerKeyExchange in server flight")
	errSKEAfterCertReq       = errors.New("tls: ServerKeyExchange received after CertificateRequest (out of order)")
	errDuplicateCertReq      = errors.New("tls: duplicate CertificateRequest in server flight")
	errUnexpectedFlightMsg   = errors.New("tls: unexpected message type in server flight")
	errSKERequired           = errors.New("tls: ServerKeyExchange required but not received")
	errUnexpectedSKE         = errors.New("tls: unexpected ServerKeyExchange for suite")
	errECDHESKETooShort      = errors.New("tls: ECDHE ServerKeyExchange too short")
	errECDHEUnsupportedCT    = errors.New("tls: ECDHE ServerKeyExchange: unsupported curve_type")
	errECDHEBodyTruncated    = errors.New("tls: ECDHE ServerKeyExchange: body truncated after point")
	errECDHESigSectionShort  = errors.New("tls: ECDHE ServerKeyExchange: signature section too short")
	errECDHESigTruncated     = errors.New("tls: ECDHE ServerKeyExchange: signature truncated")
	errDHESigSectionShort    = errors.New("tls: DHE ServerKeyExchange: signature section too short")
	errDHESigTruncated       = errors.New("tls: DHE ServerKeyExchange: signature truncated")
	errSKEUnadvertisedSigAlg = errors.New("tls: ServerKeyExchange signature algorithm not offered by client")
	errSKESigAuthMismatch    = errors.New(
		"tls: ServerKeyExchange signature algorithm does not match the suite's authentication kind",
	)
	errU16PrefixTruncated    = errors.New("truncated: need 2 bytes for length prefix")
	errU16BodyTruncated      = errors.New("truncated: body too short")
	errCertNotRSA            = errors.New("cert public key is not RSA")
	errCertNotECDSA          = errors.New("cert public key is not ECDSA")
	errUnsupportedSigAlg     = errors.New("unsupported signature algorithm")
	errRSAKeyExpected        = errors.New("tls: RSA key exchange but cert has non-RSA public key")
	errUnknownKXKind         = errors.New("tls: unknown KX kind for suite")
	errUnsupportedHashAlg    = errors.New("unsupported hash algorithm")
	errUnsupportedKeyType    = errors.New("tls: CertificateVerify: unsupported key type")
	errKeyExpansionZero      = errors.New("tls: key expansion total length is zero for suite")
	errHSBodyTruncated       = errors.New("tls: handshake body truncated")
	errAlertRecordTruncated  = errors.New("tls: alert record truncated")
	errAlertReceived         = errors.New("tls: received alert")
	errUnexpectedRecordType  = errors.New("tls: unexpected record type during handshake")
	errInterleavedHandshake  = errors.New("tls: non-handshake record interleaved with a fragmented handshake message")
	errKeyExpansionZeroLocal = errors.New("key expansion total length is zero")
	errECDSATrailingBytes    = errors.New("ecdsa: trailing bytes in signature")
	errECDSAVerifyFailed     = errors.New("ecdsa: signature verification failed")
	errUnsupportedAEAD       = errors.New("unsupported AEAD cipher")
	errUnsupportedMACLen     = errors.New("unsupported MAC length for suite")
	errUnsupportedCBCCipher  = errors.New("unsupported CBC cipher")
)

// Unexpected message type errors (forcetypeassert guard).
var (
	errUnexpectedFinishedType = errors.New("tls: unexpected Finished message type")
	errUnexpectedSHType       = errors.New("tls: unexpected ServerHello message type")
	errUnexpectedCertType     = errors.New("tls: unexpected Certificate message type")
	errUnexpectedSKEType      = errors.New("tls: unexpected ServerKeyExchange type")
	errUnexpectedCertReqType  = errors.New("tls: unexpected CertificateRequest type")
)

// GOST key exchange errors.
var (
	errGOSTNeedGOSTCert     = errors.New("tls: GOST key exchange requires a GOST server certificate")
	errGOSTUnexpectedKXKind = errors.New("tls: unexpected GOST KX kind")
	errGOST2018NeedGOSTCert = errors.New("tls: GOST 2018 key exchange requires a GOST server certificate")
	errGOST2018UnexpectedID = errors.New("tls: GOST 2018 key exchange: unexpected suite ID")
)

// cert_gost.go errors.
var (
	errGOSTRootsWrongType         = errors.New("tls: ClientParams.GOSTRoots has wrong type")
	errGOSTIntermediatesWrongType = errors.New("tls: ClientParams.GOSTIntermediates has wrong type")
)
