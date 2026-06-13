package handshake

import "fmt"

// hsEnvelopeSize is the size of the handshake message envelope:
// uint8 msg_type + uint24 body_length (RFC 5246 §7.4).
const hsEnvelopeSize = 4

// Type identifies a handshake message type (RFC 5246 §7.4).
type Type uint8

const (
	TypeHelloRequest       Type = 0
	TypeClientHello        Type = 1
	TypeServerHello        Type = 2
	TypeCertificate        Type = 11
	TypeServerKeyExchange  Type = 12
	TypeCertificateRequest Type = 13
	TypeServerHelloDone    Type = 14
	TypeCertificateVerify  Type = 15
	TypeClientKeyExchange  Type = 16
	TypeFinished           Type = 20
)

func (t Type) String() string {
	switch t {
	case TypeHelloRequest:
		return "HelloRequest"
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeCertificate:
		return "Certificate"
	case TypeServerKeyExchange:
		return "ServerKeyExchange"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeServerHelloDone:
		return "ServerHelloDone"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeClientKeyExchange:
		return "ClientKeyExchange"
	case TypeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Type(%d)", int(t))
	}
}

// SigAndHash is the SignatureAndHashAlgorithm struct from RFC 5246 §7.4.1.4.1.
// Hash and Sig are raw byte values from the TLS registry.
type SigAndHash struct {
	Hash uint8
	Sig  uint8
}

// Message is a handshake message that can report its type and marshal its body.
type Message interface {
	// Type returns the handshake message type byte.
	Type() Type
	// Marshal returns the serialized body of the message (without the 4-byte envelope).
	Marshal() []byte
}

// MarshalMessage wraps a Message in the 4-byte handshake envelope:
// uint8 msg_type + uint24 length + body.
// Per RFC 5246 §7.4, this is what goes into the transcript hash.
func MarshalMessage(m Message) []byte {
	body := m.Marshal()
	out := make([]byte, 0, hsEnvelopeSize+len(body))

	out = append(out, byte(m.Type()))
	out = appendUint24(out, uint32(len(body)))
	out = append(out, body...)

	return out
}

// ParseMessage parses a single handshake message from data.
// It returns the parsed Message, any remaining bytes after the message, and an error.
// Returns an error for unknown message types, truncated data, or malformed bodies.
func ParseMessage(data []byte) (Message, []byte, error) {
	if len(data) < hsEnvelopeSize {
		return nil, nil, fmt.Errorf("%w (have %d)", errMsgHeaderTruncated, len(data))
	}

	msgType := Type(data[0])
	bodyLen := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	data = data[hsEnvelopeSize:]

	if uint32(len(data)) < bodyLen {
		return nil, nil, fmt.Errorf("%w: declared %d bytes, have %d", errMsgBodyTruncated, bodyLen, len(data))
	}

	body := data[:bodyLen]
	remaining := data[bodyLen:]

	var (
		msg Message
		err error
	)

	switch msgType {
	case TypeHelloRequest:
		// HelloRequest has an empty body; treat as a no-op message.
		msg, err = &ServerHelloDone{}, nil
	case TypeClientHello:
		msg, err = parseClientHello(body)
	case TypeServerHello:
		msg, err = parseServerHello(body)
	case TypeCertificate:
		msg, err = parseCertificate(body)
	case TypeServerKeyExchange:
		msg = parseServerKeyExchange(body)
	case TypeCertificateRequest:
		msg, err = parseCertificateRequest(body)
	case TypeServerHelloDone:
		msg, err = parseServerHelloDone(body)
	case TypeClientKeyExchange:
		msg = parseClientKeyExchange(body)
	case TypeCertificateVerify:
		msg, err = parseCertificateVerify(body)
	case TypeFinished:
		msg, err = parseFinished(body)
	default:
		return nil, nil, fmt.Errorf("%w %d", errUnknownMsgType, msgType)
	}

	if err != nil {
		return nil, nil, err
	}

	return msg, remaining, nil
}

// RawMessage allows constructing arbitrary wire-format messages for testing.
// It uses a pre-built body and a specified type. Used in tests to inject
// malformed extension data without going through the high-level constructors.
type RawMessage struct {
	MsgType Type
	Body    []byte
}

func (r *RawMessage) Type() Type      { return r.MsgType }
func (r *RawMessage) Marshal() []byte { return r.Body }
