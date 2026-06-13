package record

import "fmt"

// Alert levels (RFC 5246 §7.2).
const (
	AlertLevelWarning uint8 = 1
	AlertLevelFatal   uint8 = 2
)

// Alert descriptions (RFC 5246 §7.2).
const (
	AlertCloseNotify          uint8 = 0
	AlertUnexpectedMessage    uint8 = 10
	AlertBadRecordMAC         uint8 = 20
	AlertDecryptionFailed     uint8 = 21
	AlertRecordOverflow       uint8 = 22
	AlertHandshakeFailure     uint8 = 40
	AlertBadCertificate       uint8 = 42
	AlertIllegalParameter     uint8 = 47
	AlertDecodeError          uint8 = 50
	AlertDecryptError         uint8 = 51
	AlertProtocolVersion      uint8 = 70
	AlertUnsupportedExtension uint8 = 110
	AlertInternalError        uint8 = 80
	AlertInsufficientSecurity uint8 = 71
)

// EncodeAlert returns the 2-byte alert body (level || description).
// The caller is responsible for wrapping this in a record with ContentTypeAlert.
func EncodeAlert(level, description uint8) []byte {
	return []byte{level, description}
}

// DecodeAlert parses a 2-byte alert body, returning level and description.
// If the slice is shorter than 2 bytes the values are undefined; callers must
// check length first.
func DecodeAlert(b []byte) (level, description uint8) {
	return b[0], b[1]
}

// AlertError is the error type for a fatal TLS alert.
type AlertError struct {
	Level       uint8
	Description uint8
}

func (e *AlertError) Error() string {
	return fmt.Sprintf("tls: fatal alert %d (level %d)", e.Description, e.Level)
}

// NewFatalAlertError returns an AlertError for a fatal alert with the given
// description code.
func NewFatalAlertError(description uint8) error {
	return &AlertError{Level: AlertLevelFatal, Description: description}
}

// RecordError represents a hard error in the record layer that is not
// necessarily tied to a TLS alert (e.g., sequence number overflow, local
// protocol violations). Fatal indicates whether the connection must be closed.
type RecordError struct {
	Fatal   bool
	Message string
}

func (e *RecordError) Error() string {
	return "tls record: " + e.Message
}

func fatalRecordError(msg string) *RecordError {
	return &RecordError{Fatal: true, Message: msg}
}
