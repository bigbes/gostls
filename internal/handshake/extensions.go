package handshake

import (
	"encoding/binary"
	"fmt"
)

// Extension type codes (RFC registry).
const (
	extServerName           uint16 = 0x0000
	extSupportedGroups      uint16 = 0x000A
	extECPointFormats       uint16 = 0x000B
	extSignatureAlgorithms  uint16 = 0x000D
	extExtendedMasterSecret uint16 = 0x0017
	extRenegotiationInfo    uint16 = 0xFF01
)

// Wire encoding widths.
const (
	sizeUint8  = 1 // one byte for uint8 fields.
	sizeUint16 = 2 // two bytes for uint16 fields.
	sizeUint24 = 3 // three bytes for uint24 fields.
	sizeUint32 = 4 // four bytes for uint32 fields.

	// sniMinEntry is the minimum number of bytes per server_name list entry:
	// uint8 name_type + uint16 name_len.
	sniMinEntry = sizeUint8 + sizeUint16

	// extHeaderSize is the minimum extension header: uint16 type + uint16 body_len.
	extHeaderSize = sizeUint16 + sizeUint16

	// sniHostNameType is the RFC 6066 name type for host_name (0x00).
	sniHostNameType = uint8(0x00)

	// pairSize is the number of bytes per (hash, sig) pair in the sig_algs extension.
	pairSize = 2
)

// parsedExtensions holds the decoded content of all recognized extensions.
// Unknown extension types cause an error immediately (fail-fast).
type parsedExtensions struct {
	// server_name (0x0000).
	ServerName string

	// supported_groups (0x000A).
	SupportedGroups []uint16

	// ec_point_formats (0x000B).
	ECPointFormats []uint8

	// signature_algorithms (0x000D).
	SignatureAlgorithms []SigAndHash

	// extended_master_secret (0x0017) — present/absent flag only.
	ExtendedMasterSecret bool

	// renegotiation_info (0xFF01) — empty body only.
	RenegotiationInfo bool
}

// parseExtensions parses the extensions section of a ClientHello or ServerHello body.
// extData is the raw bytes of the extension list (after the 2-byte total-length prefix
// has already been stripped from the outer message).
//
// Any unrecognized extension type returns an error.
func parseExtensions(extData []byte) (parsedExtensions, error) {
	var out parsedExtensions

	for len(extData) > 0 {
		if len(extData) < extHeaderSize {
			return parsedExtensions{}, fmt.Errorf("%w, have %d", errExtHeaderTruncated, len(extData))
		}

		extType := binary.BigEndian.Uint16(extData[:sizeUint16])
		extLen := int(binary.BigEndian.Uint16(extData[sizeUint16:extHeaderSize]))

		extData = extData[extHeaderSize:]

		if len(extData) < extLen {
			return parsedExtensions{}, fmt.Errorf(
				"%w 0x%04x: declared %d bytes, have %d",
				errExtBodyTruncated, extType, extLen, len(extData),
			)
		}

		extBody := extData[:extLen]

		extData = extData[extLen:]

		var err error

		switch extType {
		case extServerName:
			out.ServerName, err = parseServerName(extBody)
		case extSupportedGroups:
			out.SupportedGroups, err = parseSupportedGroups(extBody)
		case extECPointFormats:
			out.ECPointFormats, err = parseECPointFormats(extBody)
		case extSignatureAlgorithms:
			out.SignatureAlgorithms, err = parseSignatureAlgorithms(extBody)
		case extExtendedMasterSecret:
			err = parseExtendedMasterSecret(extBody)
			if err == nil {
				out.ExtendedMasterSecret = true
			}
		case extRenegotiationInfo:
			err = parseRenegotiationInfo(extBody)
			if err == nil {
				out.RenegotiationInfo = true
			}
		default:
			return parsedExtensions{}, fmt.Errorf("%w 0x%04x", errExtUnknown, extType)
		}

		if err != nil {
			return parsedExtensions{}, err
		}
	}

	return out, nil
}

// parseServerName parses the server_name extension body (RFC 6066 §3).
//
// ClientHello format: uint16 list_length; then entries of: uint8 name_type;
// uint16 name_length; name. Only host_name (type 0) is accepted.
//
// ServerHello format (RFC 6066 §3): "extension_data SHALL be empty."
// An empty body returns ("", nil) to signal acknowledgement without a name.
//
// Returns the first (and expected only) host_name value.
func parseServerName(b []byte) (string, error) {
	if len(b) == 0 {
		// Empty ServerHello acknowledgement — valid per RFC 6066 §3.
		return "", nil
	}

	if len(b) < sizeUint16 {
		return "", errSNITruncatedListLen
	}

	listLen := int(binary.BigEndian.Uint16(b[:sizeUint16]))

	b = b[sizeUint16:]

	if len(b) < listLen {
		return "", fmt.Errorf("%w: %d exceeds available %d bytes", errSNIListLenExceeds, listLen, len(b))
	}

	list := b[:listLen]

	var hostName string

	for len(list) > 0 {
		if len(list) < sniMinEntry {
			return "", errSNITruncatedEntry
		}

		nameType := list[0]
		nameLen := int(binary.BigEndian.Uint16(list[sizeUint8:sniMinEntry]))

		list = list[sniMinEntry:]

		if len(list) < nameLen {
			return "", fmt.Errorf("%w: %d exceeds list length %d", errSNINameLenExceeds, nameLen, len(list))
		}

		name := list[:nameLen]

		list = list[nameLen:]

		if nameType != sniHostNameType {
			return "", fmt.Errorf("%w: got 0x%02x", errSNIUnsupportedNameType, nameType)
		}

		hostName = string(name)
	}

	return hostName, nil
}

// marshalServerName encodes the server_name extension body for a single host name.
func marshalServerName(name string) []byte {
	nameBytes := []byte(name)
	// Entry: uint8 name_type + uint16 name_len + name.
	entryLen := sniMinEntry + len(nameBytes)
	out := make([]byte, 0, sizeUint16+entryLen)

	out = appendUint16(out, uint16(entryLen))
	out = appendUint8(out, sniHostNameType) // host_name.
	out = appendUint16(out, uint16(len(nameBytes)))
	out = append(out, nameBytes...)

	return out
}

// parseSupportedGroups parses the supported_groups (elliptic_curves) extension body
// (RFC 8422 §5.1.1). Format: uint16 list_length; uint16 curve_ids[].
func parseSupportedGroups(b []byte) ([]uint16, error) {
	if len(b) < sizeUint16 {
		return nil, errSGTruncatedListLen
	}

	listLen := int(binary.BigEndian.Uint16(b[:sizeUint16]))

	b = b[sizeUint16:]

	if len(b) < listLen {
		return nil, fmt.Errorf("%w: %d exceeds available %d bytes", errSGListLenExceeds, listLen, len(b))
	}

	if listLen%2 != 0 {
		return nil, fmt.Errorf("%w: %d", errSGOddListLen, listLen)
	}

	list := b[:listLen]
	groups := make([]uint16, listLen/pairSize)

	for i := range groups {
		groups[i] = binary.BigEndian.Uint16(list[pairSize*i : pairSize*i+pairSize])
	}

	return groups, nil
}

// marshalSupportedGroups encodes the supported_groups extension body.
func marshalSupportedGroups(groups []uint16) []byte {
	out := make([]byte, 0, sizeUint16+pairSize*len(groups))

	out = appendUint16(out, uint16(pairSize*len(groups)))

	for _, g := range groups {
		out = appendUint16(out, g)
	}

	return out
}

// parseECPointFormats parses the ec_point_formats extension body (RFC 8422 §5.1.2).
// Format: uint8 list_length; uint8 formats[].
func parseECPointFormats(b []byte) ([]uint8, error) {
	if len(b) < 1 {
		return nil, errEPFTruncatedListLen
	}

	listLen := int(b[0])

	b = b[1:]

	if len(b) < listLen {
		return nil, fmt.Errorf("%w: %d exceeds available %d bytes", errEPFListLenExceeds, listLen, len(b))
	}

	return append([]uint8(nil), b[:listLen]...), nil
}

// marshalECPointFormats encodes the ec_point_formats extension body.
func marshalECPointFormats(formats []uint8) []byte {
	out := make([]byte, 0, 1+len(formats))

	out = appendUint8(out, uint8(len(formats)))
	out = append(out, formats...)

	return out
}

// parseSignatureAlgorithms parses the signature_algorithms extension body
// (RFC 5246 §7.4.1.4.1). Format: uint16 list_length; pairs of (hash, sig) uint8.
func parseSignatureAlgorithms(b []byte) ([]SigAndHash, error) {
	if len(b) < sizeUint16 {
		return nil, errSATruncatedListLen
	}

	listLen := int(binary.BigEndian.Uint16(b[:sizeUint16]))

	b = b[sizeUint16:]

	if len(b) < listLen {
		return nil, fmt.Errorf("%w: %d exceeds available %d bytes", errSAListLenExceeds, listLen, len(b))
	}

	if listLen%2 != 0 {
		return nil, fmt.Errorf("%w: %d", errSAOddListLen, listLen)
	}

	list := b[:listLen]
	pairs := make([]SigAndHash, listLen/pairSize)

	for i := range pairs {
		pairs[i] = SigAndHash{Hash: list[pairSize*i], Sig: list[pairSize*i+1]}
	}

	return pairs, nil
}

// marshalSignatureAlgorithms encodes the signature_algorithms extension body.
func marshalSignatureAlgorithms(pairs []SigAndHash) []byte {
	out := make([]byte, 0, sizeUint16+pairSize*len(pairs))

	out = appendUint16(out, uint16(pairSize*len(pairs)))

	for _, p := range pairs {
		out = appendUint8(out, p.Hash)
		out = appendUint8(out, p.Sig)
	}

	return out
}

// parseExtendedMasterSecret parses the extended_master_secret extension body (RFC 7627).
// The extension has an empty body; any non-empty body is rejected.
func parseExtendedMasterSecret(b []byte) error {
	if len(b) != 0 {
		return fmt.Errorf("%w, got %d bytes", errEMSNonEmptyBody, len(b))
	}

	return nil
}

// parseRenegotiationInfo parses the renegotiation_info extension body (RFC 5746).
// Only an empty renegotiated_connection is accepted (length byte == 0).
// Non-empty bodies indicate an active renegotiation, which this implementation
// does not support.
func parseRenegotiationInfo(b []byte) error {
	if len(b) < 1 {
		return errRITruncatedBody
	}

	// The body is: uint8 renegotiated_connection_length + renegotiated_connection.
	riLen := int(b[0])

	b = b[1:]

	if len(b) < riLen {
		return fmt.Errorf("%w: declared %d bytes, have %d", errRIDeclaredLenExceeds, riLen, len(b))
	}

	if riLen != 0 {
		return fmt.Errorf("%w (%d bytes)", errRINonEmpty, riLen)
	}

	return nil
}

// appendExtension appends a single extension (type + uint16 body length + body) to dst.
func appendExtension(dst []byte, extType uint16, body []byte) []byte {
	dst = appendUint16(dst, extType)
	dst = appendUint16(dst, uint16(len(body)))
	dst = append(dst, body...)

	return dst
}

// marshalExtensions serializes the set of recognized extensions into a
// uint16-length-prefixed extension list, in the canonical order:
//
//	server_name, supported_groups, ec_point_formats, signature_algorithms,
//	extended_master_secret (if set), renegotiation_info (if set, last).
//
// Returns nil (no bytes) if no extensions are present.
func marshalExtensions(ext parsedExtensions) []byte {
	var extBytes []byte

	if ext.ServerName != "" {
		extBytes = appendExtension(extBytes, extServerName, marshalServerName(ext.ServerName))
	}

	if len(ext.SupportedGroups) > 0 {
		extBytes = appendExtension(extBytes, extSupportedGroups, marshalSupportedGroups(ext.SupportedGroups))
	}

	if len(ext.ECPointFormats) > 0 {
		extBytes = appendExtension(extBytes, extECPointFormats, marshalECPointFormats(ext.ECPointFormats))
	}

	if len(ext.SignatureAlgorithms) > 0 {
		extBytes = appendExtension(
			extBytes, extSignatureAlgorithms,
			marshalSignatureAlgorithms(ext.SignatureAlgorithms),
		)
	}

	if ext.ExtendedMasterSecret {
		extBytes = appendExtension(extBytes, extExtendedMasterSecret, nil)
	}

	if ext.RenegotiationInfo {
		// Body: uint8(0) — empty renegotiated_connection.
		extBytes = appendExtension(extBytes, extRenegotiationInfo, []byte{0x00})
	}

	if len(extBytes) == 0 {
		return nil
	}

	// Prepend the total extension list length.
	out := make([]byte, 0, sizeUint16+len(extBytes))

	out = appendUint16(out, uint16(len(extBytes)))
	out = append(out, extBytes...)

	return out
}
