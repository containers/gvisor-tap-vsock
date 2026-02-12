package forwarder

import (
	"bufio"
	"encoding/binary"
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrNotTLS is returned when the connection does not appear to be TLS.
	ErrNotTLS = errors.New("not a TLS handshake")
	// ErrNoSNI is returned when a valid TLS ClientHello contains no SNI extension
	// or the SNI hostname is empty.
	ErrNoSNI = errors.New("no SNI extension found")
	// ErrECH is returned when the ClientHello contains an Encrypted Client Hello
	// (or legacy ESNI) extension, meaning the outer SNI cannot be trusted.
	ErrECH = errors.New("encrypted client hello detected")
	// ErrShortRead is returned when the data is too short to parse.
	ErrShortRead = errors.New("short read")
)

const (
	// TLS record and handshake constants
	tlsContentTypeHandshake = 0x16
	tlsHandshakeClientHello = 0x01
	tlsMaxRecordLen         = 16384
	// maxClientHelloLen is the maximum accepted handshake body length.
	// A real ClientHello rarely exceeds a few KB; 65536 is generous.
	// This prevents an attacker from forcing huge Peek calls via a
	// crafted 3-byte length field (which could encode up to 16 MB).
	maxClientHelloLen = 65536

	// TLS extension types
	extServerName           = 0x0000
	extEncryptedClientHello = 0xfe0d
	extLegacyESNI           = 0xffce

	// SNI name types
	sniNameTypeHostName = 0x00
)

// PeekSNI peeks at TLS ClientHello bytes from br without consuming them,
// extracts the SNI hostname. It returns the hostname, the number of bytes
// peeked, and any error. The bufio.Reader is left with all peeked bytes
// available for subsequent reads.
//
// The parser handles ClientHello messages split across multiple TLS records
// (TLS record fragmentation), detects ECH/ESNI extensions, and performs
// bounds checking at every field boundary.
func PeekSNI(br *bufio.Reader) (sni string, peeked int, err error) {
	// Peek at the first byte to check if it looks like TLS.
	hdr, err := br.Peek(1)
	if err != nil || len(hdr) < 1 {
		return "", 0, ErrNotTLS
	}
	if hdr[0] != tlsContentTypeHandshake {
		return "", 1, ErrNotTLS
	}

	// Peek at the first TLS record header (5 bytes).
	hdr, err = br.Peek(5)
	if err != nil || len(hdr) < 5 {
		return "", len(hdr), ErrShortRead
	}

	recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recordLen == 0 || recordLen > tlsMaxRecordLen {
		return "", 5, ErrNotTLS
	}

	// Peek the entire first TLS record.
	totalPeeked := 5 + recordLen
	data, err := br.Peek(totalPeeked)
	if err != nil || len(data) < totalPeeked {
		return "", len(data), ErrShortRead
	}

	// The handshake payload starts at offset 5.
	// We need at least 4 bytes for handshake type (1) + length (3).
	payload := data[5:]
	if len(payload) < 4 {
		return "", totalPeeked, ErrNotTLS
	}

	if payload[0] != tlsHandshakeClientHello {
		return "", totalPeeked, ErrNotTLS
	}

	// Handshake message length (3 bytes, big-endian).
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if hsLen > maxClientHelloLen {
		return "", totalPeeked, ErrNotTLS
	}

	// The handshake message body starts at payload[4:].
	// If hsLen > len(payload)-4, the ClientHello spans multiple TLS records.
	hsBody := payload[4:]

	for len(hsBody) < hsLen {
		// Need more data from subsequent TLS records.
		// Peek the next record header.
		nextHdrEnd := totalPeeked + 5
		data, err = br.Peek(nextHdrEnd)
		if err != nil || len(data) < nextHdrEnd {
			return "", len(data), ErrShortRead
		}

		nextHdr := data[totalPeeked:]
		if nextHdr[0] != tlsContentTypeHandshake {
			return "", nextHdrEnd, ErrNotTLS
		}

		nextRecordLen := int(binary.BigEndian.Uint16(nextHdr[3:5]))
		if nextRecordLen == 0 || nextRecordLen > tlsMaxRecordLen {
			return "", nextHdrEnd, ErrNotTLS
		}

		nextEnd := totalPeeked + 5 + nextRecordLen
		data, err = br.Peek(nextEnd)
		if err != nil || len(data) < nextEnd {
			return "", len(data), ErrShortRead
		}

		// Append the new record's payload to hsBody.
		// We need to reassemble from scratch since Peek returns the full buffer.
		totalPeeked = nextEnd
		hsBody = reassembleHandshake(data)
	}

	// Truncate hsBody to exactly hsLen.
	if len(hsBody) < hsLen {
		return "", totalPeeked, ErrShortRead
	}
	hsBody = hsBody[:hsLen]

	sni, err = parseClientHello(hsBody)
	return sni, totalPeeked, err
}

// reassembleHandshake extracts and concatenates all TLS record payloads from
// the raw peeked data, then skips the 4-byte handshake header to return the
// handshake message body. Only records with content type Handshake (0x16)
// contribute to the assembled payload.
func reassembleHandshake(data []byte) []byte {
	var assembled []byte
	off := 0
	for off+5 <= len(data) {
		if data[off] != tlsContentTypeHandshake {
			break // stop on non-handshake record
		}
		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		payloadStart := off + 5
		payloadEnd := payloadStart + recLen
		if payloadEnd > len(data) {
			payloadEnd = len(data)
		}
		assembled = append(assembled, data[payloadStart:payloadEnd]...)
		off = payloadEnd
	}
	// Skip the 4-byte handshake header (type + length).
	if len(assembled) > 4 {
		return assembled[4:]
	}
	return nil
}

// parseClientHello parses the ClientHello body (after the 4-byte handshake
// header) and extracts the SNI hostname. It returns ErrECH if an ECH or
// legacy ESNI extension is found, and ErrNoSNI if no SNI is present.
func parseClientHello(body []byte) (string, error) {
	off := 0

	// Version (2 bytes).
	if off+2 > len(body) {
		return "", ErrShortRead
	}
	off += 2

	// Random (32 bytes).
	if off+32 > len(body) {
		return "", ErrShortRead
	}
	off += 32

	// Session ID (variable length, 1-byte length prefix).
	if off+1 > len(body) {
		return "", ErrShortRead
	}
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return "", ErrShortRead
	}
	off += sidLen

	// Cipher Suites (variable length, 2-byte length prefix).
	if off+2 > len(body) {
		return "", ErrShortRead
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+csLen > len(body) {
		return "", ErrShortRead
	}
	off += csLen

	// Compression Methods (variable length, 1-byte length prefix).
	if off+1 > len(body) {
		return "", ErrShortRead
	}
	cmLen := int(body[off])
	off++
	if off+cmLen > len(body) {
		return "", ErrShortRead
	}
	off += cmLen

	// Extensions (2-byte total length prefix).
	if off+2 > len(body) {
		// No extensions at all.
		return "", ErrNoSNI
	}
	extsLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extsLen > len(body) {
		return "", ErrShortRead
	}

	extsEnd := off + extsLen
	var foundSNI string
	hasECH := false

	for off+4 <= extsEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extsEnd {
			return "", ErrShortRead
		}
		extData := body[off : off+extLen]

		switch extType {
		case extEncryptedClientHello, extLegacyESNI:
			hasECH = true
		case extServerName:
			if foundSNI == "" {
				name, err := parseSNIExtension(extData)
				if err == nil && name != "" {
					foundSNI = name
				}
			}
		}

		off += extLen
	}

	if hasECH {
		return "", ErrECH
	}
	if foundSNI == "" {
		return "", ErrNoSNI
	}
	return foundSNI, nil
}

// parseSNIExtension parses the server_name extension data and returns the
// first host_name type entry.
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrShortRead
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return "", ErrShortRead
	}

	off := 2
	end := 2 + listLen
	for off+3 <= end {
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if off+nameLen > end {
			return "", ErrShortRead
		}
		if nameType == sniNameTypeHostName {
			hostname := string(data[off : off+nameLen])
			if hostname == "" {
				return "", nil
			}
			// Normalize: strip trailing dot (FQDN form).
			hostname = strings.TrimSuffix(hostname, ".")
			if hostname == "" {
				return "", nil
			}
			// Reject hostnames with invalid characters (null bytes,
			// control chars, non-ASCII). Valid: [a-zA-Z0-9._-]
			if !isValidSNIHostname(hostname) {
				return "", nil
			}
			return hostname, nil
		}
		off += nameLen
	}
	return "", nil
}

// isValidSNIHostname checks that s contains only characters valid in a DNS
// hostname: ASCII letters, digits, hyphens, dots, and underscores. This
// rejects null bytes, control characters, non-ASCII bytes, and other special
// characters that could be used in bypass attacks.
func isValidSNIHostname(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// MatchesAllowlist checks whether the given domain matches at least one of
// the compiled regex patterns. Returns false if the allowlist is empty.
func MatchesAllowlist(domain string, allowlist []*regexp.Regexp) bool {
	for _, re := range allowlist {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}
