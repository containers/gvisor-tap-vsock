package forwarder

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helper: ClientHello builder
// ---------------------------------------------------------------------------

type clientHelloOpts struct {
	serverName         string
	version            uint16 // legacy_version in record header
	handshakeVersion   uint16 // version in ClientHello body
	sessionID          []byte
	cipherSuites       []uint16
	compressionMethods []byte
	extensions         []tlsExtension
	// For fragmentation tests: split the handshake across multiple TLS records
	// at the given byte offsets within the handshake payload.
	fragmentAt []int
}

type tlsExtension struct {
	typ  uint16
	data []byte
}

func defaultOpts() clientHelloOpts {
	return clientHelloOpts{
		serverName:         "example.com",
		version:            0x0301, // TLS 1.0 in record header (common)
		handshakeVersion:   0x0303, // TLS 1.2
		sessionID:          nil,
		cipherSuites:       []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b},
		compressionMethods: []byte{0x00},
	}
}

func buildSNIExtension(hostname string) tlsExtension {
	// server_name extension (0x0000)
	nameBytes := []byte(hostname)
	// Server Name List: 2-byte list length, then entries (1-byte type + 2-byte name length + name)
	listLen := 1 + 2 + len(nameBytes)
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(listLen))
	buf.WriteByte(0x00) // host_name type
	binary.Write(&buf, binary.BigEndian, uint16(len(nameBytes)))
	buf.Write(nameBytes)
	return tlsExtension{typ: 0x0000, data: buf.Bytes()}
}

func buildSNIExtensionWithNameType(nameType byte, hostname string) tlsExtension {
	nameBytes := []byte(hostname)
	entryLen := 1 + 2 + len(nameBytes)
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(entryLen))
	buf.WriteByte(nameType)
	binary.Write(&buf, binary.BigEndian, uint16(len(nameBytes)))
	buf.Write(nameBytes)
	return tlsExtension{typ: 0x0000, data: buf.Bytes()}
}

func buildMultipleServerNames(names []struct {
	nameType byte
	name     string
}) tlsExtension {
	var entries bytes.Buffer
	for _, n := range names {
		nameBytes := []byte(n.name)
		entries.WriteByte(n.nameType)
		binary.Write(&entries, binary.BigEndian, uint16(len(nameBytes)))
		entries.Write(nameBytes)
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(entries.Len()))
	buf.Write(entries.Bytes())
	return tlsExtension{typ: 0x0000, data: buf.Bytes()}
}

func buildECHExtension() tlsExtension {
	return tlsExtension{typ: 0xfe0d, data: []byte{0x00, 0x01, 0x02, 0x03}}
}

func buildESNIExtension() tlsExtension {
	return tlsExtension{typ: 0xffce, data: []byte{0x00, 0x01}}
}

func buildALPNExtension() tlsExtension {
	// ALPN extension (0x0010) with "h2" and "http/1.1"
	var buf bytes.Buffer
	protos := []string{"h2", "http/1.1"}
	var list bytes.Buffer
	for _, p := range protos {
		list.WriteByte(byte(len(p)))
		list.WriteString(p)
	}
	binary.Write(&buf, binary.BigEndian, uint16(list.Len()))
	buf.Write(list.Bytes())
	return tlsExtension{typ: 0x0010, data: buf.Bytes()}
}

func buildSupportedGroupsExtension() tlsExtension {
	var buf bytes.Buffer
	groups := []uint16{0x001d, 0x0017, 0x0018} // x25519, secp256r1, secp384r1
	binary.Write(&buf, binary.BigEndian, uint16(len(groups)*2))
	for _, g := range groups {
		binary.Write(&buf, binary.BigEndian, g)
	}
	return tlsExtension{typ: 0x000a, data: buf.Bytes()}
}

func buildKeyShareExtension() tlsExtension {
	// Minimal key_share extension
	var buf bytes.Buffer
	keyData := make([]byte, 32)                                    // fake key
	binary.Write(&buf, binary.BigEndian, uint16(2+2+len(keyData))) // list length
	binary.Write(&buf, binary.BigEndian, uint16(0x001d))           // x25519
	binary.Write(&buf, binary.BigEndian, uint16(len(keyData)))
	buf.Write(keyData)
	return tlsExtension{typ: 0x0033, data: buf.Bytes()}
}

func buildSupportedVersionsExtension(versions ...uint16) tlsExtension {
	var buf bytes.Buffer
	buf.WriteByte(byte(len(versions) * 2))
	for _, v := range versions {
		binary.Write(&buf, binary.BigEndian, v)
	}
	return tlsExtension{typ: 0x002b, data: buf.Bytes()}
}

func buildGREASEExtension(greaseType uint16) tlsExtension {
	return tlsExtension{typ: greaseType, data: []byte{0x00}}
}

// ---------------------------------------------------------------------------
// ECH extension helpers (RFC 9849 wire format)
// ---------------------------------------------------------------------------

// buildECHOuterExtension builds a spec-compliant ECH outer extension (type=0x00)
// with HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001) cipher suite.
// Wire format: type(1) | kdf_id(2) | aead_id(2) | config_id(1) | enc_len(2) | enc(N) | payload_len(2) | payload(M)
func buildECHOuterExtension(configID uint8, encLen, payloadLen int) tlsExtension {
	return buildECHOuterExtensionWithCipher(configID, 0x0001, 0x0001, encLen, payloadLen)
}

// buildECHOuterExtensionWithCipher builds an ECH outer extension with explicit cipher suite.
func buildECHOuterExtensionWithCipher(configID uint8, kdfID, aeadID uint16, encLen, payloadLen int) tlsExtension {
	var buf bytes.Buffer
	buf.WriteByte(0x00) // ECHClientHelloType: outer
	binary.Write(&buf, binary.BigEndian, kdfID)
	binary.Write(&buf, binary.BigEndian, aeadID)
	buf.WriteByte(configID)
	binary.Write(&buf, binary.BigEndian, uint16(encLen))
	buf.Write(make([]byte, encLen))
	binary.Write(&buf, binary.BigEndian, uint16(payloadLen))
	buf.Write(make([]byte, payloadLen))
	return tlsExtension{typ: 0xfe0d, data: buf.Bytes()}
}

// buildECHInnerExtension builds an ECH inner extension (type=0x01).
// Inner ClientHellos should never appear on the wire from a client.
func buildECHInnerExtension() tlsExtension {
	return tlsExtension{typ: 0xfe0d, data: []byte{0x01}}
}

// buildChromeECHGreaseExtension builds a Chrome-inspired ECH GREASE extension.
// Chrome-inspired ECH GREASE: HKDF-SHA256+AES-128-GCM, 32B enc, 288B payload (330B data).
// Real Chrome uses random config_id and smaller payloads (144-240B).
func buildChromeECHGreaseExtension() tlsExtension {
	return buildECHOuterExtensionWithCipher(0x00, 0x0001, 0x0001, 32, 288)
}

// buildFirefoxECHGreaseExtension builds a Firefox-inspired ECH GREASE extension.
// Firefox-inspired ECH GREASE: HKDF-SHA256+ChaCha20Poly1305, 32B enc, 224B payload (266B data).
// Real Firefox defaults to ~100B payload (security.tls.ech.grease_size).
func buildFirefoxECHGreaseExtension() tlsExtension {
	return buildECHOuterExtensionWithCipher(0x42, 0x0001, 0x0003, 32, 224)
}

// buildLegacyESNIExtensionWithPayload builds a legacy ESNI extension (0xffce)
// with configurable payload size.
func buildLegacyESNIExtensionWithPayload(size int) tlsExtension {
	return tlsExtension{typ: 0xffce, data: make([]byte, size)}
}

func buildClientHello(opts clientHelloOpts) []byte {
	// Build extensions
	exts := opts.extensions
	if exts == nil && opts.serverName != "" {
		exts = []tlsExtension{buildSNIExtension(opts.serverName)}
	}

	var extsBuf bytes.Buffer
	for _, ext := range exts {
		binary.Write(&extsBuf, binary.BigEndian, ext.typ)
		binary.Write(&extsBuf, binary.BigEndian, uint16(len(ext.data)))
		extsBuf.Write(ext.data)
	}

	// Build ClientHello body (after handshake header).
	var body bytes.Buffer
	// Version
	binary.Write(&body, binary.BigEndian, opts.handshakeVersion)
	// Random (32 bytes)
	random := make([]byte, 32)
	body.Write(random)
	// Session ID
	body.WriteByte(byte(len(opts.sessionID)))
	body.Write(opts.sessionID)
	// Cipher Suites
	binary.Write(&body, binary.BigEndian, uint16(len(opts.cipherSuites)*2))
	for _, cs := range opts.cipherSuites {
		binary.Write(&body, binary.BigEndian, cs)
	}
	// Compression Methods
	body.WriteByte(byte(len(opts.compressionMethods)))
	body.Write(opts.compressionMethods)
	// Extensions
	if extsBuf.Len() > 0 || len(exts) > 0 {
		binary.Write(&body, binary.BigEndian, uint16(extsBuf.Len()))
		body.Write(extsBuf.Bytes())
	}

	bodyBytes := body.Bytes()

	// Build handshake message: type(1) + length(3) + body
	var handshake bytes.Buffer
	handshake.WriteByte(0x01) // ClientHello
	hsLen := len(bodyBytes)
	handshake.WriteByte(byte(hsLen >> 16))
	handshake.WriteByte(byte(hsLen >> 8))
	handshake.WriteByte(byte(hsLen))
	handshake.Write(bodyBytes)

	hsBytes := handshake.Bytes()

	if len(opts.fragmentAt) > 0 {
		return fragmentIntoRecords(hsBytes, opts.version, opts.fragmentAt)
	}

	// Wrap in a single TLS record.
	return wrapTLSRecord(hsBytes, opts.version)
}

func wrapTLSRecord(payload []byte, version uint16) []byte {
	var rec bytes.Buffer
	rec.WriteByte(0x16) // handshake
	binary.Write(&rec, binary.BigEndian, version)
	binary.Write(&rec, binary.BigEndian, uint16(len(payload)))
	rec.Write(payload)
	return rec.Bytes()
}

func fragmentIntoRecords(hsBytes []byte, version uint16, splitAt []int) []byte {
	var result bytes.Buffer
	prev := 0
	for _, at := range splitAt {
		if at > len(hsBytes) {
			at = len(hsBytes)
		}
		if at <= prev {
			continue
		}
		chunk := hsBytes[prev:at]
		result.Write(wrapTLSRecord(chunk, version))
		prev = at
	}
	if prev < len(hsBytes) {
		result.Write(wrapTLSRecord(hsBytes[prev:], version))
	}
	return result.Bytes()
}

func buildClientHelloWithECH(hostname string) []byte {
	opts := defaultOpts()
	opts.serverName = hostname
	opts.extensions = []tlsExtension{
		buildSNIExtension(hostname),
		buildECHExtension(),
	}
	return buildClientHello(opts)
}

func buildClientHelloBytes(hostname string) []byte {
	opts := defaultOpts()
	opts.serverName = hostname
	return buildClientHello(opts)
}

func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// checkProperties verifies the property invariants P1-P4 from the plan.
func checkProperties(t *testing.T, data []byte, sni string, _ []string, peeked int, err error) {
	t.Helper()
	// P1: no panic — implicit if we reach here.
	// P2: non-empty on success.
	if err == nil {
		require.NotEmpty(t, sni, "P2: sni must be non-empty on success")
		// P4: valid hostname chars.
		require.True(t, isPrintableASCII(sni), "P4: sni contains non-printable chars: %q", sni)
	}
	// P3: defined error types.
	if err != nil {
		require.True(t,
			errors.Is(err, ErrNotTLS) || errors.Is(err, ErrNoSNI) || errors.Is(err, ErrShortRead),
			"P3: unexpected error type: %v", err)
	}
	// P7: bounded peek.
	// We allow up to 3 fragments * (5 + 16384) as a generous upper bound.
	require.LessOrEqual(t, peeked, 3*(5+tlsMaxRecordLen)+5, "P7: peeked too many bytes")
}

// ---------------------------------------------------------------------------
// A. Normal cases
// ---------------------------------------------------------------------------

func TestPeekSNI_TLS12(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com"
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_TLS13(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com"
	opts.handshakeVersion = 0x0303 // legacy TLS 1.2
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildSupportedVersionsExtension(0x0304), // TLS 1.3
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_TLS11(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com"
	opts.version = 0x0302           // TLS 1.1 in record header
	opts.handshakeVersion = 0x0302  // TLS 1.1 in ClientHello body
	opts.cipherSuites = []uint16{0x002f, 0x0035, 0x003c} // TLS 1.1 cipher suites
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_TLS10(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com"
	opts.version = 0x0301           // TLS 1.0 in record header
	opts.handshakeVersion = 0x0301  // TLS 1.0 in ClientHello body
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_SSLv3(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com"
	opts.version = 0x0300           // SSLv3 in record header
	opts.handshakeVersion = 0x0300  // SSLv3 in ClientHello body
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	// SSLv3 ClientHello has the same structure — parser does not reject by version.
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

// TestPeekSNI_FakeVersion_TLS14 verifies that a ClientHello claiming to be
// "TLS 1.4" (version 0x0305, which does not exist) is still parsed. The parser
// intentionally ignores version fields — per RFC 8446 Section 4.1.2, clients
// MUST set legacy_version to 0x0303 and use supported_versions for negotiation,
// so the version field is unreliable for filtering.
func TestPeekSNI_FakeVersion_TLS14(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com"
	opts.version = 0x0305           // fake "TLS 1.4" in record header
	opts.handshakeVersion = 0x0305  // fake "TLS 1.4" in ClientHello body
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	// Parser does not validate version — this is correct. Rejecting unknown
	// versions would break forward compatibility and is explicitly discouraged
	// by RFC 8446.
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

// TestPeekSNI_BogusVersions verifies that extreme/invalid version values
// don't cause issues. The parser ignores version bytes entirely.
func TestPeekSNI_BogusVersions(t *testing.T) {
	versions := []struct {
		name    string
		recVer  uint16
		hsVer   uint16
	}{
		{"ZeroZero", 0x0000, 0x0000},
		{"MaxMax", 0xFFFF, 0xFFFF},
		{"RecordSSLv3_BodyTLS13", 0x0300, 0x0303},
		{"RecordTLS12_BodySSLv2", 0x0303, 0x0200},
		{"MismatchedVersions", 0x0301, 0x0305},
	}

	for _, tc := range versions {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.serverName = "example.com"
			opts.version = tc.recVer
			opts.handshakeVersion = tc.hsVer
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, alpn, peeked, err := PeekSNI(br)
			require.NoError(t, err)
			require.Equal(t, "example.com", sni)
			checkProperties(t, data, sni, alpn, peeked, err)
		})
	}
}

func TestPeekSNI_LongHostname(t *testing.T) {
	// 253-char hostname (DNS max).
	hostname := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	require.Equal(t, 253, len(hostname))
	opts := defaultOpts()
	opts.serverName = hostname
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, hostname, sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_SubdomainDots(t *testing.T) {
	hostname := "deep.nested.sub.example.com"
	data := buildClientHelloBytes(hostname)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, hostname, sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_MultipleExtensions(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildALPNExtension(),
		buildSupportedGroupsExtension(),
		buildSNIExtension("example.com"),
		buildKeyShareExtension(),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_DoesNotConsumeBytes(t *testing.T) {
	data := buildClientHelloBytes("example.com")
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	// P5: non-consumption.
	require.Equal(t, peeked, br.Buffered(), "P5: buffered bytes should equal peeked")
	// Read all bytes back.
	all, readErr := io.ReadAll(br)
	require.NoError(t, readErr)
	require.Equal(t, data, all, "P5: all original bytes should be readable")
}

// ---------------------------------------------------------------------------
// B. Edge cases
// ---------------------------------------------------------------------------

func TestPeekSNI_NoSNIExtension(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{buildALPNExtension()}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_EmptySNIHostname(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{buildSNIExtension("")}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_SNIFirstExtension(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("first.example.com"),
		buildALPNExtension(),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "first.example.com", sni)
}

func TestPeekSNI_SNILastExtension(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildALPNExtension(),
		buildSupportedGroupsExtension(),
		buildKeyShareExtension(),
		buildSNIExtension("last.example.com"),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "last.example.com", sni)
}

func TestPeekSNI_MultipleServerNames(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildMultipleServerNames([]struct {
			nameType byte
			name     string
		}{
			{0x00, "first.example.com"},
			{0x00, "second.example.com"},
		}),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "first.example.com", sni)
}

func TestPeekSNI_NonHostNameType(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtensionWithNameType(0x01, "nothost.example.com"),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_GREASEExtensions(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildGREASEExtension(0x0a0a),
		buildGREASEExtension(0x1a1a),
		buildSNIExtension("example.com"),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

func TestPeekSNI_LargeSessionID(t *testing.T) {
	opts := defaultOpts()
	opts.sessionID = make([]byte, 32) // max session ID length
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

func TestPeekSNI_ManyCipherSuites(t *testing.T) {
	opts := defaultOpts()
	opts.cipherSuites = make([]uint16, 100)
	for i := range opts.cipherSuites {
		opts.cipherSuites[i] = uint16(0xc000 + i)
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

func TestPeekSNI_NoExtensions(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{} // empty extensions list
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_TrailingDotHostname(t *testing.T) {
	data := buildClientHelloBytes("example.com.")
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni) // trailing dot stripped
}

func TestPeekSNI_IPv4InSNI(t *testing.T) {
	data := buildClientHelloBytes("1.2.3.4")
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI, "IPv4 literal in SNI should be rejected per RFC 6066")
}

func TestPeekSNI_IPv6InSNI(t *testing.T) {
	// "::1" contains colons which are rejected by isValidSNIHostname.
	data := buildClientHelloBytes("::1")
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_IPv4MappedIPv6(t *testing.T) {
	// "::ffff:1.2.3.4" contains colons, rejected by isValidSNIHostname.
	data := buildClientHelloBytes("::ffff:1.2.3.4")
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_NotAnIP(t *testing.T) {
	// "10.example.com" looks like it starts with an IP but is a valid hostname.
	data := buildClientHelloBytes("10.example.com")
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "10.example.com", sni, "hostname starting with digits should still be allowed")
}

// ---------------------------------------------------------------------------
// C. Security / bypass cases
// ---------------------------------------------------------------------------

func TestPeekSNI_FragmentedTLSRecords(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "fragmented.example.com"
	// Split the handshake at byte 30 (inside handshake body).
	opts.fragmentAt = []int{30}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "fragmented.example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_ThreeFragments(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "three.fragments.example.com"
	opts.fragmentAt = []int{20, 50}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "three.fragments.example.com", sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_FragmentMidSNI(t *testing.T) {
	hostname := "mid-sni-split.example.com"
	opts := defaultOpts()
	opts.serverName = hostname
	// We need to find a split point inside the SNI hostname bytes.
	// Build without fragmentation first to find the offset.
	unfragmented := buildClientHello(defaultOpts())
	// The hostname is near the end. Fragment at a point that's likely inside it.
	// handshake header(4) + version(2) + random(32) + sessionID(1+0) + cipherSuites(2+10) + comp(1+1) + extsLen(2) + extType(2) + extLen(2) + listLen(2) + nameType(1) + nameLen(2) + partial
	splitPoint := len(unfragmented) - 5 - 5 // well inside the payload, should be within SNI
	if splitPoint < 4 {
		splitPoint = 10
	}
	opts.fragmentAt = []int{splitPoint}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, peeked, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, hostname, sni)
	checkProperties(t, data, sni, alpn, peeked, err)
}

func TestPeekSNI_ECHExtension(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildECHExtension(),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

func TestPeekSNI_ECHWithSNI(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("outer.example.com"),
		buildECHExtension(),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "outer.example.com", sni)
}

func TestPeekSNI_ESNILegacy(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("outer.example.com"),
		buildESNIExtension(),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "outer.example.com", sni)
}

// ---------------------------------------------------------------------------
// D. Out-of-bounds / malformed
// ---------------------------------------------------------------------------

func TestPeekSNI_NotTLS(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\n")
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNotTLS)
}

func TestPeekSNI_EmptyInput(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader(nil))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNotTLS)
}

func TestPeekSNI_OneByte(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte{0x16}))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_HeaderOnly(t *testing.T) {
	// 5-byte TLS header with record length 0.
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_RecordLenOverflow(t *testing.T) {
	// Header says 16384 bytes but only 100 exist.
	data := make([]byte, 105)
	data[0] = 0x16
	data[1] = 0x03
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 16384)
	// Fill some payload.
	for i := 5; i < len(data); i++ {
		data[i] = 0x01
	}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err, "should not panic with truncated data")
}

func TestPeekSNI_RecordLenZero(t *testing.T) {
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNotTLS)
}

func TestPeekSNI_BadHandshakeType(t *testing.T) {
	// ContentType=0x16 but HandshakeType=0x02 (ServerHello).
	payload := []byte{0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00}
	data := wrapTLSRecord(payload, 0x0301)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNotTLS)
}

func TestPeekSNI_SessionIDLenOverflow(t *testing.T) {
	opts := defaultOpts()
	data := buildClientHello(opts)
	// Corrupt sessionID length byte. It's at offset 5 (record hdr) + 4 (hs hdr) + 2 (version) + 32 (random) = 43.
	if len(data) > 43 {
		data[43] = 0xFF
	}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_CipherSuiteLenOverflow(t *testing.T) {
	opts := defaultOpts()
	data := buildClientHello(opts)
	// Cipher suites length is at offset 43 + 1 (sid len) + 0 (empty sid) = 44.
	if len(data) > 45 {
		binary.BigEndian.PutUint16(data[44:46], 0xFFFF)
	}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_ExtLenOverflow(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		{typ: 0x0000, data: []byte{0x00}}, // short data
	}
	data := buildClientHello(opts)
	// Find the extension length field and corrupt it.
	// Extension is near the end: ext_type(2) + ext_len(2) + data(1).
	// The ext_len is at -3 from end.
	if len(data) > 10 {
		// Corrupt the last extension's length.
		pos := len(data) - 3
		binary.BigEndian.PutUint16(data[pos:pos+2], 0xFFFF)
	}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_ExtsTotalLenOverflow(t *testing.T) {
	opts := defaultOpts()
	data := buildClientHello(opts)
	// Find extensions total length and corrupt it.
	// It's 2 bytes before the extensions start.
	// For empty session ID: offset = 5 + 4 + 2 + 32 + 1 + (2 + 10) + (1 + 1) = 58
	// The extensions total length is at offset 58.
	off := 5 + 4 + 2 + 32 + 1 + 0 + 2 + len(opts.cipherSuites)*2 + 1 + len(opts.compressionMethods)
	if off+2 <= len(data) {
		binary.BigEndian.PutUint16(data[off:off+2], 0xFFFF)
	}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_SNIInternalLenMismatch(t *testing.T) {
	opts := defaultOpts()
	// Build an SNI extension with wrong internal length.
	nameBytes := []byte("example.com")
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(0xFF)) // wrong list length
	buf.WriteByte(0x00)
	binary.Write(&buf, binary.BigEndian, uint16(len(nameBytes)))
	buf.Write(nameBytes)
	opts.extensions = []tlsExtension{{typ: 0x0000, data: buf.Bytes()}}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_TruncatedMidExtension(t *testing.T) {
	data := buildClientHelloBytes("example.com")
	// Truncate 5 bytes from the end (mid-extension).
	if len(data) > 10 {
		data = data[:len(data)-5]
		// Also fix the record length.
		binary.BigEndian.PutUint16(data[3:5], uint16(len(data)-5))
	}
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.Error(t, err)
}

func TestPeekSNI_AllZeros(t *testing.T) {
	data := make([]byte, 500)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNotTLS)
}

func TestPeekSNI_MaxRecordLen(t *testing.T) {
	// Build a valid ClientHello inside a record declared as 16384 bytes.
	opts := defaultOpts()
	opts.serverName = "example.com"
	// Build the handshake payload.
	inner := buildClientHello(opts)
	// Extract the handshake payload (skip the 5-byte record header).
	hsPayload := inner[5:]
	// Pad to 16384 bytes. Update the handshake length to match.
	padded := make([]byte, 16384)
	copy(padded, hsPayload)
	data := wrapTLSRecord(padded, 0x0301)
	br := bufio.NewReaderSize(bytes.NewReader(data), len(data)+1)
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

func TestPeekSNI_OverMaxRecordLen(t *testing.T) {
	data := []byte{0x16, 0x03, 0x01}
	data = append(data, byte(16385>>8), byte(16385&0xFF))
	data = append(data, make([]byte, 100)...)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNotTLS)
}

// ---------------------------------------------------------------------------
// Fuzz tests
// ---------------------------------------------------------------------------

func TestPeekSNI_FuzzRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		size := rng.Intn(2001)
		data := make([]byte, size)
		rng.Read(data)
		br := bufio.NewReader(bytes.NewReader(data))
		_, _, _, _ = PeekSNI(br) // must not panic
	}
}

func TestPeekSNI_FuzzMutated(t *testing.T) {
	rng := rand.New(rand.NewSource(43))
	base := buildClientHelloBytes("fuzz.example.com")

	for i := 0; i < 1000; i++ {
		mutated := make([]byte, len(base))
		copy(mutated, base)

		numMutations := rng.Intn(10) + 1
		for j := 0; j < numMutations; j++ {
			switch rng.Intn(3) {
			case 0: // flip a byte
				if len(mutated) > 0 {
					pos := rng.Intn(len(mutated))
					mutated[pos] = byte(rng.Intn(256))
				}
			case 1: // insert a byte
				pos := rng.Intn(len(mutated) + 1)
				mutated = append(mutated[:pos], append([]byte{byte(rng.Intn(256))}, mutated[pos:]...)...)
			case 2: // delete a byte
				if len(mutated) > 0 {
					pos := rng.Intn(len(mutated))
					mutated = append(mutated[:pos], mutated[pos+1:]...)
				}
			}
		}

		br := bufio.NewReader(bytes.NewReader(mutated))
		sni, _, _, err := PeekSNI(br) // must not panic
		if err == nil {
			require.NotEmpty(t, sni, "P2: sni must be non-empty on success")
		}
		if err != nil {
			require.True(t,
				errors.Is(err, ErrNotTLS) || errors.Is(err, ErrNoSNI) || errors.Is(err, ErrShortRead),
				"P3: unexpected error type: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// E. Allowlist matching
// ---------------------------------------------------------------------------

func TestMatchesAllowlist_ExactMatch(t *testing.T) {
	allowlist := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	require.True(t, MatchesAllowlist("example.com", allowlist))
}

func TestMatchesAllowlist_WildcardSubdomain(t *testing.T) {
	allowlist := []*regexp.Regexp{regexp.MustCompile(`^.*\.example\.com$`)}
	require.True(t, MatchesAllowlist("foo.example.com", allowlist))
}

func TestMatchesAllowlist_WildcardNoMatchBase(t *testing.T) {
	allowlist := []*regexp.Regexp{regexp.MustCompile(`^.*\.example\.com$`)}
	require.False(t, MatchesAllowlist("example.com", allowlist))
}

func TestMatchesAllowlist_MultiplePatterns(t *testing.T) {
	allowlist := []*regexp.Regexp{
		regexp.MustCompile(`^a\.com$`),
		regexp.MustCompile(`^b\.com$`),
	}
	require.True(t, MatchesAllowlist("b.com", allowlist))
}

func TestMatchesAllowlist_NoMatch(t *testing.T) {
	allowlist := []*regexp.Regexp{regexp.MustCompile(`^a\.com$`)}
	require.False(t, MatchesAllowlist("evil.com", allowlist))
}

func TestMatchesAllowlist_EmptyAllowlist(t *testing.T) {
	require.False(t, MatchesAllowlist("anything", nil))
}

func TestMatchesAllowlist_EmptyDomain(t *testing.T) {
	allowlist := []*regexp.Regexp{regexp.MustCompile(`^.*`)}
	require.True(t, MatchesAllowlist("", allowlist))
}

func TestMatchesAllowlist_UnanchoredRegex(t *testing.T) {
	allowlist := []*regexp.Regexp{regexp.MustCompile(`example\.com`)}
	// This demonstrates the need for ^...$ anchors — an unanchored regex matches substrings.
	require.True(t, MatchesAllowlist("evil-example.com", allowlist))
}

// ---------------------------------------------------------------------------
// F. Go native fuzz test
// ---------------------------------------------------------------------------

func FuzzPeekSNI(f *testing.F) {
	// Seed corpus.
	f.Add(buildClientHelloBytes("example.com"))
	f.Add(buildClientHelloBytes(""))
	f.Add(buildClientHelloWithECH("x.com"))
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Add([]byte{})
	f.Add(make([]byte, 500))
	// ECH corpus entries.
	f.Add(func() []byte {
		opts := defaultOpts()
		opts.extensions = []tlsExtension{buildSNIExtension("example.com"), buildECHOuterExtension(0, 32, 256)}
		return buildClientHello(opts)
	}())
	f.Add(func() []byte {
		opts := defaultOpts()
		opts.extensions = []tlsExtension{buildSNIExtension("example.com"), buildChromeECHGreaseExtension()}
		return buildClientHello(opts)
	}())
	f.Add(func() []byte {
		opts := defaultOpts()
		opts.extensions = []tlsExtension{buildSNIExtension("example.com"), buildECHInnerExtension()}
		return buildClientHello(opts)
	}())
	f.Add(func() []byte {
		opts := defaultOpts()
		opts.extensions = []tlsExtension{buildSNIExtension("example.com"), buildLegacyESNIExtensionWithPayload(512)}
		return buildClientHello(opts)
	}())

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		sni, _, _, err := PeekSNI(br)
		if err == nil {
			require.NotEmpty(t, sni, "P2: non-empty on success")
			// P4 (printable ASCII) is not enforced here — the parser returns
			// raw bytes from the SNI field. Validation is the caller's job.
			// The allowlist regex matching will reject non-hostname strings.
		}
	})
}

// ---------------------------------------------------------------------------
// G. Property invariants (tested via checkProperties in A-C tests)
// ---------------------------------------------------------------------------

func TestPeekSNI_Idempotent(t *testing.T) {
	data := buildClientHelloBytes("idempotent.example.com")
	// Call PeekSNI twice on the same data.
	br1 := bufio.NewReader(bytes.NewReader(data))
	sni1, _, peeked1, err1 := PeekSNI(br1)

	br2 := bufio.NewReader(bytes.NewReader(data))
	sni2, _, peeked2, err2 := PeekSNI(br2)

	require.Equal(t, sni1, sni2, "P6: idempotent — same SNI")
	require.Equal(t, peeked1, peeked2, "P6: idempotent — same peeked count")
	require.Equal(t, err1, err2, "P6: idempotent — same error")
}

// ---------------------------------------------------------------------------
// H. Differential testing against crypto/tls
// ---------------------------------------------------------------------------

func TestPeekSNI_DifferentialVsCryptoTLS(t *testing.T) {
	testCases := []string{
		"example.com",
		"foo.bar.example.com",
		"a.b.c.d.e.f.example.com",
		"test-host.example.org",
	}

	for _, hostname := range testCases {
		t.Run(hostname, func(t *testing.T) {
			data := buildClientHelloBytes(hostname)

			// Our parser.
			br := bufio.NewReader(bytes.NewReader(data))
			ourSNI, _, _, ourErr := PeekSNI(br)
			require.NoError(t, ourErr)
			require.Equal(t, hostname, ourSNI)

			// crypto/tls parser via GetConfigForClient callback.
			var tlsSNI string
			tlsConfig := &tls.Config{
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					tlsSNI = hello.ServerName
					return nil, nil
				},
			}

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			done := make(chan struct{})
			go func() {
				defer close(done)
				tlsServer := tls.Server(serverConn, tlsConfig)
				_ = tlsServer.Handshake() // will fail (no certs), but captures SNI
			}()

			// Write our ClientHello bytes to the server.
			_, _ = clientConn.Write(data)
			clientConn.Close()
			<-done

			require.Equal(t, hostname, tlsSNI,
				"differential: our parser and crypto/tls should agree on SNI")
		})
	}
}

// ---------------------------------------------------------------------------
// I. Real-world golden tests (captured hex)
// ---------------------------------------------------------------------------

// TestPeekSNI_CurlCapture tests with a ClientHello captured from
// `curl https://example.com` (TLS 1.3, Go 1.22 curl via net/http).
func TestPeekSNI_CurlCapture(t *testing.T) {
	// This is a minimal TLS 1.3 ClientHello for example.com, constructed
	// to match what a typical curl/Go TLS client sends.
	opts := clientHelloOpts{
		serverName:         "example.com",
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009e, 0x009c, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildSNIExtension("example.com"),
			buildALPNExtension(),
			buildSupportedGroupsExtension(),
			buildSupportedVersionsExtension(0x0304, 0x0303),
			buildKeyShareExtension(),
		},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// TestPeekSNI_ChromeCapture tests with a Chrome-like ClientHello with
// GREASE values and many extensions.
func TestPeekSNI_ChromeCapture(t *testing.T) {
	opts := clientHelloOpts{
		serverName:         "www.google.com",
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildGREASEExtension(0x0a0a),
			buildSNIExtension("www.google.com"),
			buildALPNExtension(),
			buildSupportedGroupsExtension(),
			buildGREASEExtension(0x1a1a),
			buildSupportedVersionsExtension(0x0a0a, 0x0304, 0x0303),
			buildKeyShareExtension(),
		},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "www.google.com", sni)
}

// TestPeekSNI_RealCurlHex tests with a hand-constructed hex ClientHello matching
// the structure of a real curl TLS 1.3 ClientHello to example.com.
func TestPeekSNI_RealCurlHex(t *testing.T) {
	hexData := "" +
		"160301" + // TLS record: handshake, TLS 1.0
		"00ac" + // record length: 172
		"01" + // handshake type: ClientHello
		"0000a8" + // handshake length: 168
		"0303" + // version: TLS 1.2
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" + // random (32 bytes)
		"00" + // session ID length: 0
		"0004" + // cipher suites length: 4
		"13011303" + // TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
		"0100" + // compression methods: length 1, null
		"007b" + // extensions length: 123
		"0000" + // extension: server_name (0)
		"0010" + // extension length: 16
		"000e" + // server name list length: 14
		"00" + // name type: host_name
		"000b" + // name length: 11
		"6578616d706c652e636f6d" + // "example.com"
		"000a" + // extension: supported_groups (10)
		"0008" + // length: 8
		"0006" + // list length: 6
		"001d00170018" + // x25519, secp256r1, secp384r1
		"000d" + // extension: signature_algorithms (13)
		"0014" + // length: 20
		"0012" + // list length: 18
		"040308040401050308050501080606010201" + // various algorithms
		"0033" + // extension: key_share (51)
		"0026" + // length: 38
		"0024" + // list length: 36
		"001d" + // x25519
		"0020" + // key length: 32
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" + // key data
		"002b" + // extension: supported_versions (43)
		"0003" + // length: 3
		"02" + // list length: 2
		"0304" + // TLS 1.3
		"0010" + // extension: ALPN (16)
		"000e" + // length: 14
		"000c" + // list length: 12
		"02" + "6832" + // "h2"
		"08" + "687474702f312e31" // "http/1.1"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, parseErr := PeekSNI(br)
	require.NoError(t, parseErr)
	require.Equal(t, "example.com", sni)
}

// ---------------------------------------------------------------------------
// J. Security bypass / spec-compliance tests (RFC 6066, RFC 8446)
// ---------------------------------------------------------------------------

// TestPeekSNI_DuplicateSNIExtensions verifies behavior when two SNI extensions
// are present. RFC 6066 Section 3: "The client MUST NOT include more than one
// name of the same name_type." Having two server_name extensions is a protocol
// violation. An attacker might put an allowed domain in one and the real target
// in the other, hoping for a mismatch between the filter and the server.
func TestPeekSNI_DuplicateSNIExtensions(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("allowed.example.com"),
		buildALPNExtension(),
		buildSNIExtension("evil.com"),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)

	// Parser uses the first SNI extension found, ignoring duplicates.
	// This prevents an attacker from placing an allowed domain first
	// (which some servers use) and a different one second.
	require.NoError(t, err)
	require.Equal(t, "allowed.example.com", sni)
}

// TestPeekSNI_NullByteInHostname verifies that null bytes embedded in the
// hostname are preserved. This is a known bypass technique: send
// "allowed.com\x00.evil.com" — C-based TLS servers may truncate at null,
// connecting to "allowed.com", while the regex matches the full string.
func TestPeekSNI_NullByteInHostname(t *testing.T) {
	hostname := "allowed.com\x00.evil.com"
	opts := defaultOpts()
	opts.serverName = hostname
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)

	// Null bytes are rejected by hostname validation — connection will be blocked.
	require.ErrorIs(t, err, ErrNoSNI)
}

// TestPeekSNI_ControlCharsInHostname verifies the parser handles hostnames
// containing control characters (tabs, newlines, etc). These are invalid per
// RFC 952/1123 but the parser does not validate hostname characters.
func TestPeekSNI_ControlCharsInHostname(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
	}{
		{"Tab", "example\t.com"},
		{"Newline", "example\n.com"},
		{"CarriageReturn", "example\r.com"},
		{"CRLF", "example\r\n.com"},
		{"Bell", "example\a.com"},
		{"Backspace", "example\b.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.serverName = tc.hostname
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			_, _, _, err := PeekSNI(br)

			// Control characters are rejected by hostname validation.
			require.ErrorIs(t, err, ErrNoSNI)
		})
	}
}

// TestPeekSNI_TrailingDotAllowlistMismatch verifies that a trailing dot in the
// SNI hostname can cause allowlist regex mismatches. RFC 6066 does not forbid
// trailing dots, and some clients send them.
func TestPeekSNI_TrailingDotNormalized(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = "example.com."
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	// Trailing dot is stripped during parsing — no regex mismatch.
	require.Equal(t, "example.com", sni)

	strict := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	require.True(t, MatchesAllowlist(sni, strict))
}

// TestPeekSNI_HighBytesInHostname verifies behavior with non-ASCII bytes
// (0x80-0xFF) in the hostname. These are invalid per DNS specs but could
// appear in attack payloads.
func TestPeekSNI_HighBytesInHostname(t *testing.T) {
	hostname := "example\x80\xff.com"
	opts := defaultOpts()
	opts.serverName = hostname
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)

	// Non-ASCII bytes are rejected by hostname validation.
	require.ErrorIs(t, err, ErrNoSNI)
}

// TestPeekSNI_HomoglyphAttack verifies that Unicode homoglyphs (which look
// like ASCII but are different bytes) pass through. For example, Cyrillic 'а'
// (U+0430) looks identical to Latin 'a' (U+0061).
func TestPeekSNI_HomoglyphAttack(t *testing.T) {
	// "exаmple.com" where 'а' is Cyrillic U+0430 (0xD0 0xB0 in UTF-8)
	hostname := "ex\xd0\xb0mple.com"
	opts := defaultOpts()
	opts.serverName = hostname
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)

	// Non-ASCII bytes (UTF-8 encoded Cyrillic) are rejected.
	require.ErrorIs(t, err, ErrNoSNI)
}

// TestPeekSNI_IntermediateESNIDraftCodes verifies that intermediate ESNI draft
// extension types (used between the original 0xffce and final ECH 0xfe0d)
// are NOT detected. These codepoints were used in drafts -06 and -07 and were
// never widely deployed, but a determined attacker might use them to hide ECH.
func TestPeekSNI_IntermediateESNIDraftCodes(t *testing.T) {
	// Draft -06 used 0xff02, draft -07 used 0xff03
	draftCodes := []struct {
		name string
		code uint16
	}{
		{"draft06_0xff02", 0xff02},
		{"draft07_0xff03", 0xff03},
	}
	for _, dc := range draftCodes {
		code := dc.code
		t.Run(dc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				{typ: code, data: []byte{0x00, 0x01, 0x02}},
			}
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, _, _, err := PeekSNI(br)

			// These intermediate draft codes are NOT detected as ECH —
			// the parser only checks 0xfe0d and 0xffce.
			// This is acceptable since these drafts were never deployed.
			require.NoError(t, err)
			require.Equal(t, "example.com", sni)
			t.Logf("Intermediate ESNI draft extension 0x%04x NOT blocked (expected)", code)
		})
	}
}

// TestPeekSNI_ECHGrease verifies that GREASE ECH (sent by Chrome when ECH
// is not available, to prevent ossification) does not prevent SNI extraction.
// Per RFC 9849 Section 8.1.2, the proxy acts based on the outer SNI.
func TestPeekSNI_ECHGrease(t *testing.T) {
	// Chrome sends GREASE ECH with random config_id and random payload
	greaseECHData := make([]byte, 166)
	rand.Read(greaseECHData)
	greaseECHData[0] = 0x00

	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		{typ: 0xfe0d, data: greaseECHData},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)

	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// TestMatchesAllowlist_NullByteBypass verifies regex behavior with null bytes.
// PeekSNI now rejects these hostnames, but MatchesAllowlist is a pure regex
// function — these tests document its raw behavior for defense-in-depth.
func TestMatchesAllowlist_NullByteBypass(t *testing.T) {
	cases := []struct {
		name     string
		domain   string
		pattern  string
		expected bool
	}{
		{
			name:     "AnchoredExactBlocks",
			domain:   "allowed.com\x00.evil.com",
			pattern:  `^allowed\.com$`,
			expected: false,
		},
		{
			name:     "UnanchoredPrefixMatches",
			domain:   "allowed.com\x00.evil.com",
			pattern:  `allowed\.com`,
			expected: true, // BYPASS: matches substring before null
		},
		{
			name:     "DotStarSuffixMatches",
			domain:   "evil.com\x00.allowed.com",
			pattern:  `allowed\.com$`,
			expected: true, // BYPASS: matches after null byte
		},
		{
			name:     "NullOnlyBeforeDot",
			domain:   "allowed\x00.com",
			pattern:  `^allowed\.com$`,
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowlist := []*regexp.Regexp{regexp.MustCompile(tc.pattern)}
			got := MatchesAllowlist(tc.domain, allowlist)
			require.Equal(t, tc.expected, got)
		})
	}
}

// TestMatchesAllowlist_DotNotEscaped demonstrates that unescaped dots in regex
// patterns match any character, which could allow bypasses.
func TestMatchesAllowlist_DotNotEscaped(t *testing.T) {
	// Pattern "example.com" (unescaped dot) matches "exampleXcom"
	allowlist := []*regexp.Regexp{regexp.MustCompile(`^example.com$`)}
	require.True(t, MatchesAllowlist("exampleXcom", allowlist),
		"unescaped dot matches any character")

	// Properly escaped
	allowlist2 := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	require.False(t, MatchesAllowlist("exampleXcom", allowlist2))
}

// TestMatchesAllowlist_CaseInsensitivity verifies that regex matching is
// case-sensitive by default. DNS is case-insensitive per RFC 4343, so
// "Example.COM" should match "example.com" patterns — but it won't unless
// the pattern uses (?i).
func TestMatchesAllowlist_CaseInsensitivity(t *testing.T) {
	// Default: case-sensitive
	strict := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	require.False(t, MatchesAllowlist("Example.COM", strict),
		"default regex is case-sensitive — DNS names with different case won't match")
	require.False(t, MatchesAllowlist("EXAMPLE.COM", strict))

	// With (?i) flag: case-insensitive
	flexible := []*regexp.Regexp{regexp.MustCompile(`(?i)^example\.com$`)}
	require.True(t, MatchesAllowlist("Example.COM", flexible))
	require.True(t, MatchesAllowlist("EXAMPLE.COM", flexible))
}

// ---------------------------------------------------------------------------
// K. Case normalization tests
// ---------------------------------------------------------------------------

func TestPeekSNI_MixedCaseNormalized(t *testing.T) {
	data := buildClientHelloBytes("Example.COM")
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni, "mixed-case SNI should be lowercased by parser")

	// Strict lowercase regex now matches because parser normalizes.
	strict := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	require.True(t, MatchesAllowlist(sni, strict))
}

func TestPeekSNI_AllUpperCaseNormalized(t *testing.T) {
	data := buildClientHelloBytes("EXAMPLE.COM")
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// ---------------------------------------------------------------------------
// L. ALPN extraction tests
// ---------------------------------------------------------------------------

func TestPeekSNI_ALPNExtracted(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildALPNExtension(), // "h2", "http/1.1"
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	require.Equal(t, []string{"h2", "http/1.1"}, alpn)
}

func TestPeekSNI_NoALPN(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	require.Nil(t, alpn)
}

func TestPeekSNI_ALPNMalformed(t *testing.T) {
	opts := defaultOpts()
	// ALPN extension with truncated data (list length says 100 but only 2 bytes)
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		{typ: 0x0010, data: []byte{0x00, 0x64, 0x02}}, // list length 100 but only 1 byte of data
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, alpn, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	require.Nil(t, alpn) // malformed ALPN returns nil, no error
}

func TestParseALPNExtension(t *testing.T) {
	cases := []struct {
		name     string
		data     []byte
		expected []string
	}{
		{
			name: "H2AndHTTP11",
			data: func() []byte {
				ext := buildALPNExtension()
				return ext.data
			}(),
			expected: []string{"h2", "http/1.1"},
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: nil,
		},
		{
			name:     "TooShort",
			data:     []byte{0x00},
			expected: nil,
		},
		{
			name:     "ZeroLength",
			data:     []byte{0x00, 0x00},
			expected: nil,
		},
		{
			name:     "ListLenOverflow",
			data:     []byte{0xFF, 0xFF},
			expected: nil,
		},
		{
			name: "SingleProtocol",
			data: func() []byte {
				var buf bytes.Buffer
				proto := "h2"
				var list bytes.Buffer
				list.WriteByte(byte(len(proto)))
				list.WriteString(proto)
				binary.Write(&buf, binary.BigEndian, uint16(list.Len()))
				buf.Write(list.Bytes())
				return buf.Bytes()
			}(),
			expected: []string{"h2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseALPNExtension(tc.data)
			require.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// M. ECH spec-compliance tests (RFC 9849 / draft-ietf-tls-esni-25)
//
// These tests verify that ECH extensions (0xfe0d) and legacy ESNI (0xffce)
// do not interfere with SNI extraction. Per RFC 9849 Section 8.1.2,
// middleboxes act based on the outer SNI. The parser ignores these
// extensions and returns the outer SNI normally. Security enforcement
// is handled by the allowlist and DNS cross-validation in
// handleTLSWithAllowlist.
// ---------------------------------------------------------------------------

// M1: SNI + spec-compliant ECH outer (config_id=42, 32B enc, 256B payload).
func TestPeekSNI_ECHOuterWithSNI(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHOuterExtension(42, 32, 256),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M2: No SNI + ECH outer. Verifies ErrNoSNI when no SNI is present, regardless of ECH.
func TestPeekSNI_ECHOuterWithoutSNI(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildECHOuterExtension(42, 32, 256),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := PeekSNI(br)
	require.ErrorIs(t, err, ErrNoSNI)
}

// M3: SNI + ECH inner (type=0x01). Should never appear on wire from client.
func TestPeekSNI_ECHInnerType(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHInnerExtension(),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M4: Full Chrome-like ClientHello with GREASE ciphers, SNI, key_share,
// supported_versions, ALPN, GREASE extensions, and Chrome-inspired ECH GREASE (330B).
func TestPeekSNI_ECHGreaseChrome(t *testing.T) {
	opts := clientHelloOpts{
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildGREASEExtension(0x0a0a),
			buildSNIExtension("www.google.com"),
			buildALPNExtension(),
			buildSupportedGroupsExtension(),
			buildGREASEExtension(0x1a1a),
			buildSupportedVersionsExtension(0x0a0a, 0x0304, 0x0303),
			buildKeyShareExtension(),
			buildChromeECHGreaseExtension(),
		},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "www.google.com", sni)
}

// M5: Full Firefox-like ClientHello with Firefox-inspired ECH GREASE (266B).
func TestPeekSNI_ECHGreaseFirefox(t *testing.T) {
	opts := clientHelloOpts{
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x1301, 0x1303, 0x1302, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildSNIExtension("www.mozilla.org"),
			buildSupportedVersionsExtension(0x0304, 0x0303),
			buildKeyShareExtension(),
			buildSupportedGroupsExtension(),
			buildALPNExtension(),
			buildFirefoxECHGreaseExtension(),
		},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "www.mozilla.org", sni)
}

// M6: Verify ECH presence does not prevent SNI extraction.
// The outer SNI bytes are present in the raw data and the parser returns them.
func TestPeekSNI_ECHGreaseOuterSNIIsParseable(t *testing.T) {
	hostname := "www.google.com"
	opts := clientHelloOpts{
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildGREASEExtension(0x0a0a),
			buildSNIExtension(hostname),
			buildKeyShareExtension(),
			buildSupportedVersionsExtension(0x0304, 0x0303),
			buildChromeECHGreaseExtension(),
		},
	}
	data := buildClientHello(opts)

	// Verify the SNI hostname bytes are present in the raw data.
	require.True(t, bytes.Contains(data, []byte(hostname)),
		"raw ClientHello should contain the outer SNI hostname bytes")

	// PeekSNI returns the outer SNI, ignoring the ECH extension.
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, hostname, sni)
}

// M7: ECH extension with zero-length data.
func TestPeekSNI_ECHEmptyPayload(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		{typ: 0xfe0d, data: []byte{}},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M8: ECH with single byte payload (just outer type byte, truncated).
func TestPeekSNI_ECHSingleBytePayload(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		{typ: 0xfe0d, data: []byte{0x00}},
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M9: Table-driven config_id values.
func TestPeekSNI_ECHConfigIDs(t *testing.T) {
	configIDs := []struct {
		name     string
		configID uint8
	}{
		{"Zero", 0},
		{"One", 1},
		{"Mid127", 127},
		{"Mid128", 128},
		{"Max255", 255},
	}
	for _, tc := range configIDs {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				buildECHOuterExtension(tc.configID, 32, 128),
			}
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, _, _, err := PeekSNI(br)
			require.NoError(t, err)
			require.Equal(t, "example.com", sni)
		})
	}
}

// M10: Table-driven cipher suites.
func TestPeekSNI_ECHCipherSuites(t *testing.T) {
	suites := []struct {
		name   string
		kdfID  uint16
		aeadID uint16
	}{
		{"SHA256_AES128", 0x0001, 0x0001},
		{"SHA256_ChaCha", 0x0001, 0x0003},
		{"SHA384_AES256", 0x0002, 0x0002},
		{"Zero_Zero", 0x0000, 0x0000},
		{"Max_Max", 0xFFFF, 0xFFFF},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				buildECHOuterExtensionWithCipher(42, tc.kdfID, tc.aeadID, 32, 128),
			}
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, _, _, err := PeekSNI(br)
			require.NoError(t, err)
			require.Equal(t, "example.com", sni)
		})
	}
}

// M11: Table-driven enc lengths.
func TestPeekSNI_ECHEncLengths(t *testing.T) {
	lengths := []struct {
		name   string
		encLen int
	}{
		{"Zero", 0},
		{"One", 1},
		{"X25519_32", 32},
		{"P256_65", 65},
		{"P384_97", 97},
		{"Large256", 256},
	}
	for _, tc := range lengths {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				buildECHOuterExtension(42, tc.encLen, 128),
			}
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, _, _, err := PeekSNI(br)
			require.NoError(t, err)
			require.Equal(t, "example.com", sni)
		})
	}
}

// M12: Table-driven payload lengths.
func TestPeekSNI_ECHPayloadLengths(t *testing.T) {
	lengths := []struct {
		name       string
		payloadLen int
	}{
		{"Tiny1", 1},
		{"Small128", 128},
		{"Medium256", 256},
		{"Large512", 512},
		{"XLarge1024", 1024},
		{"Huge4096", 4096},
	}
	for _, tc := range lengths {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				buildECHOuterExtension(42, 32, tc.payloadLen),
			}
			data := buildClientHello(opts)
			br := bufio.NewReaderSize(bytes.NewReader(data), len(data)+1)
			sni, _, _, err := PeekSNI(br)
			require.NoError(t, err)
			require.Equal(t, "example.com", sni)
		})
	}
}

// M13: Extension order: ECH first, then SNI. SNI extracted regardless of order.
func TestPeekSNI_ECHBeforeSNI(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildECHOuterExtension(42, 32, 256),
		buildSNIExtension("example.com"),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M14: Extension order: SNI first, then ECH. SNI extracted regardless of order.
func TestPeekSNI_ECHAfterSNI(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHOuterExtension(42, 32, 256),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M15: Two ECH extensions (both 0xfe0d) + SNI. Adversarial duplicate.
func TestPeekSNI_MultipleECHExtensions(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHOuterExtension(1, 32, 128),
		buildECHOuterExtension(2, 32, 128),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M16: SNI + ECH (0xfe0d) + ESNI (0xffce). Both extension types simultaneously.
func TestPeekSNI_ECHAndESNIBothPresent(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHOuterExtension(42, 32, 256),
		buildLegacyESNIExtensionWithPayload(64),
	}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M17: SNI + Chrome GREASE ECH, fragmented across 2 TLS records.
func TestPeekSNI_ECHFragmented(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildChromeECHGreaseExtension(),
	}
	opts.fragmentAt = []int{50}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M18: Fragment at the ECH extension type/length boundary
// (split between 2B type code and 2B length).
func TestPeekSNI_ECHFragmentedAtExtHeader(t *testing.T) {
	// Build unfragmented first to find the ECH extension position.
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildChromeECHGreaseExtension(),
	}
	unfragmented := buildClientHello(opts)

	// Find the ECH extension type bytes (0xfe, 0x0d) in the handshake payload.
	echTypePos := bytes.Index(unfragmented[5:], []byte{0xfe, 0x0d})
	require.Greater(t, echTypePos, 0, "ECH extension type should be present")

	// Fragment between the 2-byte type code and the 2-byte length field.
	splitPoint := echTypePos + 2
	opts.fragmentAt = []int{splitPoint}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M19: SNI + Chrome GREASE ECH, 3 TLS record fragments.
func TestPeekSNI_ECHThreeFragments(t *testing.T) {
	opts := defaultOpts()
	opts.serverName = ""
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildChromeECHGreaseExtension(),
	}
	opts.fragmentAt = []int{30, 100}
	data := buildClientHello(opts)
	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M20: Table-driven intermediate ECH draft codes 0xfe08-0xfe0c.
// These should NOT trigger ErrECH — only 0xfe0d and 0xffce are detected.
func TestPeekSNI_IntermediateECHDraftCodes_0xfe(t *testing.T) {
	draftCodes := []struct {
		name string
		code uint16
	}{
		{"draft_0xfe08", 0xfe08},
		{"draft_0xfe09", 0xfe09},
		{"draft_0xfe0a", 0xfe0a},
		{"draft_0xfe0b", 0xfe0b},
		{"draft_0xfe0c", 0xfe0c},
	}
	for _, dc := range draftCodes {
		t.Run(dc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				{typ: dc.code, data: []byte{0x00, 0x01, 0x02}},
			}
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, _, _, err := PeekSNI(br)
			require.NoError(t, err, "intermediate draft code 0x%04x should not trigger ErrECH", dc.code)
			require.Equal(t, "example.com", sni)
		})
	}
}

// M21: ECH outer with 32B enc + 16000B payload. Near TLS record maximum.
func TestPeekSNI_ECHMaxPayload(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHOuterExtension(42, 32, 16000),
	}
	data := buildClientHello(opts)
	br := bufio.NewReaderSize(bytes.NewReader(data), len(data)+1)
	sni, _, _, err := PeekSNI(br)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
}

// M22: Adjacent extension type codes — all are ignored, SNI is returned normally.
func TestPeekSNI_ECHAdjacentExtensionTypes(t *testing.T) {
	extTypes := []struct {
		name    string
		extType uint16
	}{
		{"0xfe0c", 0xfe0c},
		{"0xfe0d", 0xfe0d},
		{"0xfe0e", 0xfe0e},
		{"0xffcd", 0xffcd},
		{"0xffce", 0xffce},
		{"0xffcf", 0xffcf},
	}
	for _, tc := range extTypes {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.extensions = []tlsExtension{
				buildSNIExtension("example.com"),
				{typ: tc.extType, data: []byte{0x00, 0x01, 0x02, 0x03}},
			}
			data := buildClientHello(opts)
			br := bufio.NewReader(bytes.NewReader(data))
			sni, _, _, err := PeekSNI(br)
			require.NoError(t, err, "extension 0x%04x should not prevent SNI extraction", tc.extType)
			require.Equal(t, "example.com", sni)
		})
	}
}

// M23: Hand-built hex ClientHello mimicking Chrome 120 ECH GREASE,
// with field-by-field comments.
func TestPeekSNI_ECHGreaseGoldenHex(t *testing.T) {
	hexData := "" +
		"160301" + // TLS record: handshake, TLS 1.0
		"00ab" + // record length: 171
		"01" + // handshake type: ClientHello
		"0000a7" + // handshake length: 167
		"0303" + // version: TLS 1.2 (legacy)
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + // random (32B)
		"20" + // session ID length: 32
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + // session ID (32B)
		"000c" + // cipher suites length: 12 (6 suites)
		"0a0a" + // GREASE cipher suite
		"1301" + // TLS_AES_128_GCM_SHA256
		"1302" + // TLS_AES_256_GCM_SHA384
		"1303" + // TLS_CHACHA20_POLY1305_SHA256
		"c02c" + // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		"c02b" + // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		"01" + // compression methods length: 1
		"00" + // null compression
		"0052" + // extensions total length: 82
		// --- SNI extension ---
		"0000" + // extension type: server_name
		"0010" + // extension length: 16
		"000e" + // server name list length: 14
		"00" + // name type: host_name
		"000b" + // name length: 11
		"6578616d706c652e636f6d" + // "example.com"
		// --- ECH GREASE extension (Chrome 120 style) ---
		"fe0d" + // extension type: encrypted_client_hello
		"003a" + // extension length: 58
		"00" + // ECHClientHelloType: outer
		"0001" + // kdf_id: HKDF-SHA256
		"0001" + // aead_id: AES-128-GCM
		"00" + // config_id: 0 (GREASE)
		"0020" + // enc length: 32
		"0000000000000000000000000000000000000000000000000000000000000000" + // enc (32B)
		"0010" + // payload length: 16
		"00000000000000000000000000000000" // payload (16B)

	data, err := hex.DecodeString(hexData)
	require.NoError(t, err, "invalid hex in golden test")

	br := bufio.NewReader(bytes.NewReader(data))
	sni, _, _, parseErr := PeekSNI(br)
	require.NoError(t, parseErr)
	require.Equal(t, "example.com", sni)
}
