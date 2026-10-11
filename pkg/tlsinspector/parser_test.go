package tlsinspector

import (
	"testing"
)

// Helper to build a valid synthetic TLS ClientHello frame with SNI and ALPN
func buildSyntheticClientHello(sni string, alpnProtos []string) []byte {
	// Handshake data
	// ClientVersion: TLS 1.2 (0x0303)
	// Random: 32 bytes of 0x01
	// SessionID: length 0 (0x00)
	// CipherSuites: length 2 (0x00, 0x02), one cipher (0xC0, 0x2F)
	// Compression: length 1 (0x01), null (0x00)

	var payload []byte
	payload = append(payload, 0x03, 0x03) // Client Version
	for i := 0; i < 32; i++ {
		payload = append(payload, 0x01) // Random
	}
	payload = append(payload, 0x00)       // Session ID Length = 0
	payload = append(payload, 0x00, 0x02, 0xC0, 0x2F) // Cipher Suites
	payload = append(payload, 0x01, 0x00) // Compression Methods (1, 0)

	// Extensions
	var extBytes []byte

	// 1. SNI Extension (0x0000)
	if sni != "" {
		sniBytes := []byte(sni)
		var sniData []byte
		// ServerNameListLength = len(sni) + 3
		listLen := len(sniBytes) + 3
		sniData = append(sniData, byte(listLen>>8), byte(listLen))
		sniData = append(sniData, 0x00) // NameType = host_name
		sniData = append(sniData, byte(len(sniBytes)>>8), byte(len(sniBytes)))
		sniData = append(sniData, sniBytes...)

		// Extension Type 0x0000, Length
		extBytes = append(extBytes, 0x00, 0x00)
		extBytes = append(extBytes, byte(len(sniData)>>8), byte(len(sniData)))
		extBytes = append(extBytes, sniData...)
	}

	// 2. ALPN Extension (0x0010)
	if len(alpnProtos) > 0 {
		var alpnList []byte
		for _, proto := range alpnProtos {
			alpnList = append(alpnList, byte(len(proto)))
			alpnList = append(alpnList, proto...)
		}
		var alpnData []byte
		alpnData = append(alpnData, byte(len(alpnList)>>8), byte(len(alpnList)))
		alpnData = append(alpnData, alpnList...)

		extBytes = append(extBytes, 0x00, 0x10)
		extBytes = append(extBytes, byte(len(alpnData)>>8), byte(len(alpnData)))
		extBytes = append(extBytes, alpnData...)
	}

	// Extensions Length
	payload = append(payload, byte(len(extBytes)>>8), byte(len(extBytes)))
	payload = append(payload, extBytes...)

	// Handshake Header: Type 0x01 (ClientHello), Length (uint24)
	var handshake []byte
	handshake = append(handshake, 0x01)
	hsLen := len(payload)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, payload...)

	// TLS Record Header: ContentType 0x16, Version 0x0301, Length uint16
	var record []byte
	record = append(record, 0x16, 0x03, 0x01)
	recLen := len(handshake)
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, handshake...)

	return record
}

func TestParseClientHello_ValidSNIAndALPN(t *testing.T) {
	// Arrange
	targetSNI := "api.zscaler.com"
	targetALPN := []string{"h2", "http/1.1"}
	rawRecord := buildSyntheticClientHello(targetSNI, targetALPN)

	// Act
	info, err := ParseClientHello(rawRecord)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error parsing ClientHello: %v", err)
	}
	if info.SNI != targetSNI {
		t.Fatalf("expected SNI %q, got %q", targetSNI, info.SNI)
	}
	if len(info.ALPNProtos) != 2 || info.ALPNProtos[0] != "h2" || info.ALPNProtos[1] != "http/1.1" {
		t.Fatalf("expected ALPN [h2, http/1.1], got %v", info.ALPNProtos)
	}
}

func TestParseClientHello_NonTLSAndMalformed(t *testing.T) {
	// 1. Plain HTTP request
	plainHTTP := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if IsTLS(plainHTTP) {
		t.Fatalf("expected IsTLS to return false for plain HTTP")
	}
	_, err := ParseClientHello(plainHTTP)
	if err == nil {
		t.Fatalf("expected error parsing plain HTTP as TLS")
	}

	// 2. Truncated TLS Record
	truncated := []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01}
	_, err = ParseClientHello(truncated)
	if err == nil {
		t.Fatalf("expected error parsing truncated TLS record")
	}
}

func TestBlacklistFilter(t *testing.T) {
	// Arrange
	filter := NewBlacklistFilter([]string{
		"malicious.com",
		"*.badtracker.net",
		".evil-adserver.org",
	})

	tests := []struct {
		name          string
		hostname      string
		expectBlocked bool
	}{
		{"exact blacklisted domain", "malicious.com", true},
		{"exact domain uppercase", "MALICIOUS.COM", true},
		{"subdomain of wildcard rule", "ads.badtracker.net", true},
		{"nested subdomain of wildcard rule", "tracker.telemetry.badtracker.net", true},
		{"dot-prefixed suffix rule", "cdn.evil-adserver.org", true},
		{"safe domain", "google.com", false},
		{"partial prefix false positive should pass", "notmalicious.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blocked, rule := filter.IsBlocked(tc.hostname)
			if blocked != tc.expectBlocked {
				t.Fatalf("expected blocked=%v, got %v (rule=%s) for %s", tc.expectBlocked, blocked, rule, tc.hostname)
			}
		})
	}

	// Empty hostname check
	blocked, _ := filter.IsBlocked("")
	if blocked {
		t.Fatalf("expected empty hostname to not be blocked")
	}

	// UpdateRules with empty and whitespace rules
	filter.UpdateRules([]string{"", "  ", "safe.org"})
	blocked, _ = filter.IsBlocked("safe.org")
	if !blocked {
		t.Fatalf("expected safe.org to be blocked after update")
	}
}

func TestParseClientHello_EdgeCases(t *testing.T) {
	// 1. ClientHello without extensions
	noExt := buildSyntheticClientHello("", nil)
	info, err := ParseClientHello(noExt)
	if err != nil {
		t.Fatalf("unexpected error parsing ClientHello without extensions: %v", err)
	}
	if info.SNI != "" {
		t.Fatalf("expected empty SNI, got %q", info.SNI)
	}

	// 2. ClientHello with broken handshake header (wrong handshake type 0x02 instead of 0x01)
	brokenHS := make([]byte, len(noExt))
	copy(brokenHS, noExt)
	brokenHS[5] = 0x02 // ServerHello instead of ClientHello
	_, err = ParseClientHello(brokenHS)
	if err == nil {
		t.Fatalf("expected error on non-ClientHello handshake type")
	}

	// 3. Short buffer (< 44 bytes)
	_, err = ParseClientHello(make([]byte, 20))
	if err == nil {
		t.Fatalf("expected error on buffer < 44 bytes")
	}
}

func BenchmarkParseClientHello(b *testing.B) {
	rawRecord := buildSyntheticClientHello("telemetry.gateway.zscaler.com", []string{"h2", "http/1.1"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseClientHello(rawRecord)
	}
}
