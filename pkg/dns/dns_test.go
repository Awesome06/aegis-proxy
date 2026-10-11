package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildQuery_Format(t *testing.T) {
	// Arrange
	txID := uint16(0x1234)
	hostname := "example.com"

	// Act
	payload, err := BuildQuery(txID, hostname, TypeA)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error building query: %v", err)
	}
	if len(payload) < 12 {
		t.Fatalf("payload too short, expected >= 12, got %d", len(payload))
	}

	// Verify Header
	if payload[0] != 0x12 || payload[1] != 0x34 {
		t.Fatalf("mismatched txID in header: got %x%x", payload[0], payload[1])
	}
	// RD bit should be 1
	if payload[2] != 0x01 || payload[3] != 0x00 {
		t.Fatalf("flags expected 0x0100, got %x%x", payload[2], payload[3])
	}

	// Check QNAME: \x07example\x03com\x00
	qnameStart := 12
	expectedQname := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	qnameEnd := qnameStart + len(expectedQname)
	if string(payload[qnameStart:qnameEnd]) != string(expectedQname) {
		t.Fatalf("qname bytes mismatch: got %v, expected %v", payload[qnameStart:qnameEnd], expectedQname)
	}

	// QTYPE & QCLASS
	if payload[qnameEnd] != 0x00 || payload[qnameEnd+1] != 0x01 {
		t.Fatalf("expected QTYPE TypeA (1), got %x%x", payload[qnameEnd], payload[qnameEnd+1])
	}
}

func TestBuildQuery_Errors(t *testing.T) {
	// 1. Empty hostname
	_, err := BuildQuery(1, "", TypeA)
	if err == nil {
		t.Fatalf("expected error on empty hostname")
	}

	// 2. Trailing dot only
	_, err = BuildQuery(1, ".", TypeA)
	if err == nil {
		t.Fatalf("expected error on dot-only hostname")
	}

	// 3. Label exceeding 63 bytes (RFC 1035 limit)
	longLabel := strings.Repeat("a", 64)
	_, err = BuildQuery(1, longLabel+".com", TypeA)
	if err == nil {
		t.Fatalf("expected error on label exceeding 63 bytes")
	}
}

func TestParseResponse_SyntheticARecord(t *testing.T) {
	// Arrange: Create a synthetic DNS response for "test.com" returning 93.184.216.34 with TTL 300
	txID := uint16(0xABCD)
	resp := []byte{
		// Header (12 bytes)
		0xAB, 0xCD, // ID
		0x81, 0x80, // Flags (Standard query response, No error)
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// Question: test.com
		0x04, 't', 'e', 's', 't',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
		// Answer: pointer to question (0xC00C), Type A, Class IN, TTL 300, RDLENGTH 4, IP 93.184.216.34
		0xC0, 0x0C, // Compressed pointer to offset 12
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x01, 0x2C, // TTL = 300
		0x00, 0x04, // RDLENGTH = 4
		93, 184, 216, 34, // IP bytes
	}

	// Act
	ips, ttl, err := ParseResponse(resp, txID)

	// Assert
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("expected IP 93.184.216.34, got %v", ips[0])
	}
	if ttl != 300 {
		t.Fatalf("expected TTL 300, got %d", ttl)
	}
}

func TestParseResponse_SyntheticAAAARecord(t *testing.T) {
	txID := uint16(0x1111)
	resp := []byte{
		0x11, 0x11, // ID
		0x81, 0x80, // Flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// Question: test.com
		0x04, 't', 'e', 's', 't',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x1C, // QTYPE = AAAA (28)
		0x00, 0x01, // QCLASS = IN
		// Answer: pointer to question (0xC00C), Type AAAA, Class IN, TTL 60, RDLENGTH 16
		0xC0, 0x0C,
		0x00, 0x1C, // Type AAAA
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3C, // TTL = 60
		0x00, 0x10, // RDLENGTH = 16
		// IPv6 bytes: 2001:db8::1
		0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	ips, ttl, err := ParseResponse(resp, txID)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IPv6, got %d", len(ips))
	}
	expectedIP := net.ParseIP("2001:db8::1")
	if !ips[0].Equal(expectedIP) {
		t.Fatalf("expected IP %v, got %v", expectedIP, ips[0])
	}
	if ttl != 60 {
		t.Fatalf("expected TTL 60, got %d", ttl)
	}
}

func TestParseResponse_ErrorsAndMalformed(t *testing.T) {
	// 1. Truncated header (< 12 bytes)
	_, _, err := ParseResponse([]byte{0x00, 0x01}, 1)
	if err == nil {
		t.Fatalf("expected error on truncated packet")
	}

	// 2. TxID mismatch
	header := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _, err = ParseResponse(header, 0x0002)
	if err == nil {
		t.Fatalf("expected error on TxID mismatch")
	}

	// 3. Server failure (RCODE = 3, NXDOMAIN)
	nxDomain := []byte{0x00, 0x01, 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _, err = ParseResponse(nxDomain, 0x0001)
	if err == nil {
		t.Fatalf("expected error on non-zero RCODE")
	}

	// 4. No answers
	noAnswers := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _, err = ParseResponse(noAnswers, 0x0001)
	if err == nil {
		t.Fatalf("expected error when zero answers are returned")
	}

	// 5. Compression pointer loop
	cyclic := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // Flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// Question at offset 12: points to itself (0xC00C)
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
	}
	_, _, err = ParseResponse(cyclic, 0x0001)
	if err == nil {
		t.Fatalf("expected error on circular pointer loop")
	}
}

func TestCache_DeterministicTTLExpiration(t *testing.T) {
	cache := NewCache()
	ip := net.IPv4(1, 1, 1, 1)

	// Deterministic valid entry
	cache.SetWithExpiration("valid.com", []net.IP{ip}, time.Now().Add(10*time.Minute), 600)
	ips, ok := cache.Get("valid.com")
	if !ok || len(ips) != 1 || !ips[0].Equal(ip) {
		t.Fatalf("expected valid cached IP")
	}

	// Deterministic expired entry (in the past) - ZERO SLEEP!
	cache.SetWithExpiration("expired.com", []net.IP{ip}, time.Now().Add(-1*time.Minute), 60)
	_, ok = cache.Get("expired.com")
	if ok {
		t.Fatalf("expected expired entry to return false")
	}

	// Len check
	if cache.Len() < 1 {
		t.Fatalf("expected cache length >= 1, got %d", cache.Len())
	}

	// Purge expired
	purged := cache.PurgeExpired()
	if purged < 1 {
		t.Fatalf("expected at least 1 purged entry, got %d", purged)
	}

	// Test Active Eviction routine with context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cache.StartActiveEviction(ctx, 10*time.Millisecond)
	cancel() // Immediate clean shutdown
}

func TestResolver_LiveNetworkResolution(t *testing.T) {
	// Arrange
	resolver := NewResolver(DefaultPublicResolvers, 3*time.Second)
	if resolver.Cache() == nil {
		t.Fatalf("expected non-nil cache")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	// Act: Resolve public domain
	ips, err := resolver.Resolve(ctx, "one.one.one.one")
	if err != nil {
		t.Logf("live network resolution skipped or failed (offline environment): %v", err)
		return
	}

	// Assert: Check that at least one known Cloudflare IP is resolved (1.1.1.1 or 1.0.0.1)
	foundTarget := false
	for _, ip := range ips {
		if ip.Equal(net.IPv4(1, 1, 1, 1)) || ip.Equal(net.IPv4(1, 0, 0, 1)) {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		t.Fatalf("resolved IPs did not contain 1.1.1.1 or 1.0.0.1: %v", ips)
	}

	// Verify Cache Hit on subsequent request
	cachedIPs, err := resolver.Resolve(ctx, "one.one.one.one")
	if err != nil {
		t.Fatalf("unexpected cache lookup error: %v", err)
	}
	if len(cachedIPs) != len(ips) {
		t.Fatalf("expected cached IPs length %d, got %d", len(ips), len(cachedIPs))
	}
}
