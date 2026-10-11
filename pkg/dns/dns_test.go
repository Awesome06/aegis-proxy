package dns

import (
	"context"
	"net"
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

func TestCache_TTLAndEviction(t *testing.T) {
	// Arrange
	cache := NewCache()
	ip := net.IPv4(1, 1, 1, 1)

	// Act: Set with 1 second TTL
	cache.Set("fast.expire.com", []net.IP{ip}, 1)

	// Assert: Immediately present
	ips, ok := cache.Get("fast.expire.com")
	if !ok || len(ips) != 1 || !ips[0].Equal(ip) {
		t.Fatalf("expected cached IP to be available immediately")
	}

	// Wait past expiration
	time.Sleep(1100 * time.Millisecond)

	// Assert: Stale record is not returned
	_, ok = cache.Get("fast.expire.com")
	if ok {
		t.Fatalf("expected record to be expired and not returned")
	}

	// Purge should report cleared count
	cache.Set("to.purge.com", []net.IP{ip}, 1)
	time.Sleep(1100 * time.Millisecond)
	purged := cache.PurgeExpired()
	if purged < 1 {
		t.Fatalf("expected at least 1 purged record, got %d", purged)
	}
}

func TestResolver_LiveNetworkResolution(t *testing.T) {
	// Arrange
	resolver := NewResolver(DefaultPublicResolvers, 3*time.Second)
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
