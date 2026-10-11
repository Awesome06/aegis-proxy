package l3

import (
	"net"
	"testing"
)

func TestRadixTree_IPv4Matching(t *testing.T) {
	// Arrange
	tree := NewRadixTree()
	cidrs := []string{
		"10.0.0.0/8",
		"192.168.1.0/24",
		"192.168.1.128/28", // more specific overlap
		"172.16.0.0/16",
	}
	for _, c := range cidrs {
		if err := tree.InsertCIDR(c); err != nil {
			t.Fatalf("unexpected insert error: %v", err)
		}
	}

	tests := []struct {
		name         string
		ip           string
		expectMatch  bool
		expectedCIDR string
	}{
		{"exact private 192 range", "192.168.1.50", true, "192.168.1.0/24"},
		{"longest prefix match in 192 range", "192.168.1.130", true, "192.168.1.128/28"},
		{"class A private IP", "10.254.1.2", true, "10.0.0.0/8"},
		{"class B private IP", "172.16.50.1", true, "172.16.0.0/16"},
		{"public IP not whitelisted", "8.8.8.8", false, ""},
		{"adjacent 192 subnet not matched", "192.168.2.1", false, ""},
		{"loopback IP not whitelisted", "127.0.0.1", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			matchedCIDR, matched := tree.LongestPrefixMatch(net.ParseIP(tc.ip))

			// Assert
			if matched != tc.expectMatch {
				t.Fatalf("expected match=%v, got match=%v for IP %s", tc.expectMatch, matched, tc.ip)
			}
			if tc.expectMatch && matchedCIDR != tc.expectedCIDR {
				t.Fatalf("expected CIDR %s, got %s for IP %s", tc.expectedCIDR, matchedCIDR, tc.ip)
			}
		})
	}
}

func TestRadixTree_IPv6Matching(t *testing.T) {
	// Arrange
	tree := NewRadixTree()
	cidrs := []string{
		"2001:db8::/32",
		"2001:db8:abcd::/48",
		"fe80::/10",
	}
	for _, c := range cidrs {
		if err := tree.InsertCIDR(c); err != nil {
			t.Fatalf("unexpected insert error: %v", err)
		}
	}

	tests := []struct {
		name         string
		ip           string
		expectMatch  bool
		expectedCIDR string
	}{
		{"base documentation prefix", "2001:db8:1::1", true, "2001:db8::/32"},
		{"more specific /48 prefix", "2001:db8:abcd:1234::1", true, "2001:db8:abcd::/48"},
		{"link-local address", "fe80::1", true, "fe80::/10"},
		{"google IPv6 DNS not in tree", "2001:4860:4860::8888", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matchedCIDR, matched := tree.LongestPrefixMatch(net.ParseIP(tc.ip))
			if matched != tc.expectMatch {
				t.Fatalf("expected match=%v, got match=%v for IP %s", tc.expectMatch, matched, tc.ip)
			}
			if tc.expectMatch && matchedCIDR != tc.expectedCIDR {
				t.Fatalf("expected CIDR %s, got %s for IP %s", tc.expectedCIDR, matchedCIDR, tc.ip)
			}
		})
	}
}

func TestPolicyEngine_AtomicUpdates(t *testing.T) {
	// Arrange
	engine, err := NewPolicyEngine([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	// Act & Assert Initial
	allowed, _ := engine.EvaluateIP(net.ParseIP("10.1.2.3"))
	if !allowed {
		t.Fatalf("expected 10.1.2.3 to be allowed initially")
	}
	blocked, _ := engine.EvaluateIP(net.ParseIP("192.168.1.1"))
	if blocked {
		t.Fatalf("expected 192.168.1.1 to be blocked initially")
	}

	// Act: Atomic update
	err = engine.UpdateRules([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("failed to update rules: %v", err)
	}

	// Assert After Update
	nowAllowed, cidr := engine.EvaluateIP(net.ParseIP("192.168.1.1"))
	if !nowAllowed || cidr != "192.168.1.0/24" {
		t.Fatalf("expected 192.168.1.1 to be allowed after update, got allowed=%v cidr=%s", nowAllowed, cidr)
	}
	nowBlocked, _ := engine.EvaluateIP(net.ParseIP("10.1.2.3"))
	if nowBlocked {
		t.Fatalf("expected 10.1.2.3 to be blocked after update")
	}
}

func BenchmarkRadixTree_LongestPrefixMatch(b *testing.B) {
	tree := NewRadixTree()
	_ = tree.InsertCIDR("10.0.0.0/8")
	_ = tree.InsertCIDR("192.168.0.0/16")
	_ = tree.InsertCIDR("192.168.1.0/24")
	_ = tree.InsertCIDR("172.16.0.0/12")

	ip := net.ParseIP("192.168.1.100")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tree.LongestPrefixMatch(ip)
	}
}
