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

func TestRadixTree_EdgeCasesAndErrors(t *testing.T) {
	tree := NewRadixTree()

	// 1. Invalid CIDR notation
	err := tree.InsertCIDR("not-a-cidr")
	if err == nil {
		t.Fatalf("expected error on invalid CIDR")
	}

	// 2. Count verification
	if tree.Count() != 0 {
		t.Fatalf("expected count 0, got %d", tree.Count())
	}
	_ = tree.InsertCIDR("10.0.0.0/8")
	if tree.Count() != 1 {
		t.Fatalf("expected count 1, got %d", tree.Count())
	}

	// 3. Nil IP lookup
	_, ok := tree.LongestPrefixMatch(nil)
	if ok {
		t.Fatalf("expected false on nil IP")
	}
	if tree.Contains(nil) {
		t.Fatalf("expected Contains(nil) to be false")
	}

	// 4. Default Route 0.0.0.0/0
	defaultTree := NewRadixTree()
	_ = defaultTree.InsertCIDR("0.0.0.0/0")
	matched, found := defaultTree.LongestPrefixMatch(net.ParseIP("203.0.113.1"))
	if !found || matched != "0.0.0.0/0" {
		t.Fatalf("expected default route match for 203.0.113.1, got %s, found=%v", matched, found)
	}

	// 5. Default Route ::/0
	defaultV6Tree := NewRadixTree()
	_ = defaultV6Tree.InsertCIDR("::/0")
	matched6, found6 := defaultV6Tree.LongestPrefixMatch(net.ParseIP("2001:db8::1"))
	if !found6 || matched6 != "::/0" {
		t.Fatalf("expected default v6 route match, got %s, found=%v", matched6, found6)
	}
}

func TestPolicyEngine_EvaluateAddrVariants(t *testing.T) {
	engine, err := NewPolicyEngine([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	// 1. Nil address
	ok, _ := engine.EvaluateAddr(nil)
	if ok {
		t.Fatalf("expected nil addr to be rejected")
	}

	// 2. TCPAddr
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.5"), Port: 12345}
	ok, _ = engine.EvaluateAddr(tcpAddr)
	if !ok {
		t.Fatalf("expected TCPAddr 192.168.1.5 to be allowed")
	}

	// 3. UDPAddr
	udpAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.6"), Port: 53}
	ok, _ = engine.EvaluateAddr(udpAddr)
	if !ok {
		t.Fatalf("expected UDPAddr 192.168.1.6 to be allowed")
	}

	// 4. IPAddr
	ipAddr := &net.IPAddr{IP: net.ParseIP("192.168.1.7")}
	ok, _ = engine.EvaluateAddr(ipAddr)
	if !ok {
		t.Fatalf("expected IPAddr 192.168.1.7 to be allowed")
	}

	// 5. Custom string addr with port
	pipeAddr := customAddr("192.168.1.8:8080")
	ok, _ = engine.EvaluateAddr(pipeAddr)
	if !ok {
		t.Fatalf("expected string addr with port to be allowed")
	}

	// 6. Custom string addr without port
	rawAddr := customAddr("192.168.1.9")
	ok, _ = engine.EvaluateAddr(rawAddr)
	if !ok {
		t.Fatalf("expected raw string addr without port to be allowed")
	}

	// 7. RuleCount
	if engine.RuleCount() != 1 {
		t.Fatalf("expected rule count 1, got %d", engine.RuleCount())
	}

	// 8. NewPolicyEngine with invalid initial CIDR
	_, err = NewPolicyEngine([]string{"invalid"})
	if err == nil {
		t.Fatalf("expected error from NewPolicyEngine with invalid CIDR")
	}

	// 9. UpdateRules with invalid CIDR
	err = engine.UpdateRules([]string{"invalid"})
	if err == nil {
		t.Fatalf("expected error from UpdateRules with invalid CIDR")
	}
}

type customAddr string

func (a customAddr) Network() string { return "custom" }
func (a customAddr) String() string  { return string(a) }

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

