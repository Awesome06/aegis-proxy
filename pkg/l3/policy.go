package l3

import (
	"fmt"
	"net"
	"sync/atomic"
)

// PolicyEngine enforces Layer 3 Zero Trust network filtering.
// It uses atomic pointer swaps to guarantee non-blocking, lock-free evaluation
// even during high-frequency rule updates under production traffic.
type PolicyEngine struct {
	activeTree atomic.Pointer[RadixTree]
}

// NewPolicyEngine creates an engine seeded with an initial slice of CIDR blocks.
func NewPolicyEngine(whitelistedCIDRs []string) (*PolicyEngine, error) {
	tree := NewRadixTree()
	for _, cidr := range whitelistedCIDRs {
		if err := tree.InsertCIDR(cidr); err != nil {
			return nil, fmt.Errorf("failed to insert initial CIDR %q: %w", cidr, err)
		}
	}

	engine := &PolicyEngine{}
	engine.activeTree.Store(tree)
	return engine, nil
}

// UpdateRules atomically replaces the current routing table with a newly constructed RadixTree.
// In-flight connection checks proceed concurrently without mutex acquisition or stalling.
func (pe *PolicyEngine) UpdateRules(whitelistedCIDRs []string) error {
	newTree := NewRadixTree()
	for _, cidr := range whitelistedCIDRs {
		if err := newTree.InsertCIDR(cidr); err != nil {
			return fmt.Errorf("failed to insert CIDR %q during rule update: %w", cidr, err)
		}
	}
	pe.activeTree.Store(newTree)
	return nil
}

// EvaluateIP checks if an IP is authorized under the active policy table.
// Returns true if the IP is within an allowed CIDR block, false otherwise.
func (pe *PolicyEngine) EvaluateIP(ip net.IP) (bool, string) {
	tree := pe.activeTree.Load()
	if tree == nil {
		return false, ""
	}
	matchedCIDR, ok := tree.LongestPrefixMatch(ip)
	return ok, matchedCIDR
}

// EvaluateAddr extracts the IP from a net.Addr (e.g. *net.TCPAddr) and evaluates access.
func (pe *PolicyEngine) EvaluateAddr(addr net.Addr) (bool, string) {
	if addr == nil {
		return false, ""
	}
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			ip = net.ParseIP(addr.String())
		} else {
			ip = net.ParseIP(host)
		}
	}
	return pe.EvaluateIP(ip)
}

// RuleCount returns the active number of CIDRs stored in the trie.
func (pe *PolicyEngine) RuleCount() int {
	tree := pe.activeTree.Load()
	if tree == nil {
		return 0
	}
	return tree.Count()
}
