package l3

import (
	"errors"
	"fmt"
	"net"
)

var (
	// ErrInvalidCIDR is returned when a CIDR string cannot be parsed.
	ErrInvalidCIDR = errors.New("invalid CIDR notation")
	// ErrIPFamilyMismatch is returned when comparing mismatched IP versions.
	ErrIPFamilyMismatch = errors.New("IP family mismatch (IPv4 vs IPv6)")
)

// radixNode represents an internal or leaf node in the bitwise Patricia trie.
type radixNode struct {
	children [2]*radixNode
	isLeaf   bool
	cidr     string
}

// RadixTree is a high-performance in-memory Patricia Trie for IPv4 and IPv6 CIDR prefix matching.
// Lookups have guaranteed O(k) upper bounds (k=32 for IPv4, k=128 for IPv6) and execute with 0 allocations.
type RadixTree struct {
	rootV4 *radixNode
	rootV6 *radixNode
	count  int
}

// NewRadixTree initializes an empty RadixTree.
func NewRadixTree() *RadixTree {
	return &RadixTree{
		rootV4: &radixNode{},
		rootV6: &radixNode{},
	}
}

// InsertCIDR parses and inserts a CIDR block (e.g., "192.168.1.0/24" or "2001:db8::/32") into the trie.
func (t *RadixTree) InsertCIDR(cidrStr string) error {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidCIDR, cidrStr)
	}

	ones, _ := ipNet.Mask.Size()
	ip4 := ip.To4()
	if ip4 != nil {
		t.insert(t.rootV4, ip4, ones, cidrStr)
	} else {
		ip6 := ip.To16()
		if ip6 == nil {
			return fmt.Errorf("%w: unrecognized IP format", ErrInvalidCIDR)
		}
		t.insert(t.rootV6, ip6, ones, cidrStr)
	}
	t.count++
	return nil
}

func (t *RadixTree) insert(root *radixNode, ipBytes []byte, prefixLen int, cidr string) {
	curr := root
	for bitIdx := 0; bitIdx < prefixLen; bitIdx++ {
		bytePos := bitIdx / 8
		bitPos := 7 - (bitIdx % 8)
		bit := (ipBytes[bytePos] >> bitPos) & 1

		if curr.children[bit] == nil {
			curr.children[bit] = &radixNode{}
		}
		curr = curr.children[bit]
	}
	curr.isLeaf = true
	curr.cidr = cidr
}

// LongestPrefixMatch performs a bitwise search for the longest matching prefix for the provided IP.
// Returns the matched CIDR block and true if whitelisted, or empty string and false if rejected.
// This function operates with zero heap allocations on the hot evaluation path.
func (t *RadixTree) LongestPrefixMatch(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}

	ip4 := ip.To4()
	if ip4 != nil {
		return t.match(t.rootV4, ip4, 32)
	}

	ip6 := ip.To16()
	if ip6 != nil {
		return t.match(t.rootV6, ip6, 128)
	}

	return "", false
}

func (t *RadixTree) match(root *radixNode, ipBytes []byte, maxBits int) (string, bool) {
	curr := root
	var lastMatchedCIDR string
	found := false

	// Check if root itself is a leaf (e.g. 0.0.0.0/0 or ::/0 default route)
	if curr.isLeaf {
		lastMatchedCIDR = curr.cidr
		found = true
	}

	for bitIdx := 0; bitIdx < maxBits; bitIdx++ {
		bytePos := bitIdx / 8
		bitPos := 7 - (bitIdx % 8)
		bit := (ipBytes[bytePos] >> bitPos) & 1

		curr = curr.children[bit]
		if curr == nil {
			break
		}
		if curr.isLeaf {
			lastMatchedCIDR = curr.cidr
			found = true
		}
	}

	return lastMatchedCIDR, found
}

// Contains returns true if the specified IP matches at least one whitelisted CIDR block.
func (t *RadixTree) Contains(ip net.IP) bool {
	_, found := t.LongestPrefixMatch(ip)
	return found
}

// Count returns the number of CIDR rules registered in the trie.
func (t *RadixTree) Count() int {
	return t.count
}
