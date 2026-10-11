package tlsinspector

import (
	"strings"
	"sync/atomic"
)

// BlacklistFilter enforces L7 domain-level blocking based on extracted SNI hostnames.
// It supports both exact domain matching and suffix/wildcard matching (e.g. *.malicious.com).
type BlacklistFilter struct {
	exactDomains atomic.Pointer[map[string]struct{}]
	suffixRules  atomic.Pointer[[]string]
}

// NewBlacklistFilter initializes a filter with a slice of blacklisted domain patterns.
func NewBlacklistFilter(rules []string) *BlacklistFilter {
	filter := &BlacklistFilter{}
	filter.UpdateRules(rules)
	return filter
}

// UpdateRules atomically replaces the current blacklist rules without pausing active lookups.
func (f *BlacklistFilter) UpdateRules(rules []string) {
	exact := make(map[string]struct{})
	var suffixes []string

	for _, rule := range rules {
		normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(rule, ".")))
		if normalized == "" {
			continue
		}
		if strings.HasPrefix(normalized, "*.") {
			suffixes = append(suffixes, strings.TrimPrefix(normalized, "*"))
		} else if strings.HasPrefix(normalized, ".") {
			suffixes = append(suffixes, normalized)
		} else {
			exact[normalized] = struct{}{}
		}
	}

	f.exactDomains.Store(&exact)
	f.suffixRules.Store(&suffixes)
}

// IsBlocked evaluates whether the given hostname matches any blacklisted exact domain or wildcard suffix.
func (f *BlacklistFilter) IsBlocked(hostname string) (bool, string) {
	if hostname == "" {
		return false, ""
	}
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(hostname, ".")))

	// Check exact match
	exactPtr := f.exactDomains.Load()
	if exactPtr != nil {
		if _, exists := (*exactPtr)[normalized]; exists {
			return true, normalized
		}
	}

	// Check suffix match
	suffixesPtr := f.suffixRules.Load()
	if suffixesPtr != nil {
		for _, suffix := range *suffixesPtr {
			if strings.HasSuffix(normalized, suffix) {
				return true, "*" + suffix
			}
		}
	}

	return false, ""
}
