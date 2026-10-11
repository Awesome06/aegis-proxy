package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Awesome06/aegis-proxy/pkg/telemetry"
)

// DefaultPublicResolvers defines standard upstream public DNS resolvers.
var DefaultPublicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// Resolver implements a custom Layer 7 DNS resolution engine utilizing raw UDP sockets.
// It bypasses standard OS resolvers, parsing RFC 1035 wire frames and maintaining a concurrent TTL cache.
type Resolver struct {
	upstreamAddrs []string
	cache         *Cache
	timeout       time.Duration
}

// NewResolver initializes a DNS resolver targeting the provided upstream addresses.
func NewResolver(upstreamAddrs []string, timeout time.Duration) *Resolver {
	if len(upstreamAddrs) == 0 {
		upstreamAddrs = DefaultPublicResolvers
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Resolver{
		upstreamAddrs: upstreamAddrs,
		cache:         NewCache(),
		timeout:       timeout,
	}
}

// Cache returns the underlying DNS cache instance.
func (r *Resolver) Cache() *Cache {
	return r.cache
}

// Resolve returns IPv4 and IPv6 addresses for the specified hostname.
// It checks the concurrent TTL cache before querying upstream UDP servers.
func (r *Resolver) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	hostname = strings.TrimSpace(strings.TrimSuffix(hostname, "."))
	if hostname == "" {
		return nil, errors.New("empty hostname provided")
	}

	// 1. Direct IP literal check
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IP{ip}, nil
	}

	// 2. Cache Lookup
	telemetry.GlobalMetrics.DNSQueriesTotal.Add(1)
	if cachedIPs, found := r.cache.Get(hostname); found {
		telemetry.GlobalMetrics.DNSCacheHits.Add(1)
		return cachedIPs, nil
	}

	// 3. Upstream Resolution over Raw UDP
	var lastErr error
	for _, upstream := range r.upstreamAddrs {
		ips, ttl, err := r.queryUDP(ctx, upstream, hostname)
		if err == nil && len(ips) > 0 {
			r.cache.Set(hostname, ips, ttl)
			return ips, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all upstream dns servers failed to resolve %q: %w", hostname, lastErr)
}

func (r *Resolver) queryUDP(ctx context.Context, upstream string, hostname string) ([]net.IP, uint32, error) {
	// Generate random 16-bit transaction ID
	var txBytes [2]byte
	_, _ = rand.Read(txBytes[:])
	txID := binary.BigEndian.Uint16(txBytes[:])

	// Construct RFC 1035 query wire payload for Type A (IPv4)
	queryPayload, err := BuildQuery(txID, hostname, TypeA)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build dns query: %w", err)
	}

	rAddr, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid upstream udp address %s: %w", upstream, err)
	}

	// Establish raw UDP connection
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to dial upstream udp %s: %w", upstream, err)
	}
	defer conn.Close()

	// Apply timeout constraint from context or resolver configuration
	deadline := time.Now().Add(r.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("failed to set udp socket deadline: %w", err)
	}

	// Transmit binary query
	if _, err := conn.Write(queryPayload); err != nil {
		return nil, 0, fmt.Errorf("failed to send udp query packet: %w", err)
	}

	// Read binary response payload
	// Standard UDP DNS responses are capped at 512 bytes (RFC 1035) unless EDNS0 is used
	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read udp dns response: %w", err)
	}

	// Parse wire frame and extract IPs and TTL
	ips, ttl, err := ParseResponse(respBuf[:n], txID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse dns response: %w", err)
	}

	return ips, ttl, nil
}
