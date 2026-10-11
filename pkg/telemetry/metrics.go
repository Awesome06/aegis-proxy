package telemetry

import (
	"strconv"
	"sync/atomic"
)

// Metrics holds lock-free atomic telemetry counters across all proxy layers.
type Metrics struct {
	TotalConnections           atomic.Uint64
	ActiveConnections          atomic.Int64
	L3BlockedConnections       atomic.Uint64
	L7BlockedDomains           atomic.Uint64
	DNSQueriesTotal            atomic.Uint64
	DNSCacheHits               atomic.Uint64
	BytesRelayedClientToServer atomic.Uint64
	BytesRelayedServerToClient atomic.Uint64
}

// GlobalMetrics is the singleton metrics tracker instance for Aegis.
var GlobalMetrics = &Metrics{}

// Snapshot captures a point-in-time immutable copy of the active metrics.
type Snapshot struct {
	TotalConnections           uint64 `json:"total_connections"`
	ActiveConnections          int64  `json:"active_connections"`
	L3BlockedConnections       uint64 `json:"l3_blocked_connections"`
	L7BlockedDomains           uint64 `json:"l7_blocked_domains"`
	DNSQueriesTotal            uint64 `json:"dns_queries_total"`
	DNSCacheHits               uint64 `json:"dns_cache_hits"`
	BytesRelayedClientToServer uint64 `json:"bytes_relayed_client_to_server"`
	BytesRelayedServerToClient uint64 `json:"bytes_relayed_server_to_client"`
}

// ReadSnapshot extracts current atomic counters into a serializable Snapshot struct.
func (m *Metrics) ReadSnapshot() Snapshot {
	return Snapshot{
		TotalConnections:           m.TotalConnections.Load(),
		ActiveConnections:          m.ActiveConnections.Load(),
		L3BlockedConnections:       m.L3BlockedConnections.Load(),
		L7BlockedDomains:           m.L7BlockedDomains.Load(),
		DNSQueriesTotal:            m.DNSQueriesTotal.Load(),
		DNSCacheHits:               m.DNSCacheHits.Load(),
		BytesRelayedClientToServer: m.BytesRelayedClientToServer.Load(),
		BytesRelayedServerToClient: m.BytesRelayedServerToClient.Load(),
	}
}

// PrometheusFormat serializes active metrics into standard Prometheus text exposition format.
func (m *Metrics) PrometheusFormat() string {
	s := m.ReadSnapshot()
	return "# HELP aegis_total_connections_total Total number of accepted connections.\n" +
		"# TYPE aegis_total_connections_total counter\n" +
		"aegis_total_connections_total " + formatUint(s.TotalConnections) + "\n" +
		"# HELP aegis_active_connections Current active in-flight connections.\n" +
		"# TYPE aegis_active_connections gauge\n" +
		"aegis_active_connections " + formatInt(s.ActiveConnections) + "\n" +
		"# HELP aegis_l3_blocked_connections_total Number of connections dropped by L3 CIDR policy.\n" +
		"# TYPE aegis_l3_blocked_connections_total counter\n" +
		"aegis_l3_blocked_connections_total " + formatUint(s.L3BlockedConnections) + "\n" +
		"# HELP aegis_l7_blocked_domains_total Number of connections terminated by L7 SNI blacklist.\n" +
		"# TYPE aegis_l7_blocked_domains_total counter\n" +
		"aegis_l7_blocked_domains_total " + formatUint(s.L7BlockedDomains) + "\n" +
		"# HELP aegis_dns_queries_total Total number of DNS resolution requests.\n" +
		"# TYPE aegis_dns_queries_total counter\n" +
		"aegis_dns_queries_total " + formatUint(s.DNSQueriesTotal) + "\n" +
		"# HELP aegis_dns_cache_hits_total Number of DNS queries served from TTL cache.\n" +
		"# TYPE aegis_dns_cache_hits_total counter\n" +
		"aegis_dns_cache_hits_total " + formatUint(s.DNSCacheHits) + "\n" +
		"# HELP aegis_bytes_relayed_client_to_server_total Bytes forwarded from client to upstream.\n" +
		"# TYPE aegis_bytes_relayed_client_to_server_total counter\n" +
		"aegis_bytes_relayed_client_to_server_total " + formatUint(s.BytesRelayedClientToServer) + "\n" +
		"# HELP aegis_bytes_relayed_server_to_client_total Bytes forwarded from upstream to client.\n" +
		"# TYPE aegis_bytes_relayed_server_to_client_total counter\n" +
		"aegis_bytes_relayed_server_to_client_total " + formatUint(s.BytesRelayedServerToClient) + "\n"
}

func formatUint(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func formatInt(v int64) string {
	return strconv.FormatInt(v, 10)
}
