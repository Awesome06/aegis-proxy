package telemetry

import "sync/atomic"

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
