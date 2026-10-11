package telemetry

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestMetrics_AtomicOperationsAndSnapshot(t *testing.T) {
	m := &Metrics{}

	// Initial values should be zero
	s0 := m.ReadSnapshot()
	if s0.TotalConnections != 0 || s0.ActiveConnections != 0 {
		t.Fatalf("expected 0 initial metrics, got %v", s0)
	}

	// Mutate counters
	m.TotalConnections.Add(10)
	m.ActiveConnections.Add(5)
	m.ActiveConnections.Add(-2)
	m.L3BlockedConnections.Add(3)
	m.L7BlockedDomains.Add(2)
	m.DNSQueriesTotal.Add(15)
	m.DNSCacheHits.Add(12)
	m.BytesRelayedClientToServer.Add(1024)
	m.BytesRelayedServerToClient.Add(2048)

	// Snapshot check
	s1 := m.ReadSnapshot()
	if s1.TotalConnections != 10 {
		t.Fatalf("expected 10 total connections, got %d", s1.TotalConnections)
	}
	if s1.ActiveConnections != 3 {
		t.Fatalf("expected 3 active connections, got %d", s1.ActiveConnections)
	}
	if s1.L3BlockedConnections != 3 {
		t.Fatalf("expected 3 l3 blocks, got %d", s1.L3BlockedConnections)
	}
	if s1.L7BlockedDomains != 2 {
		t.Fatalf("expected 2 l7 blocks, got %d", s1.L7BlockedDomains)
	}
	if s1.DNSQueriesTotal != 15 {
		t.Fatalf("expected 15 dns queries, got %d", s1.DNSQueriesTotal)
	}
	if s1.DNSCacheHits != 12 {
		t.Fatalf("expected 12 dns hits, got %d", s1.DNSCacheHits)
	}
	if s1.BytesRelayedClientToServer != 1024 {
		t.Fatalf("expected 1024 bytes c2s, got %d", s1.BytesRelayedClientToServer)
	}
	if s1.BytesRelayedServerToClient != 2048 {
		t.Fatalf("expected 2048 bytes s2c, got %d", s1.BytesRelayedServerToClient)
	}

	// Prometheus text export check
	promOutput := m.PrometheusFormat()
	if !strings.Contains(promOutput, "aegis_total_connections_total 10") {
		t.Fatalf("expected prometheus string to contain total connections, got:\n%s", promOutput)
	}
	if !strings.Contains(promOutput, "aegis_active_connections 3") {
		t.Fatalf("expected prometheus string to contain active connections, got:\n%s", promOutput)
	}
}

func TestLogger_InitAndPanicRecovery(t *testing.T) {
	logger := InitLogger(slog.LevelDebug)
	if logger == nil {
		t.Fatalf("expected non-nil logger")
	}

	// Test LogPanic does not crash
	ctx := context.Background()
	LogPanic(ctx, logger, "test_worker", "simulated panic", []byte("dummy stack trace"))
	// Test LogPanic with nil logger uses default
	LogPanic(ctx, nil, "test_worker", "simulated panic", []byte("dummy stack trace"))
}
