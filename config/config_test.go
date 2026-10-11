package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ListenAddr != ":8443" {
		t.Fatalf("expected listen_addr :8443, got %s", cfg.ListenAddr)
	}
	if cfg.MaxConnections != 10000 {
		t.Fatalf("expected max_connections 10000, got %d", cfg.MaxConnections)
	}
	if len(cfg.DNSUpstreams) != 2 {
		t.Fatalf("expected 2 default dns upstreams, got %d", len(cfg.DNSUpstreams))
	}
	if cfg.ReadTimeout() != 5*time.Second {
		t.Fatalf("expected 5s read timeout, got %v", cfg.ReadTimeout())
	}
	if cfg.DialTimeout() != 5*time.Second {
		t.Fatalf("expected 5s dial timeout, got %v", cfg.DialTimeout())
	}
	if cfg.DNSTimeout() != 2*time.Second {
		t.Fatalf("expected 2s dns timeout, got %v", cfg.DNSTimeout())
	}
}

func TestLoadConfig_SuccessAndOverrides(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_aegis.json")

	content := []byte(`{
		"listen_addr": ":9443",
		"max_connections": 500,
		"read_timeout_seconds": 10,
		"dial_timeout_seconds": 12,
		"dns_timeout_seconds": 4,
		"l3_whitelist_cidrs": ["10.10.0.0/16"],
		"l7_blacklist_domains": ["bad.com"]
	}`)

	if err := os.WriteFile(configPath, content, 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.ListenAddr != ":9443" {
		t.Fatalf("expected :9443, got %s", cfg.ListenAddr)
	}
	if cfg.MaxConnections != 500 {
		t.Fatalf("expected 500, got %d", cfg.MaxConnections)
	}
	if cfg.ReadTimeout() != 10*time.Second {
		t.Fatalf("expected 10s, got %v", cfg.ReadTimeout())
	}
	if cfg.DialTimeout() != 12*time.Second {
		t.Fatalf("expected 12s, got %v", cfg.DialTimeout())
	}
	if cfg.DNSTimeout() != 4*time.Second {
		t.Fatalf("expected 4s, got %v", cfg.DNSTimeout())
	}
}

func TestLoadConfig_ErrorsAndFallbacks(t *testing.T) {
	// Empty path should return DefaultConfig without error
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("expected nil error on empty path, got %v", err)
	}
	if cfg.ListenAddr != ":8443" {
		t.Fatalf("expected default config, got %v", cfg)
	}

	// Non-existent file
	_, err = LoadConfig("non_existent_file.json")
	if err == nil {
		t.Fatalf("expected error for non-existent file")
	}

	// Malformed JSON
	tempDir := t.TempDir()
	badPath := filepath.Join(tempDir, "bad.json")
	_ = os.WriteFile(badPath, []byte(`{ invalid json`), 0600)
	_, err = LoadConfig(badPath)
	if err == nil {
		t.Fatalf("expected error for malformed json")
	}

	// Zero/negative timeout fallback tests
	zeroCfg := Config{
		ReadTimeoutSeconds: 0,
		DialTimeoutSeconds: -1,
		DNSTimeoutSeconds:  0,
	}
	if zeroCfg.ReadTimeout() != 5*time.Second {
		t.Fatalf("expected fallback 5s read timeout, got %v", zeroCfg.ReadTimeout())
	}
	if zeroCfg.DialTimeout() != 5*time.Second {
		t.Fatalf("expected fallback 5s dial timeout, got %v", zeroCfg.DialTimeout())
	}
	if zeroCfg.DNSTimeout() != 2*time.Second {
		t.Fatalf("expected fallback 2s dns timeout, got %v", zeroCfg.DNSTimeout())
	}
}
