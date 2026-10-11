package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config defines the runtime configuration schema for Aegis.
type Config struct {
	ListenAddr          string   `json:"listen_addr"`
	DefaultUpstream     string   `json:"default_upstream"`
	MaxConnections      int      `json:"max_connections"`
	ReadTimeoutSeconds  int      `json:"read_timeout_seconds"`
	DialTimeoutSeconds  int      `json:"dial_timeout_seconds"`
	DNSUpstreams        []string `json:"dns_upstreams"`
	DNSTimeoutSeconds   int      `json:"dns_timeout_seconds"`
	L3WhitelistCIDRs    []string `json:"l3_whitelist_cidrs"`
	L7BlacklistDomains  []string `json:"l7_blacklist_domains"`
	MetricsAddr         string   `json:"metrics_addr"`
}

// DefaultConfig returns a secure out-of-the-box configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:         ":8443",
		DefaultUpstream:    "",
		MaxConnections:     10000,
		ReadTimeoutSeconds: 5,
		DialTimeoutSeconds: 5,
		DNSUpstreams:       []string{"1.1.1.1:53", "8.8.8.8:53"},
		DNSTimeoutSeconds:  2,
		L3WhitelistCIDRs: []string{
			"127.0.0.1/32",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"::1/128",
			"fe80::/10",
		},
		L7BlacklistDomains: []string{
			"malware.com",
			"*.evil-tracker.net",
			".crypto-miner.org",
		},
		MetricsAddr: ":9090",
	}
}

// LoadConfig reads and unmarshals a JSON configuration file.
func LoadConfig(filePath string) (Config, error) {
	cfg := DefaultConfig()
	if filePath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return cfg, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse JSON config in %q: %w", filePath, err)
	}

	return cfg, nil
}

// ReadTimeout returns the configured read timeout as time.Duration.
func (c *Config) ReadTimeout() time.Duration {
	if c.ReadTimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.ReadTimeoutSeconds) * time.Second
}

// DialTimeout returns the configured dial timeout as time.Duration.
func (c *Config) DialTimeout() time.Duration {
	if c.DialTimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.DialTimeoutSeconds) * time.Second
}

// DNSTimeout returns the configured DNS timeout as time.Duration.
func (c *Config) DNSTimeout() time.Duration {
	if c.DNSTimeoutSeconds <= 0 {
		return 2 * time.Second
	}
	return time.Duration(c.DNSTimeoutSeconds) * time.Second
}
