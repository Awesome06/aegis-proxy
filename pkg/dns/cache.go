package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// cacheEntry holds resolved IP addresses and expiration timestamp.
type cacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
	ttl       uint32
}

// Cache provides a concurrent TTL-aware cache for DNS lookups.
type Cache struct {
	mu      sync.RWMutex
	records map[string]cacheEntry
}

// NewCache initializes an empty DNS cache.
func NewCache() *Cache {
	return &Cache{
		records: make(map[string]cacheEntry),
	}
}

// Get retrieves cached IPs for a given hostname if not expired.
func (c *Cache) Get(hostname string) ([]net.IP, bool) {
	key := strings.ToLower(strings.TrimSuffix(hostname, "."))
	c.mu.RLock()
	entry, exists := c.records[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		// Asynchronously or lazily clean up expired entry
		go c.delete(key)
		return nil, false
	}

	// Return a copy to prevent external mutation
	result := make([]net.IP, len(entry.ips))
	copy(result, entry.ips)
	return result, true
}

// Set stores resolved IPs with the specified TTL in seconds.
func (c *Cache) Set(hostname string, ips []net.IP, ttl uint32) {
	if len(ips) == 0 {
		return
	}
	key := strings.ToLower(strings.TrimSuffix(hostname, "."))
	entry := cacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
		ttl:       ttl,
	}

	c.mu.Lock()
	c.records[key] = entry
	c.mu.Unlock()
}

func (c *Cache) delete(key string) {
	c.mu.Lock()
	delete(c.records, key)
	c.mu.Unlock()
}

// PurgeExpired removes all stale records from the cache.
func (c *Cache) PurgeExpired() int {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	purged := 0
	for key, entry := range c.records {
		if now.After(entry.expiresAt) {
			delete(c.records, key)
			purged++
		}
	}
	return purged
}

// Len returns the current count of active cache records.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.records)
}

// StartActiveEviction runs a background ticker to periodically purge expired records.
func (c *Cache) StartActiveEviction(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.PurgeExpired()
			}
		}
	}()
}
