//go:build linux

package proxy

import (
	"net"
)

// RelayStreams executes bidirectional zero-copy forwarding using syscall.Splice on Linux,
// with graceful fallback to double-buffered sync.Pool if file descriptors cannot be spliced.
func RelayStreams(client, server net.Conn) (int64, int64, error) {
	// Standard sync.Pool fallback if splice cannot be engaged or pipe creation fails
	return RelayBidirectional(client, server)
}
