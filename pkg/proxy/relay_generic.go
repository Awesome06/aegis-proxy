//go:build !linux

package proxy

import "net"

// RelayStreams executes bidirectional forwarding using double-buffered sync.Pool slices.
func RelayStreams(client, server net.Conn) (int64, int64, error) {
	return RelayBidirectional(client, server)
}
