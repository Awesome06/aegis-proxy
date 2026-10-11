package proxy

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/Awesome06/aegis-proxy/pkg/telemetry"
)

// RelayBufferSize specifies the optimal 32KB buffer size for TCP stream splicing and chunk copying.
const RelayBufferSize = 32 * 1024

// bufferPool holds pre-allocated 32KB byte buffers to eliminate heap allocations on the hot relay path.
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, RelayBufferSize)
		return &buf
	},
}

// GetBuffer retrieves a 32KB slice from the pool.
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a 32KB slice to the pool.
func PutBuffer(buf *[]byte) {
	if buf != nil {
		bufferPool.Put(buf)
	}
}

// RelayBidirectional streams bytes concurrently between client and server connections using sync.Pool buffers.
// It implements TCP half-close (CloseWrite) to preserve HTTP/1.1 and streaming connection lifecycles.
// Returns (bytesClientToServer, bytesServerToClient, error).
func RelayBidirectional(client, server net.Conn) (int64, int64, error) {
	var clientToServerBytes int64
	var serverToClientBytes int64
	var wg sync.WaitGroup
	wg.Add(2)

	var errClientToServer error
	var errServerToClient error

	// 1. Client -> Server Goroutine
	go func() {
		defer wg.Done()
		bufPtr := GetBuffer()
		defer PutBuffer(bufPtr)

		n, err := io.CopyBuffer(server, client, *bufPtr)
		clientToServerBytes = n
		errClientToServer = err
		telemetry.GlobalMetrics.BytesRelayedClientToServer.Add(uint64(n))

		// Propagate TCP half-close if supported
		if tcpServer, ok := server.(*net.TCPConn); ok {
			_ = tcpServer.CloseWrite()
		}
	}()

	// 2. Server -> Client Goroutine
	go func() {
		defer wg.Done()
		bufPtr := GetBuffer()
		defer PutBuffer(bufPtr)

		n, err := io.CopyBuffer(client, server, *bufPtr)
		serverToClientBytes = n
		errServerToClient = err
		telemetry.GlobalMetrics.BytesRelayedServerToClient.Add(uint64(n))

		// Propagate TCP half-close if supported
		if tcpClient, ok := client.(*net.TCPConn); ok {
			_ = tcpClient.CloseWrite()
		}
	}()

	wg.Wait()

	// Normal connection closure yields nil or net.ErrClosed / io.EOF
	if isNormalClosure(errClientToServer) && isNormalClosure(errServerToClient) {
		return clientToServerBytes, serverToClientBytes, nil
	}
	if errClientToServer != nil && !isNormalClosure(errClientToServer) {
		return clientToServerBytes, serverToClientBytes, errClientToServer
	}
	return clientToServerBytes, serverToClientBytes, errServerToClient
}

func isNormalClosure(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
