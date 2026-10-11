package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Awesome06/aegis-proxy/pkg/dns"
	"github.com/Awesome06/aegis-proxy/pkg/l3"
	"github.com/Awesome06/aegis-proxy/pkg/telemetry"
	"github.com/Awesome06/aegis-proxy/pkg/tlsinspector"
)

func TestRelayBidirectional_DataIntegrity(t *testing.T) {
	// Arrange: Create a real local TCP loopback listener and connection pairs
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	payload1 := []byte("hello from client to server")
	payload2 := []byte("hello from server to client")

	// Upstream target listener
	upListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on upstream: %v", err)
	}
	defer upListener.Close()

	// Upstream server routine
	go func() {
		upConn, err := upListener.Accept()
		if err != nil {
			return
		}
		defer upConn.Close()

		buf := make([]byte, len(payload1))
		_, _ = io.ReadFull(upConn, buf)
		_, _ = upConn.Write(payload2)
	}()

	// Proxy relay simulation
	go func() {
		clientConn, err := l.Accept()
		if err != nil {
			return
		}
		defer clientConn.Close()

		upConn, err := net.Dial("tcp", upListener.Addr().String())
		if err != nil {
			return
		}
		defer upConn.Close()

		_, _, _ = RelayBidirectional(clientConn, upConn)
	}()

	// Client connect
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Act: Send client payload
	if _, err := client.Write(payload1); err != nil {
		t.Fatalf("failed to write payload1: %v", err)
	}

	// Read response from upstream through relay
	respBuf := make([]byte, len(payload2))
	if _, err := io.ReadFull(client, respBuf); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	// Assert: Validate exact match
	if !bytes.Equal(respBuf, payload2) {
		t.Fatalf("expected payload %q, got %q", string(payload2), string(respBuf))
	}
}

func TestServer_L3AccessControl(t *testing.T) {
	// Arrange: L3 policy only allows 192.168.100.0/24 (127.0.0.1 is blocked)
	l3Engine, err := l3.NewPolicyEngine([]string{"192.168.100.0/24"})
	if err != nil {
		t.Fatalf("failed to init l3: %v", err)
	}

	dnsResolver := dns.NewResolver(dns.DefaultPublicResolvers, time.Second)
	blacklist := tlsinspector.NewBlacklistFilter(nil)
	logger := telemetry.InitLogger(0)

	cfg := ServerConfig{
		ListenAddr:     "127.0.0.1:0", // random available port
		MaxConnections: 10,
	}
	server := NewServer(cfg, l3Engine, dnsResolver, blacklist, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start(ctx)
	}()

	// Wait for listener to bind
	var boundAddr string
	for i := 0; i < 20; i++ {
		if addr := server.Addr(); addr != nil {
			boundAddr = addr.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if boundAddr == "" {
		t.Fatalf("server failed to bind listener in time")
	}

	// Act: Connect to server from loopback (127.0.0.1 is NOT in allowlist)
	conn, err := net.DialTimeout("tcp", boundAddr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial proxy server: %v", err)
	}

	// Assert: Server should immediately terminate socket before reading
	buf := make([]byte, 10)
	n, readErr := conn.Read(buf)
	if n != 0 || (readErr != io.EOF && readErr == nil) {
		t.Fatalf("expected immediate EOF on blocked connection, got n=%d, err=%v", n, readErr)
	}
	_ = conn.Close()

	_ = server.Shutdown(context.Background())
}

func BenchmarkBufferPool_Cycle(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer()
		PutBuffer(buf)
	}
}
