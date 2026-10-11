package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Awesome06/aegis-proxy/pkg/dns"
	"github.com/Awesome06/aegis-proxy/pkg/l3"
	"github.com/Awesome06/aegis-proxy/pkg/telemetry"
	"github.com/Awesome06/aegis-proxy/pkg/tlsinspector"
)

// Helper to build a minimal synthetic TLS ClientHello frame with SNI
func makeSyntheticClientHello(sni string) []byte {
	var payload []byte
	payload = append(payload, 0x03, 0x03) // Version
	for i := 0; i < 32; i++ {
		payload = append(payload, 0x01) // Random
	}
	payload = append(payload, 0x00)                   // Session ID len 0
	payload = append(payload, 0x00, 0x02, 0xC0, 0x2F) // Cipher Suites
	payload = append(payload, 0x01, 0x00)             // Compression

	var extBytes []byte
	if sni != "" {
		sniBytes := []byte(sni)
		listLen := len(sniBytes) + 3
		var sniData []byte
		sniData = append(sniData, byte(listLen>>8), byte(listLen))
		sniData = append(sniData, 0x00) // host_name
		sniData = append(sniData, byte(len(sniBytes)>>8), byte(len(sniBytes)))
		sniData = append(sniData, sniBytes...)

		extBytes = append(extBytes, 0x00, 0x00) // SNI type
		extBytes = append(extBytes, byte(len(sniData)>>8), byte(len(sniData)))
		extBytes = append(extBytes, sniData...)
	}

	payload = append(payload, byte(len(extBytes)>>8), byte(len(extBytes)))
	payload = append(payload, extBytes...)

	hsLen := len(payload)
	var handshake []byte
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, payload...)

	recLen := len(handshake)
	var record []byte
	record = append(record, 0x16, 0x03, 0x01)
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, handshake...)

	return record
}

func TestRelayBidirectional_DataIntegrity(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	payload1 := []byte("hello from client to server")
	payload2 := []byte("hello from server to client")

	upListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on upstream: %v", err)
	}
	defer upListener.Close()

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

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(payload1); err != nil {
		t.Fatalf("failed to write payload1: %v", err)
	}

	respBuf := make([]byte, len(payload2))
	if _, err := io.ReadFull(client, respBuf); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if !bytes.Equal(respBuf, payload2) {
		t.Fatalf("expected payload %q, got %q", string(payload2), string(respBuf))
	}
}

func TestServer_L3AccessControl(t *testing.T) {
	l3Engine, err := l3.NewPolicyEngine([]string{"192.168.100.0/24"})
	if err != nil {
		t.Fatalf("failed to init l3: %v", err)
	}

	dnsResolver := dns.NewResolver(dns.DefaultPublicResolvers, time.Second)
	blacklist := tlsinspector.NewBlacklistFilter(nil)
	logger := telemetry.InitLogger(0)

	cfg := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		MaxConnections: 10,
	}
	server := NewServer(cfg, l3Engine, dnsResolver, blacklist, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Deterministic wait on server readiness channel - ZERO SLEEP!
	select {
	case <-server.Ready():
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for server to become ready")
	}

	boundAddr := server.Addr().String()

	// Act: Connect to server from loopback (127.0.0.1 is blocked)
	conn, err := net.DialTimeout("tcp", boundAddr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial proxy server: %v", err)
	}

	buf := make([]byte, 10)
	n, readErr := conn.Read(buf)
	if n != 0 || (readErr != io.EOF && readErr == nil) {
		t.Fatalf("expected immediate EOF on blocked connection, got n=%d, err=%v", n, readErr)
	}
	_ = conn.Close()

	_ = server.Shutdown(context.Background())
}

func TestServer_DefaultUpstreamRelay(t *testing.T) {
	// 1. Start mock upstream server
	upListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start upstream: %v", err)
	}
	defer upListener.Close()

	upstreamReq := []byte("plain text request")
	upstreamResp := []byte("plain text response")

	go func() {
		conn, err := upListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(upstreamReq))
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write(upstreamResp)
	}()

	// 2. Start proxy with L3 allowlist containing 127.0.0.1 and default upstream
	l3Engine, err := l3.NewPolicyEngine([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("failed to init l3: %v", err)
	}

	dnsResolver := dns.NewResolver(dns.DefaultPublicResolvers, time.Second)
	blacklist := tlsinspector.NewBlacklistFilter(nil)
	logger := telemetry.InitLogger(0)

	cfg := ServerConfig{
		ListenAddr:      "127.0.0.1:0",
		DefaultUpstream: upListener.Addr().String(),
		MaxConnections:  10,
	}
	server := NewServer(cfg, l3Engine, dnsResolver, blacklist, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	select {
	case <-server.Ready():
	case <-time.After(2 * time.Second):
		t.Fatalf("server failed to get ready")
	}

	// 3. Client connects and sends plain TCP request
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(upstreamReq); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	respBuf := make([]byte, len(upstreamResp))
	if _, err := io.ReadFull(client, respBuf); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if !bytes.Equal(respBuf, upstreamResp) {
		t.Fatalf("expected response %q, got %q", string(upstreamResp), string(respBuf))
	}

	_ = client.Close()
	_ = server.Shutdown(context.Background())
}

func TestServer_SNIBlacklistBlocking(t *testing.T) {
	l3Engine, err := l3.NewPolicyEngine([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("failed to init l3: %v", err)
	}

	dnsResolver := dns.NewResolver(dns.DefaultPublicResolvers, time.Second)
	blacklist := tlsinspector.NewBlacklistFilter([]string{"malware.com"})
	logger := telemetry.InitLogger(0)

	cfg := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		MaxConnections: 10,
	}
	server := NewServer(cfg, l3Engine, dnsResolver, blacklist, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	select {
	case <-server.Ready():
	case <-time.After(2 * time.Second):
		t.Fatalf("server failed to get ready")
	}

	// Client sends ClientHello for blacklisted SNI "malware.com"
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	clientHello := makeSyntheticClientHello("malware.com")
	if _, err := client.Write(clientHello); err != nil {
		t.Fatalf("failed to write ClientHello: %v", err)
	}

	// Server should immediately close connection
	buf := make([]byte, 10)
	n, readErr := client.Read(buf)
	if n != 0 || (readErr != io.EOF && readErr == nil) {
		t.Fatalf("expected EOF on blacklisted SNI, got n=%d, err=%v", n, readErr)
	}

	_ = server.Shutdown(context.Background())
}

func TestServer_WorkerSaturation(t *testing.T) {
	l3Engine, _ := l3.NewPolicyEngine([]string{"127.0.0.1/32"})
	dnsResolver := dns.NewResolver(dns.DefaultPublicResolvers, time.Second)
	blacklist := tlsinspector.NewBlacklistFilter(nil)
	logger := telemetry.InitLogger(0)

	// Set MaxConnections: 1 with short read timeout
	cfg := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		MaxConnections: 1,
		ReadTimeout:    50 * time.Millisecond,
	}
	server := NewServer(cfg, l3Engine, dnsResolver, blacklist, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	select {
	case <-server.Ready():
	case <-time.After(2 * time.Second):
		t.Fatalf("server failed to get ready")
	}

	// 1st client connects and holds open
	c1, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial c1: %v", err)
	}

	// 2nd client connects while c1 occupies the single worker slot
	c2, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		_ = c1.Close()
		t.Fatalf("failed to dial c2: %v", err)
	}

	// c2 should be rejected/dropped by saturated worker pool
	buf := make([]byte, 10)
	n, _ := c2.Read(buf)
	if n != 0 {
		t.Fatalf("expected 0 bytes from dropped c2")
	}
	_ = c2.Close()
	_ = c1.Close() // Explicitly close c1 so handleConnection finishes immediately

	_ = server.Shutdown(context.Background())
}

func TestRelay_HelperBranches(t *testing.T) {
	// 1. isNormalClosure checks
	if !isNormalClosure(nil) {
		t.Fatalf("expected nil error to be normal closure")
	}
	if !isNormalClosure(io.EOF) {
		t.Fatalf("expected io.EOF to be normal closure")
	}
	if !isNormalClosure(net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed to be normal closure")
	}
	if isNormalClosure(errors.New("unexpected network reset")) {
		t.Fatalf("expected custom error to not be normal closure")
	}

	// 2. PutBuffer(nil) does not panic
	PutBuffer(nil)
}

func BenchmarkBufferPool_Cycle(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer()
		PutBuffer(buf)
	}
}
