package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/Awesome06/aegis-proxy/pkg/dns"
	"github.com/Awesome06/aegis-proxy/pkg/l3"
	"github.com/Awesome06/aegis-proxy/pkg/telemetry"
	"github.com/Awesome06/aegis-proxy/pkg/tlsinspector"
)

// ServerConfig defines operational configuration for the forward proxy.
type ServerConfig struct {
	ListenAddr      string
	DefaultUpstream string
	MaxConnections  int
	ReadTimeout     time.Duration
	DialTimeout     time.Duration
}

// Server coordinates the multi-layer proxy pipeline:
// L3 Radix Tree Access Control -> L6 TLS/SNI Inspection -> L7 DNS Resolution -> Zero-Allocation Relay.
type Server struct {
	config      ServerConfig
	l3Engine    *l3.PolicyEngine
	dnsResolver *dns.Resolver
	blacklist   *tlsinspector.BlacklistFilter
	logger      *slog.Logger
	semaphore   chan struct{}

	listener net.Listener
	mu       sync.Mutex
	running  bool
	wg       sync.WaitGroup
}

// NewServer initializes a Server with its required policy engines and worker bounds.
func NewServer(
	cfg ServerConfig,
	l3Engine *l3.PolicyEngine,
	dnsResolver *dns.Resolver,
	blacklist *tlsinspector.BlacklistFilter,
	logger *slog.Logger,
) *Server {
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 10000
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Server{
		config:      cfg,
		l3Engine:    l3Engine,
		dnsResolver: dnsResolver,
		blacklist:   blacklist,
		logger:      logger,
		semaphore:   make(chan struct{}, cfg.MaxConnections),
	}
}

// Addr returns the bound network address of the active listener, or nil if not yet started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Start begins accepting TCP connections on the configured listen address until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind tcp listener on %s: %w", s.config.ListenAddr, err)
	}

	s.mu.Lock()
	s.listener = l
	s.running = true
	s.mu.Unlock()

	s.logger.InfoContext(ctx, "proxy_server_started",
		slog.String("listen_addr", s.config.ListenAddr),
		slog.Int("max_workers", s.config.MaxConnections),
		slog.Int("l3_rules", s.l3Engine.RuleCount()),
	)

	// Context cancellation watcher
	go func() {
		<-ctx.Done()
		s.Shutdown(context.Background())
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running {
				return nil // Clean shutdown
			}
			s.logger.WarnContext(ctx, "listener_accept_error", slog.String("error", err.Error()))
			continue
		}

		// Enforce bounded concurrency pool (semaphore)
		select {
		case s.semaphore <- struct{}{}:
			s.wg.Add(1)
			telemetry.GlobalMetrics.TotalConnections.Add(1)
			telemetry.GlobalMetrics.ActiveConnections.Add(1)

			go func(c net.Conn) {
				defer func() {
					<-s.semaphore
					telemetry.GlobalMetrics.ActiveConnections.Add(-1)
					s.wg.Done()
					if r := recover(); r != nil {
						telemetry.LogPanic(ctx, s.logger, "proxy_worker", r, debug.Stack())
					}
				}()
				s.handleConnection(ctx, c)
			}(conn)

		default:
			// Worker pool saturated: reject connection to protect proxy stability
			s.logger.WarnContext(ctx, "worker_pool_saturated_dropping_connection",
				slog.String("remote_addr", conn.RemoteAddr().String()),
			)
			_ = conn.Close()
		}
	}
}

// Shutdown gracefully stops the listener and waits for active relays to terminate.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.mu.Unlock()

	s.logger.InfoContext(ctx, "proxy_server_shutting_down")

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.InfoContext(ctx, "proxy_server_shutdown_complete")
		return nil
	case <-ctx.Done():
		s.logger.WarnContext(ctx, "proxy_server_shutdown_timed_out")
		return ctx.Err()
	}
}

func (s *Server) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	startTime := time.Now()
	clientRemote := clientConn.RemoteAddr()

	// ----------------------------------------------------
	// 1. LAYER 3 ZERO TRUST ACCESS CONTROL
	// ----------------------------------------------------
	allowed, matchedCIDR := s.l3Engine.EvaluateAddr(clientRemote)
	if !allowed {
		telemetry.GlobalMetrics.L3BlockedConnections.Add(1)
		s.logger.WarnContext(ctx, "l3_traffic_blocked",
			slog.String("client_ip", clientRemote.String()),
			slog.String("action", "DROPPED"),
		)
		// Immediately terminate socket without reading payload
		return
	}

	// ----------------------------------------------------
	// 2. BUFFER INITIAL BYTES FOR INSPECTION
	// ----------------------------------------------------
	_ = clientConn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))
	peekBuf := make([]byte, 4096)
	n, err := clientConn.Read(peekBuf)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.logger.DebugContext(ctx, "client_initial_read_failed",
				slog.String("client_ip", clientRemote.String()),
				slog.String("error", err.Error()),
			)
		}
		return
	}
	initialBytes := peekBuf[:n]
	// Reset read deadline for streaming relay
	_ = clientConn.SetReadDeadline(time.Time{})

	var targetHost string
	var targetPort int = 443
	var alpn string

	// ----------------------------------------------------
	// 3. LAYER 6 TLS / SNI & ALPN INSPECTION
	// ----------------------------------------------------
	if tlsinspector.IsTLS(initialBytes) {
		info, err := tlsinspector.ParseClientHello(initialBytes)
		if err == nil && info != nil {
			targetHost = info.SNI
			if len(info.ALPNProtos) > 0 {
				alpn = info.ALPNProtos[0]
			}

			// Check L7 Domain Blacklist
			if s.blacklist != nil && targetHost != "" {
				blocked, rule := s.blacklist.IsBlocked(targetHost)
				if blocked {
					telemetry.GlobalMetrics.L7BlockedDomains.Add(1)
					s.logger.WarnContext(ctx, "l7_domain_blocked",
						slog.String("client_ip", clientRemote.String()),
						slog.String("sni", targetHost),
						slog.String("matched_rule", rule),
						slog.String("action", "DROPPED"),
					)
					return
				}
			}
		}
	}

	// Fallback to default upstream if target host could not be extracted from SNI
	if targetHost == "" {
		if s.config.DefaultUpstream == "" {
			s.logger.WarnContext(ctx, "unroutable_connection_no_sni_no_default_upstream",
				slog.String("client_ip", clientRemote.String()),
			)
			return
		}
		host, portStr, err := net.SplitHostPort(s.config.DefaultUpstream)
		if err != nil {
			targetHost = s.config.DefaultUpstream
			targetPort = 80
		} else {
			targetHost = host
			targetPort, _ = strconv.Atoi(portStr)
		}
	}

	// ----------------------------------------------------
	// 4. LAYER 7 CUSTOM RFC 1035 UDP DNS RESOLUTION
	// ----------------------------------------------------
	var targetIP net.IP
	if ip := net.ParseIP(targetHost); ip != nil {
		targetIP = ip
	} else {
		ips, err := s.dnsResolver.Resolve(ctx, targetHost)
		if err != nil || len(ips) == 0 {
			s.logger.WarnContext(ctx, "dns_resolution_failed",
				slog.String("hostname", targetHost),
				slog.Any("error", err),
			)
			return
		}
		targetIP = ips[0]
	}

	targetAddr := net.JoinHostPort(targetIP.String(), strconv.Itoa(targetPort))

	// ----------------------------------------------------
	// 5. ESTABLISH UPSTREAM TCP RELAY & FORWARD INITIAL BYTES
	// ----------------------------------------------------
	upstreamConn, err := net.DialTimeout("tcp", targetAddr, s.config.DialTimeout)
	if err != nil {
		s.logger.WarnContext(ctx, "upstream_dial_failed",
			slog.String("target_addr", targetAddr),
			slog.String("sni", targetHost),
			slog.String("error", err.Error()),
		)
		return
	}
	defer upstreamConn.Close()

	// Write unaltered initial bytes (replaying ClientHello without decrypting)
	if _, err := upstreamConn.Write(initialBytes); err != nil {
		s.logger.WarnContext(ctx, "failed_to_forward_initial_handshake_bytes",
			slog.String("target_addr", targetAddr),
			slog.String("error", err.Error()),
		)
		return
	}

	// ----------------------------------------------------
	// 6. ZERO-ALLOCATION BIDIRECTIONAL RELAY
	// ----------------------------------------------------
	c2s, s2c, _ := RelayStreams(clientConn, upstreamConn)

	s.logger.InfoContext(ctx, "proxy_relay_completed",
		slog.String("client_ip", clientRemote.String()),
		slog.String("target", targetHost),
		slog.String("target_ip", targetIP.String()),
		slog.String("l3_rule", matchedCIDR),
		slog.String("alpn", alpn),
		slog.Int64("bytes_c2s", c2s),
		slog.Int64("bytes_s2c", s2c),
		slog.Duration("duration_ms", time.Since(startTime)),
	)
}
