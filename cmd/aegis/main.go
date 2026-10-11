package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Awesome06/aegis-proxy/config"
	"github.com/Awesome06/aegis-proxy/pkg/dns"
	"github.com/Awesome06/aegis-proxy/pkg/l3"
	"github.com/Awesome06/aegis-proxy/pkg/proxy"
	"github.com/Awesome06/aegis-proxy/pkg/telemetry"
	"github.com/Awesome06/aegis-proxy/pkg/tlsinspector"
)

func main() {
	configPath := flag.String("config", "config/aegis.json", "Path to JSON configuration file")
	listenAddr := flag.String("listen", "", "TCP listen address override (e.g. :8443)")
	metricsAddr := flag.String("metrics", "", "HTTP metrics address override (e.g. :9090)")
	logLevelStr := flag.String("log-level", "info", "Logging level: debug, info, warn, error")
	flag.Parse()

	// 1. Initialize Structured JSON Logger
	var logLevel slog.Level
	switch *logLevelStr {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger := telemetry.InitLogger(logLevel)

	// 2. Load Configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Warn("failed_to_load_config_file_falling_back_to_defaults",
			slog.String("path", *configPath),
			slog.String("error", err.Error()),
		)
		cfg = config.DefaultConfig()
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *metricsAddr != "" {
		cfg.MetricsAddr = *metricsAddr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 3. Initialize Layer 3 Zero Trust Policy Engine
	l3Engine, err := l3.NewPolicyEngine(cfg.L3WhitelistCIDRs)
	if err != nil {
		logger.Error("failed_to_initialize_l3_policy_engine", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// 4. Initialize Layer 7 Custom RFC 1035 UDP DNS Resolver
	dnsResolver := dns.NewResolver(cfg.DNSUpstreams, cfg.DNSTimeout())
	dnsResolver.Cache().StartActiveEviction(ctx, 30*time.Second)

	// 5. Initialize Layer 6 Domain Blacklist Filter
	blacklistFilter := tlsinspector.NewBlacklistFilter(cfg.L7BlacklistDomains)

	// 6. Start Observability HTTP Server (Optional)
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"UP","service":"aegis-proxy"}`))
		})
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("format") == "prometheus" || strings.Contains(r.Header.Get("Accept"), "text/plain") {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				_, _ = w.Write([]byte(telemetry.GlobalMetrics.PrometheusFormat()))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			snapshot := telemetry.GlobalMetrics.ReadSnapshot()
			_ = json.NewEncoder(w).Encode(snapshot)
		})

		metricsServer := &http.Server{
			Addr:    cfg.MetricsAddr,
			Handler: mux,
		}
		go func() {
			logger.InfoContext(ctx, "metrics_server_started", slog.String("addr", cfg.MetricsAddr))
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.WarnContext(ctx, "metrics_server_error", slog.String("error", err.Error()))
			}
		}()
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			_ = metricsServer.Shutdown(shutdownCtx)
		}()
	}

	// 7. Initialize and Launch Forward Proxy Server
	serverCfg := proxy.ServerConfig{
		ListenAddr:      cfg.ListenAddr,
		DefaultUpstream: cfg.DefaultUpstream,
		MaxConnections:  cfg.MaxConnections,
		ReadTimeout:     cfg.ReadTimeout(),
		DialTimeout:     cfg.DialTimeout(),
	}
	server := proxy.NewServer(serverCfg, l3Engine, dnsResolver, blacklistFilter, logger)

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start(ctx)
	}()

	logger.InfoContext(ctx, "aegis_proxy_initialized_successfully",
		slog.String("listen_addr", cfg.ListenAddr),
		slog.Int("l3_whitelisted_cidrs", l3Engine.RuleCount()),
		slog.Int("l7_blacklisted_domains", len(cfg.L7BlacklistDomains)),
		slog.Any("dns_upstreams", cfg.DNSUpstreams),
	)

	// 8. Handle Graceful Shutdown Signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.InfoContext(ctx, "shutdown_signal_received", slog.String("signal", sig.String()))
		cancel()
	case err := <-serverErrCh:
		if err != nil {
			logger.ErrorContext(ctx, "proxy_server_fatal_error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	shutdownTimeoutCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownTimeoutCtx); err != nil {
		logger.Error("proxy_graceful_shutdown_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	fmt.Println("Aegis proxy terminated cleanly.")
}
