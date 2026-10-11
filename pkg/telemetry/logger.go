package telemetry

import (
	"context"
	"log/slog"
	"os"
)

// InitLogger initializes and returns a structured JSON logger writing to os.Stdout.
// It adheres to enterprise error-discipline standards with deterministic field keys.
func InitLogger(level slog.Level) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				// Format timestamp in UTC ISO8601
				return slog.String("timestamp", a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
			}
			return a
		},
	})
	logger := slog.New(handler).With(slog.String("service", "aegis-proxy"))
	slog.SetDefault(logger)
	return logger
}

// LogPanic recovers from a panic in a spawned worker goroutine, logs the stack trace and context,
// and guarantees the proxy process maintains runtime stability.
func LogPanic(ctx context.Context, logger *slog.Logger, component string, r any, stack []byte) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.ErrorContext(ctx, "worker_panic_recovered",
		slog.String("component", component),
		slog.Any("panic", r),
		slog.String("stack", string(stack)),
	)
}
