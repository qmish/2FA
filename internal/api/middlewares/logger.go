package middlewares

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/qmish/2FA/pkg/logger"
	"go.opentelemetry.io/otel/trace"
)

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		reqID, _ := logger.RequestIDFromContext(r.Context())
		span := trace.SpanFromContext(r.Context())
		traceID := ""
		if span.SpanContext().IsValid() {
			traceID = span.SpanContext().TraceID().String()
		}
		slog.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", reqID,
			"trace_id", traceID,
		)
	})
}
