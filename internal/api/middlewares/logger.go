package middlewares

import (
    "log/slog"
    "net/http"
    "time"

    "github.com/qmish/2FA/pkg/logger"
)

func RequestLogger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
        next.ServeHTTP(rec, r)
        reqID, _ := logger.RequestIDFromContext(r.Context())
        slog.Info("http_request",
            "method", r.Method,
            "path", r.URL.Path,
            "status", rec.status,
            "duration_ms", time.Since(start).Milliseconds(),
            "request_id", reqID,
        )
    })
}
