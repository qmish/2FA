package middlewares

import (
    "net/http"
    "time"

    "github.com/qmish/2FA/internal/api/metrics"
)

type statusRecorder struct {
    http.ResponseWriter
    status int
}

func (s *statusRecorder) WriteHeader(code int) {
    s.status = code
    s.ResponseWriter.WriteHeader(code)
}

func Metrics(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
        next.ServeHTTP(rec, r)
        metrics.Default.IncHTTPRequest(r.Method, r.URL.Path, rec.status)
        metrics.Default.ObserveHTTPDuration(r.Method, r.URL.Path, time.Since(start))
    })
}
