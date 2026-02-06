package handlers

import (
    "net/http"

    "github.com/qmish/2FA/internal/api/metrics"
)

func Metrics(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; version=0.0.4")
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte(metrics.Default.Render()))
}
