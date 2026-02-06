package handlers

import (
    "context"
    "database/sql"
    "net/http"

    "github.com/qmish/2FA/internal/api/metrics"
)

type RedisPinger interface {
    Ping(ctx context.Context) error
}

type HealthHandler struct {
    db *sql.DB
    redis RedisPinger
}

func NewHealthHandler(db *sql.DB, redis RedisPinger) *HealthHandler {
    return &HealthHandler{db: db, redis: redis}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
    if h.db != nil {
        if err := h.db.PingContext(r.Context()); err != nil {
            metrics.Default.IncSystemError("db")
            w.WriteHeader(http.StatusServiceUnavailable)
            _, _ = w.Write([]byte("db_unavailable"))
            return
        }
    }
    if h.redis != nil {
        if err := h.redis.Ping(r.Context()); err != nil {
            metrics.Default.IncSystemError("redis")
            w.WriteHeader(http.StatusServiceUnavailable)
            _, _ = w.Write([]byte("redis_unavailable"))
            return
        }
    }
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
}

func Health(w http.ResponseWriter, r *http.Request) {
    NewHealthHandler(nil, nil).Health(w, r)
}
