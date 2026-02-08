package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/qmish/2FA/internal/api/metrics"
)

type RedisPinger interface {
	Ping(ctx context.Context) error
}

type HealthHandler struct {
	db        *sql.DB
	redis     RedisPinger
	dbTimeout time.Duration
}

func NewHealthHandler(db *sql.DB, redis RedisPinger, dbTimeout time.Duration) *HealthHandler {
	return &HealthHandler{db: db, redis: redis, dbTimeout: dbTimeout}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK
	dbStatus := "disabled"
	redisStatus := "disabled"

	if h.db != nil {
		ctx := r.Context()
		if h.dbTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, h.dbTimeout)
			defer cancel()
		}
		if err := h.db.PingContext(ctx); err != nil {
			metrics.Default.IncSystemError("db")
			metrics.Default.IncDBPing("error")
			dbStatus = "down"
			status = http.StatusServiceUnavailable
		} else {
			metrics.Default.IncDBPing("success")
			dbStatus = "ok"
		}
	}
	if h.redis != nil {
		if err := h.redis.Ping(r.Context()); err != nil {
			metrics.Default.IncSystemError("redis")
			metrics.Default.IncRedisPing("error")
			redisStatus = "down"
			status = http.StatusServiceUnavailable
		} else {
			metrics.Default.IncRedisPing("success")
			redisStatus = "ok"
		}
	}

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": boolStatus(status == http.StatusOK),
			"db":     dbStatus,
			"redis":  redisStatus,
		})
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		if dbStatus == "down" {
			_, _ = w.Write([]byte("db_unavailable"))
			return
		}
		if redisStatus == "down" {
			_, _ = w.Write([]byte("redis_unavailable"))
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func Health(w http.ResponseWriter, r *http.Request) {
	NewHealthHandler(nil, nil, 0).Health(w, r)
}

func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

func boolStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}
