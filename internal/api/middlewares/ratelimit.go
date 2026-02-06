package middlewares

import (
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/qmish/2FA/internal/api/metrics"
    "github.com/qmish/2FA/internal/ratelimit"
)

func RateLimit(client *ratelimit.RedisClient, name string, limit int, window time.Duration) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if client == nil || limit <= 0 {
                next.ServeHTTP(w, r)
                return
            }
            key := "rl:" + name + ":" + clientIP(r)
            count, err := client.IncrWithExpire(r.Context(), key, window)
            if err != nil {
                metrics.Default.IncSystemError("redis")
            }
            if err == nil && count > int64(limit) {
                w.WriteHeader(http.StatusTooManyRequests)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

func clientIP(r *http.Request) string {
    forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
    if forwarded != "" {
        parts := strings.Split(forwarded, ",")
        if len(parts) > 0 {
            return strings.TrimSpace(parts[0])
        }
    }
    host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
    if err == nil && host != "" {
        return host
    }
    return strings.TrimSpace(r.RemoteAddr)
}
