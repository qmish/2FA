package middlewares

import (
    "crypto/rand"
    "encoding/hex"
    "net/http"

    "github.com/qmish/2FA/pkg/logger"
)

const RequestIDHeader = "X-Request-ID"

func RequestID(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        reqID := r.Header.Get(RequestIDHeader)
        if reqID == "" {
            reqID = generateID()
        }
        ctx := logger.WithRequestID(r.Context(), reqID)
        w.Header().Set(RequestIDHeader, reqID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func generateID() string {
    buf := make([]byte, 16)
    if _, err := rand.Read(buf); err != nil {
        return "unknown"
    }
    return hex.EncodeToString(buf)
}
