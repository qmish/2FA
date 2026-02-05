package logger

import (
    "context"
    "log/slog"
    "os"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func New() *slog.Logger {
    return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
    return context.WithValue(ctx, requestIDKey, requestID)
}

func RequestIDFromContext(ctx context.Context) (string, bool) {
    val, ok := ctx.Value(requestIDKey).(string)
    return val, ok
}
