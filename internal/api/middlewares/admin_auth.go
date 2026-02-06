package middlewares

import (
    "context"
    "net/http"
    "strings"

    "github.com/qmish/2FA/internal/models"
)

type AdminClaims struct {
    UserID string
    Role   string
}

type AdminTokenValidator interface {
    ParseClaims(token string) (*AdminClaims, error)
}

func AdminAuth(validator AdminTokenValidator) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            header := r.Header.Get("Authorization")
            if !strings.HasPrefix(header, "Bearer ") {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            token := strings.TrimPrefix(header, "Bearer ")
            claims, err := validator.ParseClaims(token)
            if err != nil {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            // Проверяем, что роль пользователя - admin
            if claims.Role != string(models.RoleAdmin) {
                w.WriteHeader(http.StatusForbidden)
                return
            }
            ctx := context.WithValue(r.Context(), adminClaimsKey{}, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

type adminClaimsKey struct{}

func AdminClaimsFromContext(ctx context.Context) (*AdminClaims, bool) {
    claims, ok := ctx.Value(adminClaimsKey{}).(*AdminClaims)
    return claims, ok
}

func WithAdminClaims(ctx context.Context, claims *AdminClaims) context.Context {
    return context.WithValue(ctx, adminClaimsKey{}, claims)
}
