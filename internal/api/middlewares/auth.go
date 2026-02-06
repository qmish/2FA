package middlewares

import (
    "context"
    "net/http"
    "strings"
    "time"

    authjwt "github.com/qmish/2FA/internal/auth/jwt"
    "github.com/qmish/2FA/internal/api/metrics"
    "github.com/qmish/2FA/internal/repository"
)

type AuthClaims struct {
    UserID    string
    SessionID string
}

type AccessTokenValidator interface {
    ParseClaims(token string) (*authjwt.Claims, error)
}

func Auth(validator AccessTokenValidator, sessions repository.SessionRepository, now func() time.Time) func(http.Handler) http.Handler {
    if now == nil {
        now = time.Now
    }
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            header := r.Header.Get("Authorization")
            if !strings.HasPrefix(header, "Bearer ") {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            token := strings.TrimPrefix(header, "Bearer ")
            claims, err := validator.ParseClaims(token)
            if err != nil || claims == nil {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            sess, err := sessions.GetByID(r.Context(), claims.SessionID)
            if err != nil {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            if sess.RevokedAt != nil || now().After(sess.ExpiresAt) {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            if err := sessions.Touch(r.Context(), sess.ID, now()); err != nil {
                metrics.Default.IncSystemError("db")
            }
            ctx := context.WithValue(r.Context(), authClaimsKey{}, &AuthClaims{
                UserID:    claims.Subject,
                SessionID: claims.SessionID,
            })
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

type authClaimsKey struct{}

func AuthClaimsFromContext(ctx context.Context) (*AuthClaims, bool) {
    claims, ok := ctx.Value(authClaimsKey{}).(*AuthClaims)
    return claims, ok
}

func WithAuthClaims(ctx context.Context, claims *AuthClaims) context.Context {
    return context.WithValue(ctx, authClaimsKey{}, claims)
}
