package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qmish/2FA/internal/api/handlers"
	"github.com/qmish/2FA/internal/auth/service"
	"github.com/qmish/2FA/internal/dto"
)

func TestPasskeyLoginRateLimitMiddleware(t *testing.T) {
	svc := &service.MockAuthService{
		BeginPasskeyLoginFunc: func(ctx context.Context) (dto.PasskeyLoginBeginResponse, error) {
			return dto.PasskeyLoginBeginResponse{Options: []byte(`{}`), SessionID: "s1"}, nil
		},
		FinishPasskeyLoginFunc: func(ctx context.Context, sessionID string, credential json.RawMessage, ip string, userAgent string) (dto.TokenPair, error) {
			return dto.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresIn: 1}, nil
		},
	}
	authHandler := handlers.NewAuthHandler(svc)
	routes := Routes{
		Auth: authHandler,
		AuthRateLimit: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-RateLimit", "auth")
				next.ServeHTTP(w, r)
			})
		},
		VerifyRateLimit: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-RateLimit", "verify")
				next.ServeHTTP(w, r)
			})
		},
	}
	handler := New(routes)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/login/begin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("X-RateLimit") != "auth" {
		t.Fatalf("expected auth rate limit middleware")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/login/finish", strings.NewReader(`{"session_id":"s1","credential":{"id":"c1"}}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("User-Agent", "ua")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("X-RateLimit") != "verify" {
		t.Fatalf("expected verify rate limit middleware")
	}
}
