package handlers

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/admin/auth"
    "github.com/qmish/2FA/internal/dto"
)

func TestAdminAuthLogin(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    svc := auth.NewService("2fa", "admin", string(hash), []byte("secret"), time.Minute)
    handler := NewAdminAuthHandler(svc)

    body, _ := json.Marshal(dto.AdminLoginRequest{Username: "admin", Password: "pass"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d", rec.Code)
    }
}
