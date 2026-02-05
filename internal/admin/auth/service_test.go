package auth

import (
    "testing"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/dto"
)

func TestAdminLoginAndValidate(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    svc := NewService("2fa", "admin", string(hash), []byte("secret"), time.Minute)

    token, err := svc.Login(nil, dto.AdminLoginRequest{Username: "admin", Password: "pass"})
    if err != nil || token.AccessToken == "" {
        t.Fatalf("login error: %v", err)
    }

    claims, err := svc.ParseClaims(token.AccessToken)
    if err != nil || claims.Role != "admin" {
        t.Fatalf("validate error: %v", err)
    }
}
