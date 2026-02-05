package handlers

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/admin/auth"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestAdminAuthLogin(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    repo := fakeUserRepo{
        user: &models.User{
            Username:     "admin",
            Status:       models.UserActive,
            Role:         models.RoleAdmin,
            PasswordHash: string(hash),
        },
    }
    svc := auth.NewService("2fa", []byte("secret"), time.Minute, repo)
    handler := NewAdminAuthHandler(svc)

    body, _ := json.Marshal(dto.AdminLoginRequest{Username: "admin", Password: "pass"})
    req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/login", bytes.NewReader(body))
    rec := httptest.NewRecorder()

    handler.Login(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("status=%d", rec.Code)
    }
}

type fakeUserRepo struct {
    user *models.User
}

func (f fakeUserRepo) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
    if f.user != nil && f.user.Username == username && f.user.Role == role {
        return f.user, nil
    }
    return nil, auth.ErrInvalidCredentials
}

func (f fakeUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
    return nil, auth.ErrInvalidCredentials
}
func (f fakeUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
    return nil, auth.ErrInvalidCredentials
}
func (f fakeUserRepo) List(ctx context.Context, filter repository.UserListFilter, limit, offset int) ([]models.User, int, error) {
    return nil, 0, auth.ErrInvalidCredentials
}
func (f fakeUserRepo) Create(ctx context.Context, u *models.User) error {
    return nil
}
func (f fakeUserRepo) Update(ctx context.Context, u *models.User) error {
    return nil
}
func (f fakeUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
    return nil
}
