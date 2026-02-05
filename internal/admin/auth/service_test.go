package auth

import (
    "context"
    "testing"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestAdminLoginAndValidate(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    repo := fakeUserRepo{
        user: &models.User{
            Username:     "admin",
            Status:       models.UserActive,
            Role:         models.RoleAdmin,
            PasswordHash: string(hash),
        },
    }
    svc := NewService("2fa", []byte("secret"), time.Minute, repo)

    token, err := svc.Login(nil, dto.AdminLoginRequest{Username: "admin", Password: "pass"})
    if err != nil || token.AccessToken == "" {
        t.Fatalf("login error: %v", err)
    }

    claims, err := svc.ParseClaims(token.AccessToken)
    if err != nil || claims.Role != "admin" {
        t.Fatalf("validate error: %v", err)
    }
}

type fakeUserRepo struct {
    user *models.User
}

func (f fakeUserRepo) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
    if f.user != nil && f.user.Username == username && f.user.Role == role {
        return f.user, nil
    }
    return nil, ErrInvalidCredentials
}

func (f fakeUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
    return nil, ErrInvalidCredentials
}
func (f fakeUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
    return nil, ErrInvalidCredentials
}
func (f fakeUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    return nil, ErrInvalidCredentials
}
func (f fakeUserRepo) GetByPhone(ctx context.Context, phone string) (*models.User, error) {
    return nil, ErrInvalidCredentials
}
func (f fakeUserRepo) List(ctx context.Context, filter repository.UserListFilter, limit, offset int) ([]models.User, int, error) {
    return nil, 0, ErrInvalidCredentials
}
func (f fakeUserRepo) Create(ctx context.Context, u *models.User) error {
    return nil
}
func (f fakeUserRepo) Update(ctx context.Context, u *models.User) error {
    return nil
}
func (f fakeUserRepo) Delete(ctx context.Context, id string) error {
    return nil
}
func (f fakeUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
    return nil
}
