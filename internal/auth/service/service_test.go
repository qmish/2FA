package service

import (
    "context"
    "testing"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestAuthLoginVerify(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
    challenges := &fakeChallengeRepo{}
    sessions := &fakeSessionRepo{}

    svc := NewService(users, challenges, sessions, nil, time.Minute, time.Hour)
    svc.codeGen = func() string { return "123456" }

    loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
    if err != nil {
        t.Fatalf("login error: %v", err)
    }
    if loginResp.ChallengeID == "" {
        t.Fatalf("missing challenge id")
    }

    verifyResp, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
        UserID:      "u1",
        ChallengeID: loginResp.ChallengeID,
        Method:      models.MethodOTP,
        Code:        "123456",
    })
    if err != nil {
        t.Fatalf("verify error: %v", err)
    }
    if verifyResp.AccessToken == "" || verifyResp.RefreshToken == "" {
        t.Fatalf("missing tokens")
    }

    refreshed, err := svc.Refresh(context.Background(), dto.RefreshRequest{RefreshToken: verifyResp.RefreshToken})
    if err != nil || refreshed.AccessToken == "" {
        t.Fatalf("refresh error: %v", err)
    }
}

type fakeUserRepo struct {
    user *models.User
}

func (f fakeUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
    return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
    if f.user != nil && f.user.Username == username {
        return f.user, nil
    }
    return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
    return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByPhone(ctx context.Context, phone string) (*models.User, error) {
    return nil, repository.ErrNotFound
}
func (f fakeUserRepo) List(ctx context.Context, filter repository.UserListFilter, limit, offset int) ([]models.User, int, error) {
    return nil, 0, nil
}
func (f fakeUserRepo) Create(ctx context.Context, u *models.User) error { return nil }
func (f fakeUserRepo) Update(ctx context.Context, u *models.User) error { return nil }
func (f fakeUserRepo) Delete(ctx context.Context, id string) error { return nil }
func (f fakeUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error { return nil }

type fakeChallengeRepo struct {
    items map[string]challengeItem
}

type challengeItem struct {
    models.Challenge
    plainCode string
}

func (f *fakeChallengeRepo) GetByID(ctx context.Context, id string) (*models.Challenge, error) {
    if f.items == nil {
        return nil, repository.ErrNotFound
    }
    item, ok := f.items[id]
    if !ok {
        return nil, repository.ErrNotFound
    }
    return &item.Challenge, nil
}
func (f *fakeChallengeRepo) Create(ctx context.Context, c *models.Challenge) error {
    if f.items == nil {
        f.items = map[string]challengeItem{}
    }
    f.items[c.ID] = challengeItem{Challenge: *c, plainCode: ""} // plainCode set below
    return nil
}
func (f *fakeChallengeRepo) UpdateStatus(ctx context.Context, id string, status models.ChallengeStatus) error {
    item := f.items[id]
    item.Status = status
    f.items[id] = item
    return nil
}
func (f *fakeChallengeRepo) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
    return 0, nil
}

type fakeSessionRepo struct {
    items map[string]models.UserSession
}

func (f *fakeSessionRepo) Create(ctx context.Context, s *models.UserSession) error {
    if f.items == nil {
        f.items = map[string]models.UserSession{}
    }
    f.items[s.RefreshTokenHash] = *s
    return nil
}
func (f *fakeSessionRepo) Revoke(ctx context.Context, id string, revokedAt time.Time) error { return nil }
func (f *fakeSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
    s, ok := f.items[hash]
    if !ok {
        return nil, repository.ErrNotFound
    }
    return &s, nil
}
