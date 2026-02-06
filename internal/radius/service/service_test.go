package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/qmish/2FA/internal/auth/providers"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/radius/protocol"
	"github.com/qmish/2FA/internal/repository"
)

func TestRadiusServiceAccept(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
	challenges := &fakeChallengeRepo{
		active: &models.Challenge{
			ID:        "c1",
			UserID:    "u1",
			Method:    models.MethodOTP,
			Status:    models.ChallengeSent,
			CodeHash:  hashOTP("123456"),
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}
	svc := NewRadiusService(users, challenges, nil, fakeLoginRepo{}, fakeAuditRepo{}, time.Minute)

	req := protocol.AccessRequest{Username: "alice", Password: "pass:123456"}
	resp := svc.HandleAccessRequest(context.Background(), req)
	if resp.Code != AccessAccept {
		t.Fatalf("expected accept, got %s", resp.Code)
	}
}

func TestRadiusServiceOTPRequired(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
	challenges := &fakeChallengeRepo{}
	svc := NewRadiusService(users, challenges, nil, fakeLoginRepo{}, fakeAuditRepo{}, time.Minute)

	req := protocol.AccessRequest{Username: "alice", Password: "pass"}
	resp := svc.HandleAccessRequest(context.Background(), req)
	if resp.Code != AccessReject || resp.Message != "otp_required" {
		t.Fatalf("expected otp_required, got %s", resp.Message)
	}
}

func TestRadiusServiceRejectInvalid(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
	svc := NewRadiusService(users, &fakeChallengeRepo{}, nil, fakeLoginRepo{}, fakeAuditRepo{}, time.Minute)

	req := protocol.AccessRequest{Username: "alice", Password: "bad"}
	resp := svc.HandleAccessRequest(context.Background(), req)
	if resp.Code != AccessReject {
		t.Fatalf("expected reject, got %s", resp.Code)
	}
}

func TestRadiusServicePushRequired(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+70000000000"}}
	challenges := &fakeChallengeRepo{}
	registry := providers.NewRegistry()
	registry.RegisterPush(providers.DefaultPushProvider, providers.NewExpressMobileMock())
	svc := NewRadiusService(users, challenges, registry, fakeLoginRepo{}, fakeAuditRepo{}, time.Minute)

	req := protocol.AccessRequest{Username: "alice", Password: "pass:push"}
	resp := svc.HandleAccessRequest(context.Background(), req)
	if resp.Code != AccessReject || resp.Message != "push_required" {
		t.Fatalf("expected push_required, got %s", resp.Message)
	}
	if challenges.created == nil || challenges.created.Method != models.MethodPush {
		t.Fatalf("expected push challenge, got %+v", challenges.created)
	}
}

func TestRadiusServiceCallRequired(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+70000000000"}}
	challenges := &fakeChallengeRepo{}
	registry := providers.NewRegistry()
	registry.RegisterCall(providers.DefaultCallProvider, providers.NewExpressMobileMock())
	svc := NewRadiusService(users, challenges, registry, fakeLoginRepo{}, fakeAuditRepo{}, time.Minute)

	req := protocol.AccessRequest{Username: "alice", Password: "pass:call"}
	resp := svc.HandleAccessRequest(context.Background(), req)
	if resp.Code != AccessReject || resp.Message != "call_required" {
		t.Fatalf("expected call_required, got %s", resp.Message)
	}
	if challenges.created == nil || challenges.created.Method != models.MethodCall {
		t.Fatalf("expected call challenge, got %+v", challenges.created)
	}
}

func TestRadiusServicePushVerifyCode(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
	challenges := &fakeChallengeRepo{
		active: &models.Challenge{
			ID:        "c1",
			UserID:    "u1",
			Method:    models.MethodPush,
			Status:    models.ChallengeSent,
			CodeHash:  hashOTP("123456"),
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}
	svc := NewRadiusService(users, challenges, nil, fakeLoginRepo{}, fakeAuditRepo{}, time.Minute)

	req := protocol.AccessRequest{Username: "alice", Password: "pass:123456"}
	resp := svc.HandleAccessRequest(context.Background(), req)
	if resp.Code != AccessAccept {
		t.Fatalf("expected accept, got %s", resp.Code)
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
func (f fakeUserRepo) Delete(ctx context.Context, id string) error      { return nil }
func (f fakeUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
	return nil
}

type fakeChallengeRepo struct {
	active  *models.Challenge
	created *models.Challenge
}

func (f *fakeChallengeRepo) GetByID(ctx context.Context, id string) (*models.Challenge, error) {
	return nil, repository.ErrNotFound
}
func (f *fakeChallengeRepo) GetActiveByUserAndMethod(ctx context.Context, userID string, method models.SecondFactorMethod) (*models.Challenge, error) {
	if f.active != nil && f.active.UserID == userID && f.active.Method == method {
		return f.active, nil
	}
	return nil, repository.ErrNotFound
}
func (f *fakeChallengeRepo) Create(ctx context.Context, c *models.Challenge) error {
	f.created = c
	if f.active == nil {
		f.active = c
	}
	return nil
}
func (f *fakeChallengeRepo) UpdateStatus(ctx context.Context, id string, status models.ChallengeStatus) error {
	if f.active != nil && f.active.ID == id {
		f.active.Status = status
	}
	return nil
}
func (f *fakeChallengeRepo) UpdateDelivery(ctx context.Context, id string, providerID string, status models.ChallengeStatus) error {
	if f.active != nil && f.active.ID == id {
		f.active.ProviderID = providerID
		f.active.Status = status
	}
	return nil
}
func (f *fakeChallengeRepo) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
	return 0, nil
}

type fakeLoginRepo struct{}

func (f fakeLoginRepo) Create(ctx context.Context, h *models.LoginHistory) error { return nil }
func (f fakeLoginRepo) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
	return nil, 0, nil
}
func (f fakeLoginRepo) CountFailures(ctx context.Context, userID string, since time.Time) (int, error) {
	return 0, nil
}

type fakeAuditRepo struct{}

func (f fakeAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error { return nil }
func (f fakeAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
	return nil, 0, nil
}

func hashOTP(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
