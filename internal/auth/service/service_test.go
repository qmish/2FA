package service

import (
    "context"
    "errors"
    "testing"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/auth/jwt"
    "github.com/qmish/2FA/internal/auth/providers"
    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestAuthLoginVerify(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}

    jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
    svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	if loginResp.ChallengeID == "" {
		t.Fatalf("missing challenge id")
	}
	if loginResp.Status != models.ChallengeCreated {
		t.Fatalf("unexpected challenge status: %v", loginResp.Status)
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

	refreshed, err := svc.Refresh(context.Background(), dto.RefreshRequest{RefreshToken: verifyResp.RefreshToken}, "127.0.0.1")
	if err != nil || refreshed.AccessToken == "" {
		t.Fatalf("refresh error: %v", err)
	}
}

func TestAuthLoginProviderSuccess(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	registry := providers.NewRegistry()
	registry.RegisterSMS(providers.DefaultSMSProvider, fakeSMSProvider{providerID: "prov-1"})

    jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
    svc := NewService(users, challenges, sessions, registry, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	item, ok := challenges.items[loginResp.ChallengeID]
	if !ok {
		t.Fatalf("missing challenge in repo")
	}
	if item.Status != models.ChallengeSent || item.ProviderID != "prov-1" {
		t.Fatalf("unexpected challenge state: %+v", item)
	}
}

func TestAuthLoginProviderFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}
	registry := providers.NewRegistry()
	registry.RegisterSMS(providers.DefaultSMSProvider, fakeSMSProvider{err: errors.New("fail")})

    jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
    svc := NewService(users, challenges, sessions, registry, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	_, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass"})
	if !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
	for _, item := range challenges.items {
		if item.Status != models.ChallengeFailed {
			t.Fatalf("unexpected challenge status: %v", item.Status)
		}
	}
}

func TestAuthVerifyMethodMismatch(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash), Phone: "+79990000000"}}
	challenges := &fakeChallengeRepo{}
	sessions := &fakeSessionRepo{}

    jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
    svc := NewService(users, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	svc.codeGen = func() string { return "123456" }

	loginResp, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass", Method: models.MethodOTP})
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	_, err = svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: loginResp.ChallengeID,
		Method:      models.MethodCall,
		Code:        "123456",
	})
	if !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
}

func TestAuthLoginLocked(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
    lockouts := &fakeLockoutRepo{active: &models.Lockout{ID: "l1"}}
    svc := NewService(users, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, lockouts, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

    _, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "pass", IP: "127.0.0.1"})
    if !errors.Is(err, ErrForbidden) {
        t.Fatalf("expected ErrForbidden, got %v", err)
    }
}

func TestAuthLoginCreatesLockout(t *testing.T) {
    hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
    users := fakeUserRepo{user: &models.User{ID: "u1", Username: "alice", Status: models.UserActive, PasswordHash: string(hash)}}
    lockouts := &fakeLockoutRepo{}
    logins := &fakeLoginHistoryRepo{failures: models.MaxAttemptsPerWindow}
    audits := &recordAuditRepo{}
    svc := NewService(users, &fakeChallengeRepo{}, &fakeSessionRepo{}, nil, lockouts, logins, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

    _, err := svc.Login(context.Background(), dto.LoginRequest{Username: "alice", Password: "bad", IP: "127.0.0.1"})
    if !errors.Is(err, ErrInvalidCredentials) {
        t.Fatalf("expected ErrInvalidCredentials, got %v", err)
    }
    if lockouts.created == nil {
        t.Fatalf("expected lockout to be created")
    }
    if audits.count != 2 || audits.last.Action != models.AuditLockoutCreate || audits.last.EntityType != models.AuditEntityLockout || audits.last.EntityID != lockouts.created.ID || audits.last.Payload != "too_many_attempts" {
        t.Fatalf("unexpected audit event: %+v", audits.last)
    }
}

func TestAuthLogoutOK(t *testing.T) {
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			"refresh": {ID: "s1", UserID: "u1"},
		},
	}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if err := svc.Logout(context.Background(), "u1", "s1", "127.0.0.1"); err != nil {
		t.Fatalf("logout error: %v", err)
	}
	if sessions.revokedID != "s1" {
		t.Fatalf("expected revoke s1, got %s", sessions.revokedID)
	}
}

func TestAuthLogoutForbidden(t *testing.T) {
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			"refresh": {ID: "s1", UserID: "u2"},
		},
	}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if err := svc.Logout(context.Background(), "u1", "s1", "127.0.0.1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestAuthLogoutAudits(t *testing.T) {
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			"refresh": {ID: "s1", UserID: "u1"},
		},
	}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if err := svc.Logout(context.Background(), "u1", "s1", "127.0.0.1"); err != nil {
		t.Fatalf("logout error: %v", err)
	}
	if audits.count != 1 || audits.last.Action != models.AuditLogout || audits.last.EntityType != models.AuditEntitySession || audits.last.EntityID != "s1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthRefreshAudits(t *testing.T) {
	refresh := "token1"
	refreshHash := hash(refresh)
	sessions := &fakeSessionRepo{
		items: map[string]models.UserSession{
			refreshHash: {ID: "s1", UserID: "u1", RefreshTokenHash: refreshHash, ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, &fakeChallengeRepo{}, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	if _, err := svc.Refresh(context.Background(), dto.RefreshRequest{RefreshToken: refresh}, "127.0.0.1"); err != nil {
		t.Fatalf("refresh error: %v", err)
	}
	if audits.count != 1 || audits.last.Action != models.AuditRefresh || audits.last.EntityType != models.AuditEntitySession || audits.last.EntityID != "s1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthVerifySecondFactorAuditApprove(t *testing.T) {
	challenges := &fakeChallengeRepo{
		items: map[string]challengeItem{},
	}
	sessions := &fakeSessionRepo{}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodOTP,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("123456"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	if _, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodOTP,
		Code:        "123456",
		IP:          "127.0.0.1",
	}); err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if audits.count != 1 || audits.last.Action != models.AuditSecondFactorApprove || audits.last.EntityType != models.AuditEntityChallenge || audits.last.EntityID != "c1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" || audits.last.Payload != "otp" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
	}
}

func TestAuthVerifySecondFactorAuditDeny(t *testing.T) {
	challenges := &fakeChallengeRepo{
		items: map[string]challengeItem{},
	}
	sessions := &fakeSessionRepo{}
	audits := &recordAuditRepo{}
	svc := NewService(fakeUserRepo{}, challenges, sessions, nil, &fakeLockoutRepo{}, &fakeLoginHistoryRepo{}, audits, jwt.NewService("2fa", []byte("secret"), time.Minute), time.Minute, time.Hour)

	challenge := &models.Challenge{
		ID:        "c1",
		UserID:    "u1",
		Method:    models.MethodOTP,
		Status:    models.ChallengeCreated,
		CodeHash:  hash("123456"),
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := challenges.Create(context.Background(), challenge); err != nil {
		t.Fatalf("create challenge error: %v", err)
	}
	if _, err := svc.VerifySecondFactor(context.Background(), dto.VerifyRequest{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodOTP,
		Code:        "000000",
		IP:          "127.0.0.1",
	}); !errors.Is(err, ErrSecondFactorFailed) {
		t.Fatalf("expected ErrSecondFactorFailed, got %v", err)
	}
	if audits.count != 2 || audits.last.Action != models.AuditSecondFactorDeny || audits.last.EntityType != models.AuditEntityChallenge || audits.last.EntityID != "c1" || audits.last.ActorUserID != "u1" || audits.last.IP != "127.0.0.1" || audits.last.Payload != "otp" {
		t.Fatalf("unexpected audit event: %+v", audits.last)
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
func (f *fakeChallengeRepo) GetActiveByUserAndMethod(ctx context.Context, userID string, method models.SecondFactorMethod) (*models.Challenge, error) {
    for _, item := range f.items {
        if item.UserID == userID && item.Method == method && (item.Status == models.ChallengeCreated || item.Status == models.ChallengeSent || item.Status == models.ChallengePending) {
            c := item.Challenge
            return &c, nil
        }
    }
    return nil, repository.ErrNotFound
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
func (f *fakeChallengeRepo) UpdateDelivery(ctx context.Context, id string, providerID string, status models.ChallengeStatus) error {
	item := f.items[id]
	item.Status = status
	item.ProviderID = providerID
	f.items[id] = item
	return nil
}
func (f *fakeChallengeRepo) MarkExpired(ctx context.Context, now time.Time) (int64, error) {
	return 0, nil
}

type fakeSessionRepo struct {
	items map[string]models.UserSession
    revokedID string
}

type fakeLockoutRepo struct {
    active  *models.Lockout
    created *models.Lockout
}

func (f *fakeLockoutRepo) Create(ctx context.Context, l *models.Lockout) error {
    f.created = l
    return nil
}
func (f *fakeLockoutRepo) GetActive(ctx context.Context, userID string, ip string, now time.Time) (*models.Lockout, error) {
    if f.active != nil {
        return f.active, nil
    }
    return nil, repository.ErrNotFound
}
func (f *fakeLockoutRepo) ClearExpired(ctx context.Context, now time.Time) (int64, error) {
    return 0, nil
}
func (f *fakeLockoutRepo) List(ctx context.Context, filter repository.LockoutFilter, limit, offset int) ([]models.Lockout, int, error) {
    return nil, 0, nil
}
func (f *fakeLockoutRepo) ClearByFilter(ctx context.Context, filter repository.LockoutFilter) error {
    return nil
}

type fakeLoginHistoryRepo struct {
    failures int
}

func (f *fakeLoginHistoryRepo) Create(ctx context.Context, h *models.LoginHistory) error { return nil }
func (f *fakeLoginHistoryRepo) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
    return nil, 0, nil
}
func (f *fakeLoginHistoryRepo) CountFailures(ctx context.Context, userID string, since time.Time) (int, error) {
    return f.failures, nil
}

type fakeAuditRepo struct{}

func (f *fakeAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error { return nil }
func (f *fakeAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
    return nil, 0, nil
}

type recordAuditRepo struct {
	count int
	last  *models.AuditEvent
}

func (r *recordAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error {
	r.count++
	r.last = e
	return nil
}
func (r *recordAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
	return nil, 0, nil
}

type fakeSMSProvider struct {
	providerID string
	err        error
}

func (f fakeSMSProvider) SendSMS(ctx context.Context, to, message string) (string, error) {
	return f.providerID, f.err
}

func (f *fakeSessionRepo) Create(ctx context.Context, s *models.UserSession) error {
	if f.items == nil {
		f.items = map[string]models.UserSession{}
	}
	f.items[s.RefreshTokenHash] = *s
	return nil
}
func (f *fakeSessionRepo) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
    f.revokedID = id
	return nil
}
func (f *fakeSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
	s, ok := f.items[hash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &s, nil
}

func (f *fakeSessionRepo) GetByID(ctx context.Context, id string) (*models.UserSession, error) {
    for _, s := range f.items {
        if s.ID == id {
            return &s, nil
        }
    }
    return nil, repository.ErrNotFound
}

func (f *fakeSessionRepo) RotateRefreshHash(ctx context.Context, id string, newHash string) error {
    for key, s := range f.items {
        if s.ID == id {
            delete(f.items, key)
            s.RefreshTokenHash = newHash
            f.items[newHash] = s
            return nil
        }
    }
    return repository.ErrNotFound
}

func (f *fakeSessionRepo) List(ctx context.Context, filter repository.SessionListFilter, limit, offset int) ([]models.UserSession, int, error) {
    var out []models.UserSession
    for _, s := range f.items {
        if filter.UserID == "" || s.UserID == filter.UserID {
            out = append(out, s)
        }
    }
    return out, len(out), nil
}

func (f *fakeSessionRepo) RevokeAllByUser(ctx context.Context, userID string, exceptSessionID string, revokedAt time.Time) error {
    for key, s := range f.items {
        if s.UserID != userID || s.ID == exceptSessionID {
            continue
        }
        s.RevokedAt = &revokedAt
        f.items[key] = s
    }
    return nil
}

func (f *fakeSessionRepo) Touch(ctx context.Context, id string, seenAt time.Time) error {
    return nil
}
