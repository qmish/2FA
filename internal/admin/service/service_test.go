package service

import (
    "context"
    "errors"
    "testing"
    "time"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

func TestServiceListUsers(t *testing.T) {
    svc := NewService(
        fakeUserRepo{items: []models.User{{ID: "u1", Username: "admin", Status: models.UserActive, Role: models.RoleAdmin}}},
        fakePolicyRepo{},
        fakePolicyRuleRepo{},
        fakeRadiusClientRepo{},
        fakeRolePermRepo{},
        fakeGroupRepo{},
        fakeUserGroupRepo{},
        fakeGroupPolicyRepo{},
        fakeAuditRepo{},
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
        fakeSessionRepo{},
        &fakeLockoutRepo{},
    )

    resp, err := svc.ListUsers(context.Background(), dto.AdminUserListRequest{
        Page: dto.PageRequest{Limit: 10, Offset: 0},
        Filter: dto.AdminUserFilter{
            Status: models.UserActive,
        },
    })
    if err != nil {
        t.Fatalf("ListUsers error: %v", err)
    }
    if len(resp.Items) != 1 || resp.Items[0].Role != models.RoleAdmin {
        t.Fatalf("unexpected response: %+v", resp)
    }
}

func TestServiceCreateUser(t *testing.T) {
    repo := &recordUserRepo{}
    svc := NewService(
        repo,
        fakePolicyRepo{},
        fakePolicyRuleRepo{},
        fakeRadiusClientRepo{},
        fakeRolePermRepo{},
        fakeGroupRepo{},
        fakeUserGroupRepo{},
        fakeGroupPolicyRepo{},
        fakeAuditRepo{},
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
        fakeSessionRepo{},
        &fakeLockoutRepo{},
    )

    _, err := svc.CreateUser(context.Background(), dto.AdminUserCreateRequest{
        Username: "bob",
        Email:    "b@example.com",
        Phone:    "+70000000000",
        Status:   models.UserActive,
        Role:     models.RoleUser,
        Password: "secret",
    })
    if err != nil {
        t.Fatalf("CreateUser error: %v", err)
    }
    if repo.created == nil || repo.created.Username != "bob" || repo.created.Role != models.RoleUser {
        t.Fatalf("unexpected created user: %+v", repo.created)
    }
    if repo.created.PasswordHash == "" {
        t.Fatalf("expected password hash")
    }
}

func TestServiceListLockouts(t *testing.T) {
    lockouts := &fakeLockoutRepo{
        items: []models.Lockout{{ID: "l1", UserID: "u1", IP: "127.0.0.1", Reason: "too_many_attempts"}},
    }
    svc := NewService(
        fakeUserRepo{},
        fakePolicyRepo{},
        fakePolicyRuleRepo{},
        fakeRadiusClientRepo{},
        fakeRolePermRepo{},
        fakeGroupRepo{},
        fakeUserGroupRepo{},
        fakeGroupPolicyRepo{},
        fakeAuditRepo{},
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
        fakeSessionRepo{},
        lockouts,
    )
    resp, err := svc.ListLockouts(context.Background(), dto.AdminLockoutListRequest{
        Page: dto.PageRequest{Limit: 10, Offset: 0},
        Filter: dto.AdminLockoutFilter{UserID: "u1", ActiveOnly: true},
    })
    if err != nil || len(resp.Items) != 1 || resp.Items[0].ID != "l1" {
        t.Fatalf("unexpected response: %+v err=%v", resp, err)
    }
}

func TestServiceClearLockouts(t *testing.T) {
    lockouts := &fakeLockoutRepo{}
    audits := &recordAuditRepo{}
    svc := NewService(
        fakeUserRepo{},
        fakePolicyRepo{},
        fakePolicyRuleRepo{},
        fakeRadiusClientRepo{},
        fakeRolePermRepo{},
        fakeGroupRepo{},
        fakeUserGroupRepo{},
        fakeGroupPolicyRepo{},
        audits,
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
        fakeSessionRepo{},
        lockouts,
    )
    if err := svc.ClearLockouts(context.Background(), "admin1", dto.AdminLockoutClearRequest{Reason: "too_many_attempts"}); err != nil {
        t.Fatalf("ClearLockouts error: %v", err)
    }
    if lockouts.cleared.Reason != "too_many_attempts" {
        t.Fatalf("expected cleared reason, got %+v", lockouts.cleared)
    }
    if audits.count != 1 || audits.last.Action != models.AuditLockoutClear || audits.last.ActorUserID != "admin1" || audits.last.EntityType != models.AuditEntityLockout {
        t.Fatalf("unexpected audit event: %+v", audits.last)
    }
}

func TestServiceRevokeSessionAudits(t *testing.T) {
    audits := &recordAuditRepo{}
    sessions := &recordSessionRepo{}
    svc := NewService(
        fakeUserRepo{},
        fakePolicyRepo{},
        fakePolicyRuleRepo{},
        fakeRadiusClientRepo{},
        fakeRolePermRepo{},
        fakeGroupRepo{},
        fakeUserGroupRepo{},
        fakeGroupPolicyRepo{},
        audits,
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
        sessions,
        &fakeLockoutRepo{},
    )
    if err := svc.RevokeSession(context.Background(), "admin1", "s1", "127.0.0.1"); err != nil {
        t.Fatalf("RevokeSession error: %v", err)
    }
    if sessions.revokedID != "s1" {
        t.Fatalf("expected revoke s1, got %s", sessions.revokedID)
    }
    if audits.count != 1 || audits.last.Action != models.AuditSessionRevoke || audits.last.ActorUserID != "admin1" || audits.last.EntityType != models.AuditEntitySession || audits.last.EntityID != "s1" || audits.last.IP != "127.0.0.1" {
        t.Fatalf("unexpected audit event: %+v", audits.last)
    }
}

func TestServiceRevokeUserSessionsAudits(t *testing.T) {
    audits := &recordAuditRepo{}
    sessions := &recordSessionRepo{}
    svc := NewService(
        fakeUserRepo{},
        fakePolicyRepo{},
        fakePolicyRuleRepo{},
        fakeRadiusClientRepo{},
        fakeRolePermRepo{},
        fakeGroupRepo{},
        fakeUserGroupRepo{},
        fakeGroupPolicyRepo{},
        audits,
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
        sessions,
        &fakeLockoutRepo{},
    )
    if err := svc.RevokeUserSessions(context.Background(), "admin1", "u2", "s3", "127.0.0.1"); err != nil {
        t.Fatalf("RevokeUserSessions error: %v", err)
    }
    if sessions.revokedUser != "u2" || sessions.exceptID != "s3" {
        t.Fatalf("unexpected revoke user sessions: %+v", sessions)
    }
    if audits.count != 1 || audits.last.Action != models.AuditSessionRevokeAll || audits.last.ActorUserID != "admin1" || audits.last.EntityType != models.AuditEntityUser || audits.last.EntityID != "u2" || audits.last.IP != "127.0.0.1" {
        t.Fatalf("unexpected audit event: %+v", audits.last)
    }
}

type fakeUserRepo struct {
    items []models.User
}

func (f fakeUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
    return nil, repository.ErrNotFound
}
func (f fakeUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
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
    return f.items, len(f.items), nil
}
func (f fakeUserRepo) Create(ctx context.Context, u *models.User) error { return nil }
func (f fakeUserRepo) Update(ctx context.Context, u *models.User) error { return nil }
func (f fakeUserRepo) Delete(ctx context.Context, id string) error { return nil }
func (f fakeUserRepo) SetStatus(ctx context.Context, id string, status models.UserStatus) error {
    return nil
}

type recordUserRepo struct {
    fakeUserRepo
    created *models.User
}

func (r *recordUserRepo) Create(ctx context.Context, u *models.User) error {
    r.created = u
    return nil
}

type fakePolicyRepo struct{}

func (f fakePolicyRepo) GetByID(ctx context.Context, id string) (*models.Policy, error) { return nil, repository.ErrNotFound }
func (f fakePolicyRepo) GetByName(ctx context.Context, name string) (*models.Policy, error) {
    return nil, repository.ErrNotFound
}
func (f fakePolicyRepo) List(ctx context.Context, limit, offset int) ([]models.Policy, int, error) {
    return []models.Policy{}, 0, nil
}
func (f fakePolicyRepo) Create(ctx context.Context, p *models.Policy) error { return nil }
func (f fakePolicyRepo) Update(ctx context.Context, p *models.Policy) error { return nil }
func (f fakePolicyRepo) Delete(ctx context.Context, id string) error { return nil }
func (f fakePolicyRepo) SetStatus(ctx context.Context, id string, status models.PolicyStatus) error { return nil }

type fakePolicyRuleRepo struct{}

func (f fakePolicyRuleRepo) ListByPolicy(ctx context.Context, policyID string) ([]models.PolicyRule, error) {
    return []models.PolicyRule{}, nil
}
func (f fakePolicyRuleRepo) Create(ctx context.Context, r *models.PolicyRule) error { return nil }
func (f fakePolicyRuleRepo) Delete(ctx context.Context, id string) error { return nil }
func (f fakePolicyRuleRepo) DeleteByPolicy(ctx context.Context, policyID string) error { return nil }

type fakeRadiusClientRepo struct{}

func (f fakeRadiusClientRepo) GetByID(ctx context.Context, id string) (*models.RadiusClient, error) {
    return nil, repository.ErrNotFound
}
func (f fakeRadiusClientRepo) GetByIP(ctx context.Context, ip string) (*models.RadiusClient, error) {
    return nil, repository.ErrNotFound
}
func (f fakeRadiusClientRepo) List(ctx context.Context, limit, offset int) ([]models.RadiusClient, int, error) {
    return []models.RadiusClient{}, 0, nil
}
func (f fakeRadiusClientRepo) Create(ctx context.Context, c *models.RadiusClient) error { return nil }
func (f fakeRadiusClientRepo) Update(ctx context.Context, c *models.RadiusClient) error { return nil }
func (f fakeRadiusClientRepo) Delete(ctx context.Context, id string) error { return nil }
func (f fakeRadiusClientRepo) SetEnabled(ctx context.Context, id string, enabled bool) error { return nil }

type fakeAuditRepo struct{}

func (f fakeAuditRepo) Create(ctx context.Context, e *models.AuditEvent) error { return nil }
func (f fakeAuditRepo) List(ctx context.Context, filter repository.AuditFilter, limit, offset int) ([]models.AuditEvent, int, error) {
    return []models.AuditEvent{}, 0, nil
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
    return []models.AuditEvent{}, 0, nil
}

type fakeLoginRepo struct{}

func (f fakeLoginRepo) Create(ctx context.Context, h *models.LoginHistory) error { return nil }
func (f fakeLoginRepo) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
    return []models.LoginHistory{}, 0, nil
}
func (f fakeLoginRepo) CountFailures(ctx context.Context, userID string, since time.Time) (int, error) {
    return 0, nil
}

type fakeRadiusReqRepo struct{}

func (f fakeRadiusReqRepo) Create(ctx context.Context, r *models.RadiusRequest) error { return nil }
func (f fakeRadiusReqRepo) List(ctx context.Context, filter repository.RadiusRequestFilter, limit, offset int) ([]models.RadiusRequest, int, error) {
    return []models.RadiusRequest{}, 0, nil
}
func (f fakeRadiusReqRepo) UpdateResult(ctx context.Context, id string, result models.RadiusResult) error { return nil }

type fakeSessionRepo struct{}

func (f fakeSessionRepo) Create(ctx context.Context, s *models.UserSession) error { return nil }
func (f fakeSessionRepo) Revoke(ctx context.Context, id string, revokedAt time.Time) error { return nil }
func (f fakeSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
    return nil, repository.ErrNotFound
}
func (f fakeSessionRepo) GetByID(ctx context.Context, id string) (*models.UserSession, error) {
    return nil, repository.ErrNotFound
}
func (f fakeSessionRepo) RotateRefreshHash(ctx context.Context, id string, newHash string) error { return nil }
func (f fakeSessionRepo) List(ctx context.Context, filter repository.SessionListFilter, limit, offset int) ([]models.UserSession, int, error) {
    return nil, 0, nil
}
func (f fakeSessionRepo) RevokeAllByUser(ctx context.Context, userID string, exceptSessionID string, revokedAt time.Time) error {
    return nil
}
func (f fakeSessionRepo) Touch(ctx context.Context, id string, seenAt time.Time) error { return nil }

type recordSessionRepo struct {
    revokedID   string
    revokedUser string
    exceptID    string
}

func (r *recordSessionRepo) Create(ctx context.Context, s *models.UserSession) error { return nil }
func (r *recordSessionRepo) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
    r.revokedID = id
    return nil
}
func (r *recordSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*models.UserSession, error) {
    return nil, repository.ErrNotFound
}
func (r *recordSessionRepo) GetByID(ctx context.Context, id string) (*models.UserSession, error) {
    return nil, repository.ErrNotFound
}
func (r *recordSessionRepo) RotateRefreshHash(ctx context.Context, id string, newHash string) error { return nil }
func (r *recordSessionRepo) List(ctx context.Context, filter repository.SessionListFilter, limit, offset int) ([]models.UserSession, int, error) {
    return nil, 0, nil
}
func (r *recordSessionRepo) RevokeAllByUser(ctx context.Context, userID string, exceptSessionID string, revokedAt time.Time) error {
    r.revokedUser = userID
    r.exceptID = exceptSessionID
    return nil
}
func (r *recordSessionRepo) Touch(ctx context.Context, id string, seenAt time.Time) error { return nil }

type fakeLockoutRepo struct{
    items []models.Lockout
    cleared repository.LockoutFilter
}

func (f *fakeLockoutRepo) Create(ctx context.Context, l *models.Lockout) error { return nil }
func (f *fakeLockoutRepo) GetActive(ctx context.Context, userID string, ip string, now time.Time) (*models.Lockout, error) {
    return nil, repository.ErrNotFound
}
func (f *fakeLockoutRepo) ClearExpired(ctx context.Context, now time.Time) (int64, error) { return 0, nil }
func (f *fakeLockoutRepo) List(ctx context.Context, filter repository.LockoutFilter, limit, offset int) ([]models.Lockout, int, error) {
    return f.items, len(f.items), nil
}
func (f *fakeLockoutRepo) ClearByFilter(ctx context.Context, filter repository.LockoutFilter) error {
    f.cleared = filter
    return nil
}

type fakeRolePermRepo struct{}

func (f fakeRolePermRepo) ListByRole(ctx context.Context, role models.UserRole) ([]models.Permission, error) {
    return []models.Permission{}, nil
}
func (f fakeRolePermRepo) SetRolePermissions(ctx context.Context, role models.UserRole, perms []models.Permission) error {
    return nil
}

type fakeGroupRepo struct{}

func (f fakeGroupRepo) GetByID(ctx context.Context, id string) (*models.Group, error) {
    return nil, repository.ErrNotFound
}
func (f fakeGroupRepo) GetByName(ctx context.Context, name string) (*models.Group, error) {
    return nil, repository.ErrNotFound
}
func (f fakeGroupRepo) List(ctx context.Context, limit, offset int) ([]models.Group, int, error) {
    return []models.Group{}, 0, nil
}
func (f fakeGroupRepo) Create(ctx context.Context, g *models.Group) error { return nil }
func (f fakeGroupRepo) Update(ctx context.Context, g *models.Group) error { return nil }
func (f fakeGroupRepo) Delete(ctx context.Context, id string) error { return nil }

type fakeUserGroupRepo struct{}

func (f fakeUserGroupRepo) AddUser(ctx context.Context, groupID, userID string) error { return nil }
func (f fakeUserGroupRepo) RemoveUser(ctx context.Context, groupID, userID string) error { return nil }
func (f fakeUserGroupRepo) ListUsers(ctx context.Context, groupID string, limit, offset int) ([]models.User, int, error) {
    return []models.User{}, 0, nil
}

func (f fakeUserGroupRepo) ListGroups(ctx context.Context, userID string) ([]models.Group, error) {
    return []models.Group{}, nil
}

type fakeGroupPolicyRepo struct{}

func (f fakeGroupPolicyRepo) SetPolicy(ctx context.Context, groupID, policyID string) error { return nil }
func (f fakeGroupPolicyRepo) GetPolicy(ctx context.Context, groupID string) (string, error) {
    return "", errors.New("not implemented")
}
func (f fakeGroupPolicyRepo) ClearPolicy(ctx context.Context, groupID string) error { return nil }

