package service

import (
    "context"
    "errors"
    "testing"

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
        fakeAuditRepo{},
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
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
        fakeAuditRepo{},
        fakeLoginRepo{},
        fakeRadiusReqRepo{},
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

type fakeUserRepo struct {
    items []models.User
}

func (f fakeUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
    return nil, errors.New("not implemented")
}
func (f fakeUserRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
    return nil, errors.New("not implemented")
}
func (f fakeUserRepo) GetByUsernameAndRole(ctx context.Context, username string, role models.UserRole) (*models.User, error) {
    return nil, errors.New("not implemented")
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

func (f fakePolicyRepo) GetByID(ctx context.Context, id string) (*models.Policy, error) { return nil, errors.New("not implemented") }
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
    return nil, errors.New("not implemented")
}
func (f fakeRadiusClientRepo) GetByIP(ctx context.Context, ip string) (*models.RadiusClient, error) {
    return nil, errors.New("not implemented")
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

type fakeLoginRepo struct{}

func (f fakeLoginRepo) Create(ctx context.Context, h *models.LoginHistory) error { return nil }
func (f fakeLoginRepo) List(ctx context.Context, filter repository.LoginHistoryFilter, limit, offset int) ([]models.LoginHistory, int, error) {
    return []models.LoginHistory{}, 0, nil
}

type fakeRadiusReqRepo struct{}

func (f fakeRadiusReqRepo) Create(ctx context.Context, r *models.RadiusRequest) error { return nil }
func (f fakeRadiusReqRepo) List(ctx context.Context, filter repository.RadiusRequestFilter, limit, offset int) ([]models.RadiusRequest, int, error) {
    return []models.RadiusRequest{}, 0, nil
}
func (f fakeRadiusReqRepo) UpdateResult(ctx context.Context, id string, result models.RadiusResult) error { return nil }

type fakeRolePermRepo struct{}

func (f fakeRolePermRepo) ListByRole(ctx context.Context, role models.UserRole) ([]models.Permission, error) {
    return []models.Permission{}, nil
}
func (f fakeRolePermRepo) SetRolePermissions(ctx context.Context, role models.UserRole, perms []models.Permission) error {
    return nil
}

