package service

import (
    "context"
    "errors"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

var ErrRolePermissionsStoreMissing = errors.New("role permissions store not configured")

type Service struct {
    users         repository.UserRepository
    policies      repository.PolicyRepository
    policyRules   repository.PolicyRuleRepository
    radiusClients repository.RadiusClientRepository
    rolePerms     repository.RolePermissionRepository
    audit         repository.AuditRepository
    logins        repository.LoginHistoryRepository
    radiusReqs    repository.RadiusRequestRepository
}

func NewService(
    users repository.UserRepository,
    policies repository.PolicyRepository,
    policyRules repository.PolicyRuleRepository,
    radiusClients repository.RadiusClientRepository,
    rolePerms repository.RolePermissionRepository,
    audit repository.AuditRepository,
    logins repository.LoginHistoryRepository,
    radiusReqs repository.RadiusRequestRepository,
) *Service {
    return &Service{
        users:         users,
        policies:      policies,
        policyRules:   policyRules,
        radiusClients: radiusClients,
        rolePerms:     rolePerms,
        audit:         audit,
        logins:        logins,
        radiusReqs:    radiusReqs,
    }
}

func (s *Service) ListUsers(ctx context.Context, req dto.AdminUserListRequest) (dto.AdminUserListResponse, error) {
    items, total, err := s.users.List(ctx, repository.UserListFilter{
        Query:   req.Filter.Query,
        Status:  req.Filter.Status,
        GroupID: req.Filter.GroupID,
    }, req.Page.Limit, req.Page.Offset)
    if err != nil {
        return dto.AdminUserListResponse{}, err
    }
    out := make([]dto.AdminUserListItem, 0, len(items))
    for _, u := range items {
        out = append(out, dto.AdminUserListItem{
            ID:       u.ID,
            Username: u.Username,
            Email:    u.Email,
            Phone:    u.Phone,
            Status:   u.Status,
            Role:     u.Role,
        })
    }
    return dto.AdminUserListResponse{
        Items: out,
        Page:  dto.PageResponse{Total: total, Limit: req.Page.Limit, Offset: req.Page.Offset},
    }, nil
}

func (s *Service) CreateUser(ctx context.Context, req dto.AdminUserCreateRequest) (dto.AdminUserResponse, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return dto.AdminUserResponse{}, err
    }
    now := time.Now()
    user := &models.User{
        ID:           uuid.NewString(),
        Username:     req.Username,
        Email:        req.Email,
        Phone:        req.Phone,
        Status:       req.Status,
        Role:         req.Role,
        PasswordHash: string(hash),
        CreatedAt:    now,
        UpdatedAt:    now,
    }
    if err := s.users.Create(ctx, user); err != nil {
        return dto.AdminUserResponse{}, err
    }
    return dto.AdminUserResponse{
        ID:       user.ID,
        Username: user.Username,
        Email:    user.Email,
        Phone:    user.Phone,
        Status:   user.Status,
        Role:     user.Role,
    }, nil
}

func (s *Service) UpdateUser(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
    user, err := s.users.GetByID(ctx, id)
    if err != nil {
        return dto.AdminUserResponse{}, err
    }
    if req.Email != "" {
        user.Email = req.Email
    }
    if req.Phone != "" {
        user.Phone = req.Phone
    }
    if req.Status != "" {
        user.Status = req.Status
    }
    if req.Role != "" {
        user.Role = req.Role
    }
    user.UpdatedAt = time.Now()
    if err := s.users.Update(ctx, user); err != nil {
        return dto.AdminUserResponse{}, err
    }
    return dto.AdminUserResponse{
        ID:       user.ID,
        Username: user.Username,
        Email:    user.Email,
        Phone:    user.Phone,
        Status:   user.Status,
        Role:     user.Role,
    }, nil
}

func (s *Service) DeleteUser(ctx context.Context, id string) error {
    return s.users.Delete(ctx, id)
}

func (s *Service) ListPolicies(ctx context.Context, req dto.PageRequest) ([]dto.AdminPolicyDTO, dto.PageResponse, error) {
    items, total, err := s.policies.List(ctx, req.Limit, req.Offset)
    if err != nil {
        return nil, dto.PageResponse{}, err
    }
    out := make([]dto.AdminPolicyDTO, 0, len(items))
    for _, p := range items {
        rules, err := s.policyRules.ListByPolicy(ctx, p.ID)
        if err != nil {
            return nil, dto.PageResponse{}, err
        }
        out = append(out, dto.AdminPolicyDTO{
            ID:       p.ID,
            Name:     p.Name,
            Priority: p.Priority,
            Status:   p.Status,
            Rules:    mapPolicyRules(rules),
        })
    }
    return out, dto.PageResponse{Total: total, Limit: req.Limit, Offset: req.Offset}, nil
}

func (s *Service) CreatePolicy(ctx context.Context, req dto.AdminPolicyCreateRequest) (dto.AdminPolicyDTO, error) {
    now := time.Now()
    policy := &models.Policy{
        ID:       uuid.NewString(),
        Name:     req.Name,
        Priority: req.Priority,
        Status:   req.Status,
        CreatedAt: now,
    }
    if err := s.policies.Create(ctx, policy); err != nil {
        return dto.AdminPolicyDTO{}, err
    }
    for _, rule := range req.Rules {
        r := &models.PolicyRule{
            ID:        uuid.NewString(),
            PolicyID:  policy.ID,
            RuleType:  rule.Type,
            RuleValue: rule.Value,
            CreatedAt: now,
        }
        if err := s.policyRules.Create(ctx, r); err != nil {
            return dto.AdminPolicyDTO{}, err
        }
    }
    return dto.AdminPolicyDTO{
        ID:       policy.ID,
        Name:     policy.Name,
        Priority: policy.Priority,
        Status:   policy.Status,
        Rules:    req.Rules,
    }, nil
}

func (s *Service) UpdatePolicy(ctx context.Context, id string, req dto.AdminPolicyUpdateRequest) (dto.AdminPolicyDTO, error) {
    now := time.Now()
    policy, err := s.policies.GetByID(ctx, id)
    if err != nil {
        return dto.AdminPolicyDTO{}, err
    }
    if req.Name != "" {
        policy.Name = req.Name
    }
    if req.Priority != 0 {
        policy.Priority = req.Priority
    }
    if req.Status != "" {
        policy.Status = req.Status
    }
    if err := s.policies.Update(ctx, policy); err != nil {
        return dto.AdminPolicyDTO{}, err
    }
    if err := s.policyRules.DeleteByPolicy(ctx, id); err != nil {
        return dto.AdminPolicyDTO{}, err
    }
    for _, rule := range req.Rules {
        r := &models.PolicyRule{
            ID:        uuid.NewString(),
            PolicyID:  policy.ID,
            RuleType:  rule.Type,
            RuleValue: rule.Value,
            CreatedAt: now,
        }
        if err := s.policyRules.Create(ctx, r); err != nil {
            return dto.AdminPolicyDTO{}, err
        }
    }
    return dto.AdminPolicyDTO{
        ID:       policy.ID,
        Name:     policy.Name,
        Priority: policy.Priority,
        Status:   policy.Status,
        Rules:    req.Rules,
    }, nil
}

func (s *Service) DeletePolicy(ctx context.Context, id string) error {
    if err := s.policyRules.DeleteByPolicy(ctx, id); err != nil {
        return err
    }
    return s.policies.Delete(ctx, id)
}

func (s *Service) ListRadiusClients(ctx context.Context, req dto.PageRequest) ([]dto.AdminRadiusClientDTO, dto.PageResponse, error) {
    items, total, err := s.radiusClients.List(ctx, req.Limit, req.Offset)
    if err != nil {
        return nil, dto.PageResponse{}, err
    }
    out := make([]dto.AdminRadiusClientDTO, 0, len(items))
    for _, c := range items {
        out = append(out, dto.AdminRadiusClientDTO{
            ID:      c.ID,
            Name:    c.Name,
            IP:      c.IP,
            Enabled: c.Enabled,
        })
    }
    return out, dto.PageResponse{Total: total, Limit: req.Limit, Offset: req.Offset}, nil
}

func (s *Service) CreateRadiusClient(ctx context.Context, req dto.AdminRadiusClientCreateRequest) (dto.AdminRadiusClientDTO, error) {
    now := time.Now()
    client := &models.RadiusClient{
        ID:      uuid.NewString(),
        Name:    req.Name,
        IP:      req.IP,
        Secret:  req.Secret,
        Enabled: req.Enabled,
        CreatedAt: now,
    }
    if err := s.radiusClients.Create(ctx, client); err != nil {
        return dto.AdminRadiusClientDTO{}, err
    }
    return dto.AdminRadiusClientDTO{
        ID:      client.ID,
        Name:    client.Name,
        IP:      client.IP,
        Enabled: client.Enabled,
    }, nil
}

func (s *Service) UpdateRadiusClient(ctx context.Context, id string, req dto.AdminRadiusClientUpdateRequest) (dto.AdminRadiusClientDTO, error) {
    client, err := s.radiusClients.GetByID(ctx, id)
    if err != nil {
        return dto.AdminRadiusClientDTO{}, err
    }
    if req.Name != "" {
        client.Name = req.Name
    }
    if req.Secret != "" {
        client.Secret = req.Secret
    }
    client.Enabled = req.Enabled
    if err := s.radiusClients.Update(ctx, client); err != nil {
        return dto.AdminRadiusClientDTO{}, err
    }
    return dto.AdminRadiusClientDTO{
        ID:      client.ID,
        Name:    client.Name,
        IP:      client.IP,
        Enabled: client.Enabled,
    }, nil
}

func (s *Service) DeleteRadiusClient(ctx context.Context, id string) error {
    return s.radiusClients.Delete(ctx, id)
}

func (s *Service) GetRolePermissions(ctx context.Context, role string) (dto.RolePermissionsResponse, error) {
    if s.rolePerms == nil {
        return dto.RolePermissionsResponse{}, ErrRolePermissionsStoreMissing
    }
    perms, err := s.rolePerms.ListByRole(ctx, models.UserRole(role))
    if err != nil {
        return dto.RolePermissionsResponse{}, err
    }
    return dto.RolePermissionsResponse{
        Role:        models.UserRole(role),
        Permissions: perms,
    }, nil
}

func (s *Service) SetRolePermissions(ctx context.Context, role string, req dto.RolePermissionsUpdateRequest) (dto.RolePermissionsResponse, error) {
    if s.rolePerms == nil {
        return dto.RolePermissionsResponse{}, ErrRolePermissionsStoreMissing
    }
    if err := s.rolePerms.SetRolePermissions(ctx, models.UserRole(role), req.Permissions); err != nil {
        return dto.RolePermissionsResponse{}, err
    }
    return dto.RolePermissionsResponse{
        Role:        models.UserRole(role),
        Permissions: req.Permissions,
    }, nil
}

func (s *Service) ListAuditEvents(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
    items, total, err := s.audit.List(ctx, repository.AuditFilter{
        ActorUserID: req.Filter.ActorUserID,
        EntityType:  req.Filter.EntityType,
        Action:      req.Filter.Action,
        From:        req.Filter.From,
        To:          req.Filter.To,
    }, req.Page.Limit, req.Page.Offset)
    if err != nil {
        return dto.AdminAuditListResponse{}, err
    }
    out := make([]dto.AdminAuditEventDTO, 0, len(items))
    for _, e := range items {
        out = append(out, dto.AdminAuditEventDTO{
            ID:          e.ID,
            ActorUserID: e.ActorUserID,
            Action:      e.Action,
            EntityType:  e.EntityType,
            EntityID:    e.EntityID,
            IP:          e.IP,
            CreatedAt:   e.CreatedAt,
        })
    }
    return dto.AdminAuditListResponse{
        Items: out,
        Page:  dto.PageResponse{Total: total, Limit: req.Page.Limit, Offset: req.Page.Offset},
    }, nil
}

func (s *Service) ListLoginHistory(ctx context.Context, req dto.AdminLoginHistoryListRequest) (dto.AdminLoginHistoryListResponse, error) {
    items, total, err := s.logins.List(ctx, repository.LoginHistoryFilter{
        UserID:  req.Filter.UserID,
        Channel: req.Filter.Channel,
        Result:  req.Filter.Result,
        From:    req.Filter.From,
        To:      req.Filter.To,
    }, req.Page.Limit, req.Page.Offset)
    if err != nil {
        return dto.AdminLoginHistoryListResponse{}, err
    }
    out := make([]dto.LoginHistoryDTO, 0, len(items))
    for _, h := range items {
        out = append(out, dto.LoginHistoryDTO{
            ID:        h.ID,
            UserID:    h.UserID,
            Channel:   h.Channel,
            Result:    h.Result,
            IP:        h.IP,
            DeviceID:  h.DeviceID,
            CreatedAt: h.CreatedAt,
        })
    }
    return dto.AdminLoginHistoryListResponse{
        Items: out,
        Page:  dto.PageResponse{Total: total, Limit: req.Page.Limit, Offset: req.Page.Offset},
    }, nil
}

func (s *Service) ListRadiusRequests(ctx context.Context, req dto.AdminRadiusRequestListRequest) (dto.AdminRadiusRequestListResponse, error) {
    items, total, err := s.radiusReqs.List(ctx, repository.RadiusRequestFilter{
        ClientID: req.Filter.ClientID,
        Username: req.Filter.Username,
        Result:   req.Filter.Result,
        From:     req.Filter.From,
        To:       req.Filter.To,
    }, req.Page.Limit, req.Page.Offset)
    if err != nil {
        return dto.AdminRadiusRequestListResponse{}, err
    }
    out := make([]dto.RadiusRequestDTO, 0, len(items))
    for _, r := range items {
        out = append(out, dto.RadiusRequestDTO{
            ID:        r.ID,
            ClientID:  r.ClientID,
            Username:  r.Username,
            NASIP:     r.NASIP,
            Result:    r.Result,
            CreatedAt: r.CreatedAt,
        })
    }
    return dto.AdminRadiusRequestListResponse{
        Items: out,
        Page:  dto.PageResponse{Total: total, Limit: req.Page.Limit, Offset: req.Page.Offset},
    }, nil
}

func mapPolicyRules(rules []models.PolicyRule) []dto.PolicyRuleDTO {
    out := make([]dto.PolicyRuleDTO, 0, len(rules))
    for _, r := range rules {
        out = append(out, dto.PolicyRuleDTO{
            ID:    r.ID,
            Type:  r.RuleType,
            Value: r.RuleValue,
        })
    }
    return out
}
