package service

import (
    "context"

    "github.com/qmish/2FA/internal/dto"
    "github.com/qmish/2FA/internal/models"
    "github.com/qmish/2FA/internal/repository"
)

type Service struct {
    users         repository.UserRepository
    policies      repository.PolicyRepository
    policyRules   repository.PolicyRuleRepository
    radiusClients repository.RadiusClientRepository
    audit         repository.AuditRepository
    logins        repository.LoginHistoryRepository
    radiusReqs    repository.RadiusRequestRepository
}

func NewService(
    users repository.UserRepository,
    policies repository.PolicyRepository,
    policyRules repository.PolicyRuleRepository,
    radiusClients repository.RadiusClientRepository,
    audit repository.AuditRepository,
    logins repository.LoginHistoryRepository,
    radiusReqs repository.RadiusRequestRepository,
) *Service {
    return &Service{
        users:         users,
        policies:      policies,
        policyRules:   policyRules,
        radiusClients: radiusClients,
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
