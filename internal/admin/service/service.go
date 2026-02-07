package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
	"github.com/qmish/2FA/pkg/validator"
)

var (
	ErrRolePermissionsStoreMissing = errors.New("role permissions store not configured")
	ErrInvalidInput                = errors.New("invalid input")
)

type Service struct {
	users         repository.UserRepository
	invites       repository.InviteRepository
	policies      repository.PolicyRepository
	policyRules   repository.PolicyRuleRepository
	radiusClients repository.RadiusClientRepository
	rolePerms     repository.RolePermissionRepository
	groups        repository.GroupRepository
	userGroups    repository.UserGroupRepository
	groupPolicies repository.GroupPolicyRepository
	audit         repository.AuditRepository
	logins        repository.LoginHistoryRepository
	radiusReqs    repository.RadiusRequestRepository
	sessions      repository.SessionRepository
	lockouts      repository.LockoutRepository
}

func NewService(
	users repository.UserRepository,
	invites repository.InviteRepository,
	policies repository.PolicyRepository,
	policyRules repository.PolicyRuleRepository,
	radiusClients repository.RadiusClientRepository,
	rolePerms repository.RolePermissionRepository,
	groups repository.GroupRepository,
	userGroups repository.UserGroupRepository,
	groupPolicies repository.GroupPolicyRepository,
	audit repository.AuditRepository,
	logins repository.LoginHistoryRepository,
	radiusReqs repository.RadiusRequestRepository,
	sessions repository.SessionRepository,
	lockouts repository.LockoutRepository,
) *Service {
	return &Service{
		users:         users,
		invites:       invites,
		policies:      policies,
		policyRules:   policyRules,
		radiusClients: radiusClients,
		rolePerms:     rolePerms,
		groups:        groups,
		userGroups:    userGroups,
		groupPolicies: groupPolicies,
		audit:         audit,
		logins:        logins,
		radiusReqs:    radiusReqs,
		sessions:      sessions,
		lockouts:      lockouts,
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
	if _, err := s.users.GetByUsername(ctx, req.Username); err == nil {
		return dto.AdminUserResponse{}, ErrConflict
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.AdminUserResponse{}, err
	}
	if req.Email != "" {
		if _, err := s.users.GetByEmail(ctx, req.Email); err == nil {
			return dto.AdminUserResponse{}, ErrConflict
		} else if !errors.Is(err, repository.ErrNotFound) {
			return dto.AdminUserResponse{}, err
		}
	}
	if req.Phone != "" {
		if _, err := s.users.GetByPhone(ctx, req.Phone); err == nil {
			return dto.AdminUserResponse{}, ErrConflict
		} else if !errors.Is(err, repository.ErrNotFound) {
			return dto.AdminUserResponse{}, err
		}
	}
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

func (s *Service) BulkCreateUsers(ctx context.Context, req dto.AdminUserBulkRequest) (dto.AdminUserBulkResponse, error) {
	resp := dto.AdminUserBulkResponse{
		Items: make([]dto.AdminUserBulkItem, 0, len(req.Items)),
	}
	for idx, item := range req.Items {
		row := idx + 1
		item.Username = strings.TrimSpace(item.Username)
		item.Email = validator.NormalizeEmail(item.Email)
		item.Phone = validator.NormalizePhone(item.Phone)

		if item.Username == "" || item.Password == "" {
			resp.Failed++
			resp.Items = append(resp.Items, dto.AdminUserBulkItem{
				Row:      row,
				Username: item.Username,
				Status:   "failed",
				Error:    "invalid_input",
			})
			continue
		}
		if item.Email != "" && !validator.IsEmailValid(item.Email) {
			resp.Failed++
			resp.Items = append(resp.Items, dto.AdminUserBulkItem{
				Row:      row,
				Username: item.Username,
				Status:   "failed",
				Error:    "invalid_email",
			})
			continue
		}
		if item.Phone != "" && !validator.IsPhoneValid(item.Phone) {
			resp.Failed++
			resp.Items = append(resp.Items, dto.AdminUserBulkItem{
				Row:      row,
				Username: item.Username,
				Status:   "failed",
				Error:    "invalid_phone",
			})
			continue
		}
		created, err := s.CreateUser(ctx, item)
		if err != nil {
			errLabel := "create_failed"
			if errors.Is(err, ErrConflict) {
				errLabel = "conflict"
			}
			resp.Failed++
			resp.Items = append(resp.Items, dto.AdminUserBulkItem{
				Row:      row,
				Username: item.Username,
				Status:   "failed",
				Error:    errLabel,
			})
			continue
		}
		resp.Created++
		resp.Items = append(resp.Items, dto.AdminUserBulkItem{
			Row:      row,
			Username: created.Username,
			ID:       created.ID,
			Status:   "created",
		})
	}
	return resp, nil
}

func (s *Service) UpdateUser(ctx context.Context, id string, req dto.AdminUserUpdateRequest) (dto.AdminUserResponse, error) {
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AdminUserResponse{}, ErrNotFound
		}
		return dto.AdminUserResponse{}, err
	}
	if req.Email != "" {
		if found, err := s.users.GetByEmail(ctx, req.Email); err == nil && found.ID != id {
			return dto.AdminUserResponse{}, ErrConflict
		} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return dto.AdminUserResponse{}, err
		}
	}
	if req.Phone != "" {
		if found, err := s.users.GetByPhone(ctx, req.Phone); err == nil && found.ID != id {
			return dto.AdminUserResponse{}, ErrConflict
		} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return dto.AdminUserResponse{}, err
		}
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
	if _, err := s.users.GetByID(ctx, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.users.Delete(ctx, id)
}

func (s *Service) CreateInvite(ctx context.Context, req dto.AdminInviteCreateRequest) (dto.AdminInviteResponse, error) {
	if s.invites == nil {
		return dto.AdminInviteResponse{}, ErrNotImplemented
	}
	email := strings.TrimSpace(req.Email)
	phone := strings.TrimSpace(req.Phone)
	if email == "" && phone == "" {
		return dto.AdminInviteResponse{}, ErrInvalidInput
	}
	if email != "" && !validator.IsEmailValid(validator.NormalizeEmail(email)) {
		return dto.AdminInviteResponse{}, ErrInvalidInput
	}
	if phone != "" && !validator.IsPhoneValid(validator.NormalizePhone(phone)) {
		return dto.AdminInviteResponse{}, ErrInvalidInput
	}
	role := req.Role
	if role == "" {
		role = models.RoleUser
	}
	ttl := req.TTLMinutes
	if ttl <= 0 {
		ttl = 1440
	}
	now := time.Now()
	token := generateInviteToken()
	tokenHash := inviteHash(token)
	invite := &models.Invite{
		ID:        uuid.NewString(),
		TokenHash: tokenHash,
		Email:     validator.NormalizeEmail(email),
		Phone:     validator.NormalizePhone(phone),
		Role:      role,
		Status:    models.InvitePending,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Minute),
		CreatedAt: now,
	}
	if err := s.invites.Create(ctx, invite); err != nil {
		return dto.AdminInviteResponse{}, err
	}
	return dto.AdminInviteResponse{
		ID:        invite.ID,
		Token:     token,
		Email:     invite.Email,
		Phone:     invite.Phone,
		Role:      invite.Role,
		ExpiresAt: invite.ExpiresAt.Unix(),
	}, nil
}

func generateInviteToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return uuid.NewString()
	}
	return hex.EncodeToString(buf)
}

func inviteHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
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
	if _, err := s.policies.GetByName(ctx, req.Name); err == nil {
		return dto.AdminPolicyDTO{}, ErrConflict
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.AdminPolicyDTO{}, err
	}
	now := time.Now()
	policy := &models.Policy{
		ID:        uuid.NewString(),
		Name:      req.Name,
		Priority:  req.Priority,
		Status:    req.Status,
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
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AdminPolicyDTO{}, ErrNotFound
		}
		return dto.AdminPolicyDTO{}, err
	}
	if req.Name != "" && req.Name != policy.Name {
		if _, err := s.policies.GetByName(ctx, req.Name); err == nil {
			return dto.AdminPolicyDTO{}, ErrConflict
		} else if !errors.Is(err, repository.ErrNotFound) {
			return dto.AdminPolicyDTO{}, err
		}
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
	if _, err := s.policies.GetByID(ctx, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
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
	if _, err := s.radiusClients.GetByIP(ctx, req.IP); err == nil {
		return dto.AdminRadiusClientDTO{}, ErrConflict
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.AdminRadiusClientDTO{}, err
	}
	now := time.Now()
	client := &models.RadiusClient{
		ID:        uuid.NewString(),
		Name:      req.Name,
		IP:        req.IP,
		Secret:    req.Secret,
		Enabled:   req.Enabled,
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
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AdminRadiusClientDTO{}, ErrNotFound
		}
		return dto.AdminRadiusClientDTO{}, err
	}
	if req.Name == "" && req.Secret == "" && req.Enabled == client.Enabled {
		// noop
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
	if _, err := s.radiusClients.GetByID(ctx, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
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

func (s *Service) ListGroups(ctx context.Context, req dto.PageRequest) (dto.AdminGroupListResponse, error) {
	items, total, err := s.groups.List(ctx, req.Limit, req.Offset)
	if err != nil {
		return dto.AdminGroupListResponse{}, err
	}
	out := make([]dto.AdminGroupResponse, 0, len(items))
	for _, g := range items {
		out = append(out, dto.AdminGroupResponse{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
		})
	}
	return dto.AdminGroupListResponse{
		Items: out,
		Page:  dto.PageResponse{Total: total, Limit: req.Limit, Offset: req.Offset},
	}, nil
}

func (s *Service) CreateGroup(ctx context.Context, req dto.AdminGroupCreateRequest) (dto.AdminGroupResponse, error) {
	if _, err := s.groups.GetByName(ctx, req.Name); err == nil {
		return dto.AdminGroupResponse{}, ErrConflict
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.AdminGroupResponse{}, err
	}
	g := &models.Group{
		ID:          uuid.NewString(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
	}
	if err := s.groups.Create(ctx, g); err != nil {
		return dto.AdminGroupResponse{}, err
	}
	return dto.AdminGroupResponse{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
	}, nil
}

func (s *Service) UpdateGroup(ctx context.Context, id string, req dto.AdminGroupUpdateRequest) (dto.AdminGroupResponse, error) {
	g, err := s.groups.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AdminGroupResponse{}, ErrNotFound
		}
		return dto.AdminGroupResponse{}, err
	}
	if req.Name != "" && req.Name != g.Name {
		if _, err := s.groups.GetByName(ctx, req.Name); err == nil {
			return dto.AdminGroupResponse{}, ErrConflict
		} else if !errors.Is(err, repository.ErrNotFound) {
			return dto.AdminGroupResponse{}, err
		}
		g.Name = req.Name
	}
	if req.Description != "" {
		g.Description = req.Description
	}
	if err := s.groups.Update(ctx, g); err != nil {
		return dto.AdminGroupResponse{}, err
	}
	return dto.AdminGroupResponse{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
	}, nil
}

func (s *Service) DeleteGroup(ctx context.Context, id string) error {
	if _, err := s.groups.GetByID(ctx, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	_ = s.groupPolicies.ClearPolicy(ctx, id)
	return s.groups.Delete(ctx, id)
}

func (s *Service) AddGroupMember(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error {
	return s.userGroups.AddUser(ctx, groupID, req.UserID)
}

func (s *Service) RemoveGroupMember(ctx context.Context, groupID string, req dto.AdminGroupMemberRequest) error {
	return s.userGroups.RemoveUser(ctx, groupID, req.UserID)
}

func (s *Service) ListGroupMembers(ctx context.Context, groupID string, page dto.PageRequest) (dto.AdminGroupMembersResponse, error) {
	users, total, err := s.userGroups.ListUsers(ctx, groupID, page.Limit, page.Offset)
	if err != nil {
		return dto.AdminGroupMembersResponse{}, err
	}
	items := make([]dto.AdminUserListItem, 0, len(users))
	for _, u := range users {
		items = append(items, dto.AdminUserListItem{
			ID:       u.ID,
			Username: u.Username,
			Email:    u.Email,
			Phone:    u.Phone,
			Status:   u.Status,
			Role:     u.Role,
		})
	}
	return dto.AdminGroupMembersResponse{
		Items: items,
		Page:  dto.PageResponse{Total: total, Limit: page.Limit, Offset: page.Offset},
	}, nil
}

func (s *Service) SetGroupPolicy(ctx context.Context, groupID string, req dto.AdminGroupPolicyRequest) error {
	return s.groupPolicies.SetPolicy(ctx, groupID, req.PolicyID)
}

func (s *Service) ClearGroupPolicy(ctx context.Context, groupID string) error {
	return s.groupPolicies.ClearPolicy(ctx, groupID)
}

func (s *Service) ListAuditEvents(ctx context.Context, req dto.AdminAuditListRequest) (dto.AdminAuditListResponse, error) {
	items, total, err := s.audit.List(ctx, repository.AuditFilter{
		ActorUserID: req.Filter.ActorUserID,
		EntityType:  req.Filter.EntityType,
		Action:      req.Filter.Action,
		EntityID:    req.Filter.EntityID,
		IP:          req.Filter.IP,
		Payload:     req.Filter.Payload,
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
			Payload:     e.Payload,
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
		UserID:   req.Filter.UserID,
		Channel:  req.Filter.Channel,
		Result:   req.Filter.Result,
		IP:       req.Filter.IP,
		DeviceID: req.Filter.DeviceID,
		From:     req.Filter.From,
		To:       req.Filter.To,
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

func (s *Service) ListSessions(ctx context.Context, req dto.AdminSessionListRequest) (dto.AdminSessionListResponse, error) {
	items, total, err := s.sessions.List(ctx, repository.SessionListFilter{
		UserID:     req.Filter.UserID,
		ActiveOnly: req.Filter.ActiveOnly,
		IP:         req.Filter.IP,
		UserAgent:  req.Filter.UserAgent,
	}, req.Page.Limit, req.Page.Offset)
	if err != nil {
		return dto.AdminSessionListResponse{}, err
	}
	out := make([]dto.AdminSessionDTO, 0, len(items))
	for _, item := range items {
		out = append(out, dto.AdminSessionDTO{
			ID:         item.ID,
			UserID:     item.UserID,
			IP:         item.IP,
			UserAgent:  item.UserAgent,
			CreatedAt:  item.CreatedAt,
			ExpiresAt:  item.ExpiresAt,
			LastSeenAt: item.LastSeenAt,
			RevokedAt:  item.RevokedAt,
		})
	}
	return dto.AdminSessionListResponse{
		Items: out,
		Page:  dto.PageResponse{Total: total, Limit: req.Page.Limit, Offset: req.Page.Offset},
	}, nil
}

func (s *Service) RevokeSession(ctx context.Context, actorUserID string, sessionID string, ip string) error {
	if err := s.sessions.Revoke(ctx, sessionID, time.Now()); err != nil {
		return err
	}
	s.auditEvent(ctx, actorUserID, models.AuditSessionRevoke, models.AuditEntitySession, sessionID, ip)
	return nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, actorUserID string, userID string, exceptSessionID string, ip string) error {
	if err := s.sessions.RevokeAllByUser(ctx, userID, exceptSessionID, time.Now()); err != nil {
		return err
	}
	s.auditEvent(ctx, actorUserID, models.AuditSessionRevokeAll, models.AuditEntityUser, userID, ip)
	return nil
}

func (s *Service) auditEvent(ctx context.Context, actorUserID string, action models.AuditAction, entityType models.AuditEntityType, entityID string, ip string) {
	if s.audit == nil || actorUserID == "" {
		return
	}
	_ = s.audit.Create(ctx, &models.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: actorUserID,
		Action:      action,
		EntityType:  entityType,
		EntityID:    entityID,
		IP:          ip,
		CreatedAt:   time.Now(),
	})
}

func (s *Service) ListLockouts(ctx context.Context, req dto.AdminLockoutListRequest) (dto.AdminLockoutListResponse, error) {
	items, total, err := s.lockouts.List(ctx, repository.LockoutFilter{
		UserID:     req.Filter.UserID,
		IP:         req.Filter.IP,
		Reason:     req.Filter.Reason,
		ActiveOnly: req.Filter.ActiveOnly,
		Now:        time.Now(),
	}, req.Page.Limit, req.Page.Offset)
	if err != nil {
		return dto.AdminLockoutListResponse{}, err
	}
	out := make([]dto.AdminLockoutDTO, 0, len(items))
	for _, item := range items {
		out = append(out, dto.AdminLockoutDTO{
			ID:        item.ID,
			UserID:    item.UserID,
			IP:        item.IP,
			Reason:    item.Reason,
			ExpiresAt: item.ExpiresAt,
			CreatedAt: item.CreatedAt,
		})
	}
	return dto.AdminLockoutListResponse{
		Items: out,
		Page:  dto.PageResponse{Total: total, Limit: req.Page.Limit, Offset: req.Page.Offset},
	}, nil
}

func (s *Service) ClearLockouts(ctx context.Context, actorUserID string, req dto.AdminLockoutClearRequest) error {
	filter := repository.LockoutFilter{
		UserID: req.UserID,
		IP:     req.IP,
		Reason: req.Reason,
	}
	if err := s.lockouts.ClearByFilter(ctx, filter); err != nil {
		return err
	}
	if s.audit != nil && actorUserID != "" {
		payload, _ := json.Marshal(map[string]string{
			"user_id": req.UserID,
			"ip":      req.IP,
			"reason":  req.Reason,
		})
		_ = s.audit.Create(ctx, &models.AuditEvent{
			ID:          uuid.NewString(),
			ActorUserID: actorUserID,
			Action:      models.AuditLockoutClear,
			EntityType:  models.AuditEntityLockout,
			EntityID:    req.UserID,
			Payload:     string(payload),
			CreatedAt:   time.Now(),
		})
	}
	return nil
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
