package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
	"github.com/qmish/2FA/pkg/validator"
)

func (s *Service) Register(ctx context.Context, req dto.RegisterRequest) (dto.RegisterResponse, error) {
	if s.invites == nil {
		return dto.RegisterResponse{}, ErrNotConfigured
	}
	token := strings.TrimSpace(req.Token)
	username := strings.TrimSpace(req.Username)
	if token == "" || username == "" || req.Password == "" {
		return dto.RegisterResponse{}, ErrInvalidCredentials
	}
	tokenHash := hash(token)
	invite, err := s.invites.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return dto.RegisterResponse{}, ErrInviteInvalid
	}
	if invite.Status != models.InvitePending {
		return dto.RegisterResponse{}, ErrInviteInvalid
	}
	if s.now().After(invite.ExpiresAt) {
		_, _ = s.invites.MarkExpired(ctx, s.now())
		return dto.RegisterResponse{}, ErrInviteInvalid
	}
	email := validator.NormalizeEmail(req.Email)
	phone := validator.NormalizePhone(req.Phone)
	if invite.Email != "" {
		if email == "" {
			email = invite.Email
		} else if !strings.EqualFold(email, invite.Email) {
			return dto.RegisterResponse{}, ErrInviteInvalid
		}
	}
	if invite.Phone != "" {
		if phone == "" {
			phone = invite.Phone
		} else if phone != invite.Phone {
			return dto.RegisterResponse{}, ErrInviteInvalid
		}
	}
	if email != "" && !validator.IsEmailValid(email) {
		return dto.RegisterResponse{}, ErrInvalidCredentials
	}
	if phone != "" && !validator.IsPhoneValid(phone) {
		return dto.RegisterResponse{}, ErrInvalidCredentials
	}
	if _, err := s.users.GetByUsername(ctx, username); err == nil {
		return dto.RegisterResponse{}, ErrConflict
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.RegisterResponse{}, err
	}
	if email != "" {
		if _, err := s.users.GetByEmail(ctx, email); err == nil {
			return dto.RegisterResponse{}, ErrConflict
		} else if !errors.Is(err, repository.ErrNotFound) {
			return dto.RegisterResponse{}, err
		}
	}
	if phone != "" {
		if _, err := s.users.GetByPhone(ctx, phone); err == nil {
			return dto.RegisterResponse{}, ErrConflict
		} else if !errors.Is(err, repository.ErrNotFound) {
			return dto.RegisterResponse{}, err
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return dto.RegisterResponse{}, err
	}
	now := s.now()
	user := &models.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        email,
		Phone:        phone,
		Status:       models.UserActive,
		Role:         invite.Role,
		PasswordHash: string(hash),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return dto.RegisterResponse{}, err
	}
	if err := s.invites.MarkUsed(ctx, invite.ID, user.ID, now); err != nil {
		return dto.RegisterResponse{}, err
	}
	if s.audits != nil {
		_ = s.audits.Create(ctx, &models.AuditEvent{
			ID:          s.tokenGen(),
			ActorUserID: user.ID,
			Action:      models.AuditCreate,
			EntityType:  models.AuditEntityUser,
			EntityID:    user.ID,
			Payload:     user.Username,
			CreatedAt:   now,
		})
	}
	return dto.RegisterResponse{UserID: user.ID}, nil
}
