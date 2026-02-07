package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

type webauthnAdapter interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	CreateCredential(user webauthn.User, session webauthn.SessionData, parsed *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error)
}

type realWebAuthnAdapter struct {
	handler *webauthn.WebAuthn
}

func (r *realWebAuthnAdapter) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return r.handler.BeginRegistration(user, opts...)
}

func (r *realWebAuthnAdapter) CreateCredential(user webauthn.User, session webauthn.SessionData, parsed *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	return r.handler.CreateCredential(user, session, parsed)
}

type webauthnSessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

func (s *Service) WithWebAuthn(handler *webauthn.WebAuthn, repo repository.WebAuthnCredentialRepository) *Service {
	if handler != nil {
		s.webauthnAdapter = &realWebAuthnAdapter{handler: handler}
		s.webauthnParseCreation = protocol.ParseCredentialCreationResponseBytes
	}
	s.webauthnCreds = repo
	if s.webauthnSessions == nil {
		s.webauthnSessions = map[string]webauthnSessionEntry{}
	}
	return s
}

func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID string) (dto.PasskeyRegisterBeginResponse, error) {
	if s.webauthnAdapter == nil || s.webauthnCreds == nil {
		return dto.PasskeyRegisterBeginResponse{}, ErrNotConfigured
	}
	if userID == "" {
		return dto.PasskeyRegisterBeginResponse{}, ErrNotFound
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.PasskeyRegisterBeginResponse{}, ErrNotFound
		}
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	items, err := s.webauthnCreds.ListByUser(ctx, userID)
	if err != nil {
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	waUser, err := newWebAuthnUser(user, items)
	if err != nil {
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(waUser.WebAuthnCredentials()).CredentialDescriptors()),
	}
	creation, session, err := s.webauthnAdapter.BeginRegistration(waUser, opts...)
	if err != nil {
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	s.storeWebAuthnSession("register", userID, session)
	payload, err := json.Marshal(creation)
	if err != nil {
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	return dto.PasskeyRegisterBeginResponse{Options: payload}, nil
}

func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID string, credential json.RawMessage) error {
	if s.webauthnAdapter == nil || s.webauthnCreds == nil || s.webauthnParseCreation == nil {
		return ErrNotConfigured
	}
	if userID == "" {
		return ErrNotFound
	}
	entry, ok := s.takeWebAuthnSession("register", userID)
	if !ok {
		return ErrChallengeNotFound
	}
	if s.now().After(entry.expiresAt) {
		return ErrChallengeExpired
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	items, err := s.webauthnCreds.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	waUser, err := newWebAuthnUser(user, items)
	if err != nil {
		return err
	}
	parsed, err := s.webauthnParseCreation(credential)
	if err != nil {
		return err
	}
	cred, err := s.webauthnAdapter.CreateCredential(waUser, *entry.data, parsed)
	if err != nil {
		return err
	}
	now := s.now()
	item := &models.WebAuthnCredential{
		ID:           uuid.NewString(),
		UserID:       userID,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:    base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		SignCount:    int64(cred.Authenticator.SignCount),
		CreatedAt:    now,
	}
	return s.webauthnCreds.Create(ctx, item)
}

func (s *Service) storeWebAuthnSession(kind string, userID string, data *webauthn.SessionData) {
	if data == nil {
		return
	}
	s.webauthnMu.Lock()
	defer s.webauthnMu.Unlock()
	if s.webauthnSessions == nil {
		s.webauthnSessions = map[string]webauthnSessionEntry{}
	}
	s.webauthnSessions[kind+":"+userID] = webauthnSessionEntry{
		data:      data,
		expiresAt: s.now().Add(s.ttl),
	}
}

func (s *Service) takeWebAuthnSession(kind string, userID string) (webauthnSessionEntry, bool) {
	s.webauthnMu.Lock()
	defer s.webauthnMu.Unlock()
	key := kind + ":" + userID
	entry, ok := s.webauthnSessions[key]
	if ok {
		delete(s.webauthnSessions, key)
	}
	return entry, ok
}

type webauthnUser struct {
	id          string
	name        string
	displayName string
	credentials []webauthn.Credential
}

func newWebAuthnUser(user *models.User, creds []models.WebAuthnCredential) (*webauthnUser, error) {
	if user == nil {
		return nil, ErrNotFound
	}
	items := make([]webauthn.Credential, 0, len(creds))
	for _, item := range creds {
		id, err := base64.RawURLEncoding.DecodeString(item.CredentialID)
		if err != nil {
			return nil, err
		}
		pk, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err != nil {
			return nil, err
		}
		items = append(items, webauthn.Credential{
			ID:        id,
			PublicKey: pk,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(item.SignCount),
			},
		})
	}
	display := user.Username
	if display == "" {
		display = user.Email
	}
	if display == "" {
		display = user.Phone
	}
	return &webauthnUser{
		id:          user.ID,
		name:        user.Username,
		displayName: display,
		credentials: items,
	}, nil
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.id)
}

func (u *webauthnUser) WebAuthnName() string {
	return u.name
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}
