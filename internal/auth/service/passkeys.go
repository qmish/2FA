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
	BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	ValidatePasskeyLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, parsed *protocol.ParsedCredentialAssertionData) (webauthn.User, *webauthn.Credential, error)
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

func (r *realWebAuthnAdapter) BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return r.handler.BeginDiscoverableLogin(opts...)
}

func (r *realWebAuthnAdapter) ValidatePasskeyLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, parsed *protocol.ParsedCredentialAssertionData) (webauthn.User, *webauthn.Credential, error) {
	return r.handler.ValidatePasskeyLogin(handler, session, parsed)
}

type webauthnSessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
	id        string
}

func (s *Service) WithWebAuthn(handler *webauthn.WebAuthn, repo repository.WebAuthnCredentialRepository, sessions repository.WebAuthnSessionRepository) *Service {
	if handler != nil {
		s.webauthnAdapter = &realWebAuthnAdapter{handler: handler}
		s.webauthnParseCreation = protocol.ParseCredentialCreationResponseBytes
		s.webauthnParseAssertion = protocol.ParseCredentialRequestResponseBytes
	}
	s.webauthnCreds = repo
	s.webauthnSessions = sessions
	return s
}

func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID string) (dto.PasskeyRegisterBeginResponse, error) {
	if s.webauthnAdapter == nil || s.webauthnCreds == nil || s.webauthnSessions == nil {
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
	if err := s.storeWebAuthnSession(ctx, "register", userID, "", session); err != nil {
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	payload, err := json.Marshal(creation)
	if err != nil {
		return dto.PasskeyRegisterBeginResponse{}, err
	}
	return dto.PasskeyRegisterBeginResponse{Options: payload}, nil
}

func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID string, credential json.RawMessage) error {
	if s.webauthnAdapter == nil || s.webauthnCreds == nil || s.webauthnParseCreation == nil || s.webauthnSessions == nil {
		return ErrNotConfigured
	}
	if userID == "" {
		return ErrNotFound
	}
	entry, err := s.takeWebAuthnSession(ctx, "register", userID, "")
	if err != nil {
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

func (s *Service) BeginPasskeyLogin(ctx context.Context) (dto.PasskeyLoginBeginResponse, error) {
	if s.webauthnAdapter == nil || s.webauthnCreds == nil || s.webauthnSessions == nil {
		return dto.PasskeyLoginBeginResponse{}, ErrNotConfigured
	}
	assertion, session, err := s.webauthnAdapter.BeginDiscoverableLogin()
	if err != nil {
		return dto.PasskeyLoginBeginResponse{}, err
	}
	payload, err := json.Marshal(assertion)
	if err != nil {
		return dto.PasskeyLoginBeginResponse{}, err
	}
	sessionID := uuid.NewString()
	if err := s.storeWebAuthnSession(ctx, "login", "", sessionID, session); err != nil {
		return dto.PasskeyLoginBeginResponse{}, err
	}
	return dto.PasskeyLoginBeginResponse{Options: payload, SessionID: sessionID}, nil
}

func (s *Service) FinishPasskeyLogin(ctx context.Context, sessionID string, credential json.RawMessage, ip string, userAgent string) (dto.TokenPair, error) {
	if s.webauthnAdapter == nil || s.webauthnCreds == nil || s.webauthnParseAssertion == nil || s.webauthnSessions == nil {
		return dto.TokenPair{}, ErrNotConfigured
	}
	if sessionID == "" {
		return dto.TokenPair{}, ErrChallengeNotFound
	}
	entry, err := s.takeWebAuthnSession(ctx, "login", "", sessionID)
	if err != nil {
		return dto.TokenPair{}, ErrChallengeNotFound
	}
	if s.now().After(entry.expiresAt) {
		return dto.TokenPair{}, ErrChallengeExpired
	}
	parsed, err := s.webauthnParseAssertion(credential)
	if err != nil {
		return dto.TokenPair{}, err
	}
	handler := func(rawID []byte, userHandle []byte) (webauthn.User, error) {
		credID := base64.RawURLEncoding.EncodeToString(rawID)
		cred, err := s.webauthnCreds.GetByCredentialID(ctx, credID)
		if err != nil {
			return nil, err
		}
		user, err := s.users.GetByID(ctx, cred.UserID)
		if err != nil {
			return nil, err
		}
		items, err := s.webauthnCreds.ListByUser(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		return newWebAuthnUser(user, items)
	}
	user, credentialObj, err := s.webauthnAdapter.ValidatePasskeyLogin(handler, *entry.data, parsed)
	if err != nil {
		return dto.TokenPair{}, err
	}
	waUser, ok := user.(*webauthnUser)
	if !ok {
		return dto.TokenPair{}, ErrNotFound
	}
	now := s.now()
	credID := base64.RawURLEncoding.EncodeToString(credentialObj.ID)
	cred, err := s.webauthnCreds.GetByCredentialID(ctx, credID)
	if err == nil {
		_ = s.webauthnCreds.UpdateSignCount(ctx, cred.ID, int64(credentialObj.Authenticator.SignCount), now)
	}
	userModel, err := s.users.GetByID(ctx, waUser.id)
	if err != nil {
		return dto.TokenPair{}, ErrNotFound
	}
	if s.jwt == nil {
		return dto.TokenPair{}, ErrSecondFactorFailed
	}
	if ip != "" {
		s.recordLoginResult(ctx, userModel.ID, "", ip, models.AuthSuccess)
	}
	s.recordDevice(ctx, userModel.ID, userAgent)
	refresh := newToken()
	session := &models.UserSession{
		ID:               s.tokenGen(),
		UserID:           userModel.ID,
		RefreshTokenHash: hash(refresh),
		IP:               ip,
		UserAgent:        userAgent,
		ExpiresAt:        now.Add(s.sessionTTL),
		CreatedAt:        now,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return dto.TokenPair{}, err
	}
	accessToken, accessExp, err := s.jwt.Sign(session.UserID, session.ID)
	if err != nil {
		return dto.TokenPair{}, err
	}
	return dto.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refresh,
		ExpiresIn:    int64(accessExp.Sub(s.now()).Seconds()),
	}, nil
}

func (s *Service) storeWebAuthnSession(ctx context.Context, kind string, userID string, sessionID string, data *webauthn.SessionData) error {
	if data == nil {
		return nil
	}
	if s.webauthnSessions == nil {
		return ErrNotConfigured
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	now := s.now()
	if kind == "register" && userID != "" {
		_ = s.webauthnSessions.DeleteByTypeAndUser(ctx, kind, userID)
	}
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	return s.webauthnSessions.Create(ctx, &models.WebAuthnSession{
		ID:        sessionID,
		Type:      kind,
		UserID:    userID,
		Data:      string(payload),
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
	})
}

func (s *Service) takeWebAuthnSession(ctx context.Context, kind string, userID string, sessionID string) (webauthnSessionEntry, error) {
	if s.webauthnSessions == nil {
		return webauthnSessionEntry{}, ErrNotConfigured
	}
	var (
		item *models.WebAuthnSession
		err  error
	)
	if sessionID != "" {
		item, err = s.webauthnSessions.GetByID(ctx, sessionID)
	} else {
		item, err = s.webauthnSessions.GetByTypeAndUser(ctx, kind, userID)
	}
	if err != nil {
		return webauthnSessionEntry{}, err
	}
	_ = s.webauthnSessions.DeleteByID(ctx, item.ID)
	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(item.Data), &data); err != nil {
		return webauthnSessionEntry{}, err
	}
	return webauthnSessionEntry{
		id:        item.ID,
		data:      &data,
		expiresAt: item.ExpiresAt,
	}, nil
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
