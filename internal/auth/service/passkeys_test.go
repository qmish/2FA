package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/qmish/2FA/internal/auth/jwt"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

func TestPasskeyRegisterBeginNotConfigured(t *testing.T) {
	svc := NewService(fakeUserRepo{}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	if _, err := svc.BeginPasskeyRegistration(context.Background(), "u1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestPasskeyRegisterBeginStoresSession(t *testing.T) {
	user := &models.User{ID: "u1", Username: "alice"}
	svc := NewService(fakeUserRepo{user: user}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	adapter := &fakeWebAuthnAdapter{
		beginCreation: &protocol.CredentialCreation{},
		beginSession:  &webauthn.SessionData{Challenge: "challenge"},
	}
	creds := &fakeWebAuthnCredentialRepo{}
	svc.webauthnAdapter = adapter
	svc.webauthnCreds = creds
	svc.webauthnSessions = &fakeWebAuthnSessionRepo{}

	resp, err := svc.BeginPasskeyRegistration(context.Background(), "u1")
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration error: %v", err)
	}
	if len(resp.Options) == 0 {
		t.Fatalf("expected options payload")
	}
	repo, ok := svc.webauthnSessions.(*fakeWebAuthnSessionRepo)
	if !ok || repo.itemsByTypeUser["register:u1"] == nil {
		t.Fatalf("expected session stored")
	}
}

func TestPasskeyRegisterFinishNotConfigured(t *testing.T) {
	svc := NewService(fakeUserRepo{}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	if err := svc.FinishPasskeyRegistration(context.Background(), "u1", json.RawMessage(`{}`)); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestPasskeyRegisterFinishStoresCredential(t *testing.T) {
	user := &models.User{ID: "u1", Username: "alice"}
	svc := NewService(fakeUserRepo{user: user}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	adapter := &fakeWebAuthnAdapter{
		created: &webauthn.Credential{
			ID:        []byte("cred"),
			PublicKey: []byte("pk"),
			Authenticator: webauthn.Authenticator{
				SignCount: 7,
			},
		},
	}
	creds := &fakeWebAuthnCredentialRepo{}
	svc.webauthnAdapter = adapter
	svc.webauthnCreds = creds
	svc.webauthnParseCreation = func(data []byte) (*protocol.ParsedCredentialCreationData, error) {
		return &protocol.ParsedCredentialCreationData{}, nil
	}
	svc.webauthnSessions = &fakeWebAuthnSessionRepo{
		itemsByTypeUser: map[string]*models.WebAuthnSession{
			"register:u1": {
				ID:        "s1",
				Type:      "register",
				UserID:    "u1",
				Data:      `{"challenge":"challenge"}`,
				ExpiresAt: time.Now().Add(time.Minute),
			},
		},
	}

	if err := svc.FinishPasskeyRegistration(context.Background(), "u1", json.RawMessage(`{"id":"x"}`)); err != nil {
		t.Fatalf("FinishPasskeyRegistration error: %v", err)
	}
	if creds.created == nil {
		t.Fatalf("expected credential stored")
	}
	if creds.created.CredentialID != base64.RawURLEncoding.EncodeToString([]byte("cred")) {
		t.Fatalf("unexpected credential id: %s", creds.created.CredentialID)
	}
	if creds.created.PublicKey != base64.RawURLEncoding.EncodeToString([]byte("pk")) {
		t.Fatalf("unexpected public key: %s", creds.created.PublicKey)
	}
	if creds.created.SignCount != 7 {
		t.Fatalf("unexpected sign count: %d", creds.created.SignCount)
	}
}

func TestPasskeyLoginBeginNotConfigured(t *testing.T) {
	svc := NewService(fakeUserRepo{}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	if _, err := svc.BeginPasskeyLogin(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestPasskeyLoginBeginStoresSession(t *testing.T) {
	svc := NewService(fakeUserRepo{}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	adapter := &fakeWebAuthnAdapter{
		beginAssertion: &protocol.CredentialAssertion{},
		beginSession:   &webauthn.SessionData{Challenge: "challenge"},
	}
	svc.webauthnAdapter = adapter
	svc.webauthnCreds = &fakeWebAuthnCredentialRepo{}
	svc.webauthnSessions = &fakeWebAuthnSessionRepo{}

	resp, err := svc.BeginPasskeyLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginPasskeyLogin error: %v", err)
	}
	if resp.SessionID == "" || len(resp.Options) == 0 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	repo, ok := svc.webauthnSessions.(*fakeWebAuthnSessionRepo)
	if !ok || repo.itemsByID[resp.SessionID] == nil {
		t.Fatalf("expected session stored")
	}
}

func TestPasskeyLoginFinishNotConfigured(t *testing.T) {
	svc := NewService(fakeUserRepo{}, nil, nil, nil, nil, nil, nil, nil, time.Minute, time.Hour)
	if _, err := svc.FinishPasskeyLogin(context.Background(), "s1", json.RawMessage(`{}`), "127.0.0.1", "ua"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestPasskeyLoginFinishOK(t *testing.T) {
	user := &models.User{ID: "u1", Username: "alice", Status: models.UserActive}
	sessions := &fakeSessionRepo{}
	jwtSvc := jwt.NewService("2fa", []byte("secret"), time.Minute)
	svc := NewService(fakeUserRepo{user: user}, nil, sessions, nil, nil, &fakeLoginHistoryRepo{}, &fakeAuditRepo{}, jwtSvc, time.Minute, time.Hour)
	adapter := &fakeWebAuthnAdapter{
		validUser: &webauthnUser{id: "u1", name: "alice"},
		validCredential: &webauthn.Credential{
			ID:        []byte("cred"),
			PublicKey: []byte("pk"),
			Authenticator: webauthn.Authenticator{
				SignCount: 9,
			},
		},
	}
	creds := &fakeWebAuthnCredentialRepo{
		getByID: &models.WebAuthnCredential{ID: "c1", UserID: "u1", CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred"))},
		items: []models.WebAuthnCredential{
			{ID: "c1", UserID: "u1", CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred")), PublicKey: base64.RawURLEncoding.EncodeToString([]byte("pk"))},
		},
	}
	svc.webauthnAdapter = adapter
	svc.webauthnCreds = creds
	svc.webauthnParseAssertion = func(data []byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{
			ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
				RawID: []byte("cred"),
			},
			Response: protocol.ParsedAssertionResponse{
				UserHandle: []byte("u1"),
			},
		}, nil
	}
	svc.webauthnSessions = &fakeWebAuthnSessionRepo{
		itemsByID: map[string]*models.WebAuthnSession{
			"s1": {
				ID:        "s1",
				Type:      "login",
				Data:      `{"challenge":"challenge"}`,
				ExpiresAt: time.Now().Add(time.Minute),
			},
		},
	}

	resp, err := svc.FinishPasskeyLogin(context.Background(), "s1", json.RawMessage(`{"id":"x"}`), "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("FinishPasskeyLogin error: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("expected tokens")
	}
	if creds.updatedID != "c1" || creds.updatedCount != 9 {
		t.Fatalf("expected sign count update, got %+v", creds)
	}
}

type fakeWebAuthnAdapter struct {
	beginCreation   *protocol.CredentialCreation
	beginSession    *webauthn.SessionData
	beginErr        error
	created         *webauthn.Credential
	createErr       error
	beginAssertion  *protocol.CredentialAssertion
	validUser       webauthn.User
	validCredential *webauthn.Credential
}

func (f *fakeWebAuthnAdapter) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return f.beginCreation, f.beginSession, f.beginErr
}

func (f *fakeWebAuthnAdapter) CreateCredential(user webauthn.User, session webauthn.SessionData, parsed *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	return f.created, f.createErr
}

func (f *fakeWebAuthnAdapter) BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return f.beginAssertion, f.beginSession, f.beginErr
}

func (f *fakeWebAuthnAdapter) ValidatePasskeyLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, parsed *protocol.ParsedCredentialAssertionData) (webauthn.User, *webauthn.Credential, error) {
	if f.validUser != nil || f.validCredential != nil {
		return f.validUser, f.validCredential, nil
	}
	user, err := handler(parsed.RawID, parsed.Response.UserHandle)
	return user, nil, err
}

type fakeWebAuthnCredentialRepo struct {
	created      *models.WebAuthnCredential
	items        []models.WebAuthnCredential
	getByID      *models.WebAuthnCredential
	updatedID    string
	updatedCount int64
}

func (f *fakeWebAuthnCredentialRepo) Create(ctx context.Context, cred *models.WebAuthnCredential) error {
	f.created = cred
	return nil
}
func (f *fakeWebAuthnCredentialRepo) ListByUser(ctx context.Context, userID string) ([]models.WebAuthnCredential, error) {
	return f.items, nil
}
func (f *fakeWebAuthnCredentialRepo) DeleteByID(ctx context.Context, userID string, id string) (bool, error) {
	return false, nil
}
func (f *fakeWebAuthnCredentialRepo) GetByCredentialID(ctx context.Context, credentialID string) (*models.WebAuthnCredential, error) {
	if f.getByID != nil && f.getByID.CredentialID == credentialID {
		return f.getByID, nil
	}
	return nil, repository.ErrNotFound
}
func (f *fakeWebAuthnCredentialRepo) UpdateSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	f.updatedID = id
	f.updatedCount = signCount
	return nil
}

type fakeWebAuthnSessionRepo struct {
	itemsByID       map[string]*models.WebAuthnSession
	itemsByTypeUser map[string]*models.WebAuthnSession
}

func (f *fakeWebAuthnSessionRepo) Create(ctx context.Context, session *models.WebAuthnSession) error {
	if f.itemsByID == nil {
		f.itemsByID = map[string]*models.WebAuthnSession{}
	}
	f.itemsByID[session.ID] = session
	if session.Type != "" && session.UserID != "" {
		if f.itemsByTypeUser == nil {
			f.itemsByTypeUser = map[string]*models.WebAuthnSession{}
		}
		f.itemsByTypeUser[session.Type+":"+session.UserID] = session
	}
	return nil
}

func (f *fakeWebAuthnSessionRepo) GetByTypeAndUser(ctx context.Context, sessionType string, userID string) (*models.WebAuthnSession, error) {
	if f.itemsByTypeUser == nil {
		return nil, repository.ErrNotFound
	}
	item, ok := f.itemsByTypeUser[sessionType+":"+userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return item, nil
}

func (f *fakeWebAuthnSessionRepo) GetByID(ctx context.Context, id string) (*models.WebAuthnSession, error) {
	if f.itemsByID == nil {
		return nil, repository.ErrNotFound
	}
	item, ok := f.itemsByID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return item, nil
}

func (f *fakeWebAuthnSessionRepo) DeleteByID(ctx context.Context, id string) error {
	if f.itemsByID != nil {
		delete(f.itemsByID, id)
	}
	return nil
}

func (f *fakeWebAuthnSessionRepo) DeleteByTypeAndUser(ctx context.Context, sessionType string, userID string) error {
	if f.itemsByTypeUser != nil {
		delete(f.itemsByTypeUser, sessionType+":"+userID)
	}
	return nil
}
