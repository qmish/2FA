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
	svc.webauthnSessions = map[string]webauthnSessionEntry{}

	resp, err := svc.BeginPasskeyRegistration(context.Background(), "u1")
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration error: %v", err)
	}
	if len(resp.Options) == 0 {
		t.Fatalf("expected options payload")
	}
	if _, ok := svc.webauthnSessions["register:u1"]; !ok {
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
	svc.webauthnSessions = map[string]webauthnSessionEntry{
		"register:u1": {data: &webauthn.SessionData{Challenge: "challenge"}, expiresAt: time.Now().Add(time.Minute)},
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

type fakeWebAuthnAdapter struct {
	beginCreation *protocol.CredentialCreation
	beginSession  *webauthn.SessionData
	beginErr      error
	created       *webauthn.Credential
	createErr     error
}

func (f *fakeWebAuthnAdapter) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return f.beginCreation, f.beginSession, f.beginErr
}

func (f *fakeWebAuthnAdapter) CreateCredential(user webauthn.User, session webauthn.SessionData, parsed *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	return f.created, f.createErr
}

type fakeWebAuthnCredentialRepo struct {
	created *models.WebAuthnCredential
}

func (f *fakeWebAuthnCredentialRepo) Create(ctx context.Context, cred *models.WebAuthnCredential) error {
	f.created = cred
	return nil
}
func (f *fakeWebAuthnCredentialRepo) ListByUser(ctx context.Context, userID string) ([]models.WebAuthnCredential, error) {
	return nil, nil
}
func (f *fakeWebAuthnCredentialRepo) DeleteByID(ctx context.Context, userID string, id string) (bool, error) {
	return false, nil
}
func (f *fakeWebAuthnCredentialRepo) GetByCredentialID(ctx context.Context, credentialID string) (*models.WebAuthnCredential, error) {
	return nil, repository.ErrNotFound
}
func (f *fakeWebAuthnCredentialRepo) UpdateSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	return nil
}
