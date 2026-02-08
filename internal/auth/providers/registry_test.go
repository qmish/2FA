package providers

import (
	"context"
	"testing"
	"time"
)

func TestRegistry_DefaultProvider(t *testing.T) {
	registry := NewRegistry()
	mock := NewExpressMobileMock()

	registry.RegisterSMS(DefaultSMSProvider, mock)
	registry.RegisterCall(DefaultCallProvider, mock)
	registry.RegisterPush(DefaultPushProvider, mock)

	smsID, err := registry.SendSMS(context.Background(), "", "+79990000000", "code")
	if err != nil || smsID == "" {
		t.Fatalf("SendSMS default failed: %v", err)
	}

	callID, err := registry.StartCall(context.Background(), "", "+79990000000", "code")
	if err != nil || callID == "" {
		t.Fatalf("StartCall default failed: %v", err)
	}

	pushID, err := registry.SendPush(context.Background(), "", "device1", "title", "body")
	if err != nil || pushID == "" {
		t.Fatalf("SendPush default failed: %v", err)
	}
}

func TestRegistry_UnknownProvider(t *testing.T) {
	registry := NewRegistry()
	_, err := registry.SendSMS(context.Background(), "unknown", "+79990000000", "code")
	if err == nil {
		t.Fatalf("expected error for unknown provider")
	}
}

type failingSMS struct {
	calls     int
	failUntil int
}

func (f *failingSMS) SendSMS(ctx context.Context, to, message string) (string, error) {
	f.calls++
	if f.calls <= f.failUntil {
		return "", ErrProviderRequest
	}
	return "ok", nil
}

func TestRegistry_RetrySMS(t *testing.T) {
	registry := NewRegistry()
	registry.ConfigureRetry(2, 0, 0)
	mock := &failingSMS{failUntil: 2}
	registry.RegisterSMS(DefaultSMSProvider, mock)

	id, err := registry.SendSMS(context.Background(), "", "+79990000000", "code")
	if err != nil || id == "" {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if mock.calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", mock.calls)
	}
}

func TestRegistry_CircuitBreakerSMS(t *testing.T) {
	registry := NewRegistry()
	registry.ConfigureRetry(0, 2, time.Minute)
	mock := &failingSMS{failUntil: 10}
	registry.RegisterSMS(DefaultSMSProvider, mock)

	_, _ = registry.SendSMS(context.Background(), "", "+79990000000", "code")
	_, _ = registry.SendSMS(context.Background(), "", "+79990000000", "code")

	_, err := registry.SendSMS(context.Background(), "", "+79990000000", "code")
	if err != ErrProviderUnavailable {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
	if mock.calls != 2 {
		t.Fatalf("expected 2 calls before open, got %d", mock.calls)
	}
}
