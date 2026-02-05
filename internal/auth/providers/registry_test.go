package providers

import (
    "context"
    "testing"
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
