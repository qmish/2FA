package service

import (
    "context"
    "testing"

    "github.com/qmish/2FA/internal/radius/protocol"
)

func TestRadiusServiceAccept(t *testing.T) {
    svc := NewRadiusService(
        func(ctx context.Context, username, password string) bool { return true },
        func(ctx context.Context, username string) bool { return true },
    )

    req := protocol.AccessRequest{Username: "alice", Password: "pass"}
    resp := svc.HandleAccessRequest(context.Background(), req)
    if resp.Code != AccessAccept {
        t.Fatalf("expected accept, got %s", resp.Code)
    }
}

func TestRadiusServiceReject(t *testing.T) {
    svc := NewRadiusService(
        func(ctx context.Context, username, password string) bool { return false },
        func(ctx context.Context, username string) bool { return true },
    )

    req := protocol.AccessRequest{Username: "alice", Password: "bad"}
    resp := svc.HandleAccessRequest(context.Background(), req)
    if resp.Code != AccessReject {
        t.Fatalf("expected reject, got %s", resp.Code)
    }
}
