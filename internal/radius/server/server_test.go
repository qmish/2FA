package server

import (
	"context"
	"net"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/vendors/mikrotik"

	"github.com/qmish/2FA/internal/radius/protocol"
)

func TestBuildAccessRequestVendor(t *testing.T) {
	packet := radius.New(radius.CodeAccessRequest, []byte("secret"))
	_ = rfc2865.UserName_SetString(packet, "alice")
	_ = rfc2865.UserPassword_SetString(packet, "pass")
	_ = rfc2865.NASIPAddress_Set(packet, net.IPv4(10, 0, 0, 1))
	_ = rfc2865.NASIdentifier_SetString(packet, "vpn-1")

	packet.Attributes.Add(26, radius.Attribute{0, 0, 0, 9, 1, 6, 0, 0})

	req := buildAccessRequest(packet)
	if req.Vendor != protocol.VendorCiscoAnyConnect {
		t.Fatalf("expected vendor %s, got %s", protocol.VendorCiscoAnyConnect, req.Vendor)
	}
}

func TestBuildAccessRequestMikrotik(t *testing.T) {
	packet := radius.New(radius.CodeAccessRequest, []byte("secret"))
	_ = rfc2865.UserName_SetString(packet, "bob")
	_ = mikrotik.MikrotikHostIP_Set(packet, net.IPv4(10, 0, 0, 2))
	_ = mikrotik.MikrotikRealm_SetString(packet, "corp")

	req := buildAccessRequest(packet)
	if req.Attributes["Mikrotik-Host-IP"] != "10.0.0.2" {
		t.Fatalf("unexpected host ip: %s", req.Attributes["Mikrotik-Host-IP"])
	}
	if req.Attributes["Mikrotik-Realm"] != "corp" {
		t.Fatalf("unexpected realm: %s", req.Attributes["Mikrotik-Realm"])
	}
}

type testHandler struct{}

func (h testHandler) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {}

func TestServeWithContextShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- serveWithContext(ctx, "127.0.0.1:0", "secret", testHandler{})
	}()

	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for shutdown")
	}
}
