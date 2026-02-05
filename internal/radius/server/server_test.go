package server

import (
    "net"
    "testing"

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
