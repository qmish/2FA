package server

import (
    "net"
    "testing"

    "layeh.com/radius"
    "layeh.com/radius/rfc2865"

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
