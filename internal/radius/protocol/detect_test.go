package protocol

import "testing"

func TestDetectVendorCiscoAnyConnect(t *testing.T) {
    attrs := AttributeMap{
        "User-Name":    "alice",
        "Cisco-AVPair": "client-ip=10.0.0.2",
    }
    if got := DetectVendor(attrs); got != VendorCiscoAnyConnect {
        t.Fatalf("expected %s, got %s", VendorCiscoAnyConnect, got)
    }
}

func TestDetectVendorMikroTik(t *testing.T) {
    attrs := AttributeMap{
        "User-Name":        "bob",
        "Mikrotik-Host-IP": "10.0.0.3",
    }
    if got := DetectVendor(attrs); got != VendorMikroTik {
        t.Fatalf("expected %s, got %s", VendorMikroTik, got)
    }
}

func TestParseAccessRequest(t *testing.T) {
    attrs := AttributeMap{
        "User-Name":       "alice",
        "User-Password":   "pass",
        "NAS-IP-Address":  "10.0.0.1",
        "NAS-Identifier":  "vpn-1",
        "Cisco-AVPair":    "client-ip=10.0.0.2",
    }
    req := ParseAccessRequest(attrs)
    if req.Username != "alice" || req.NASIP != "10.0.0.1" {
        t.Fatalf("unexpected request: %+v", req)
    }
    if req.Vendor != VendorCiscoAnyConnect {
        t.Fatalf("unexpected vendor: %s", req.Vendor)
    }
}
