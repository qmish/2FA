package protocol

const (
    VendorCiscoAnyConnect = "cisco_anyconnect"
    VendorMikroTik        = "mikrotik"
    VendorGeneric         = "generic"
)

func DetectVendor(attrs AttributeMap) string {
    if _, ok := attrs["Cisco-AVPair"]; ok {
        return VendorCiscoAnyConnect
    }
    if _, ok := attrs["Cisco-NAS-Port"]; ok {
        return VendorCiscoAnyConnect
    }
    if _, ok := attrs["Mikrotik-Host-IP"]; ok {
        return VendorMikroTik
    }
    if _, ok := attrs["Mikrotik-Realm"]; ok {
        return VendorMikroTik
    }
    return VendorGeneric
}
