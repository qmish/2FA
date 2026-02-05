package protocol

type AttributeMap map[string]string

type AccessRequest struct {
    Username      string
    Password      string
    NASIP         string
    NASIdentifier string
    Vendor        string
    Attributes    AttributeMap
}

func ParseAccessRequest(attrs AttributeMap) AccessRequest {
    req := AccessRequest{
        Username:      attrs["User-Name"],
        Password:      attrs["User-Password"],
        NASIP:         attrs["NAS-IP-Address"],
        NASIdentifier: attrs["NAS-Identifier"],
        Attributes:    attrs,
    }
    req.Vendor = DetectVendor(attrs)
    return req
}
