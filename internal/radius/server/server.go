package server

import (
    "context"
    "encoding/binary"
    "net"

    "layeh.com/radius"
    "layeh.com/radius/rfc2865"

    "github.com/qmish/2FA/internal/radius/protocol"
    "github.com/qmish/2FA/internal/radius/service"
)

type Handler struct {
    Service *service.RadiusService
}

func (h *Handler) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
    req := buildAccessRequest(r.Packet)
    resp := h.Service.HandleAccessRequest(context.Background(), req)
    code := radius.CodeAccessReject
    if resp.Code == service.AccessAccept {
        code = radius.CodeAccessAccept
    }
    packet := r.Response(code)
    _ = rfc2865.ReplyMessage_AddString(packet, resp.Message)
    w.Write(packet)
}

func ListenAndServe(addr string, svc *service.RadiusService) error {
    server := &radius.PacketServer{
        Addr:         addr,
        Network:      "udp",
        Handler:      &Handler{Service: svc},
        SecretSource: radius.StaticSecretSource([]byte("secret")),
    }
    conn, err := net.ListenPacket(server.Network, server.Addr)
    if err != nil {
        return err
    }
    defer conn.Close()
    return server.Serve(conn)
}

func buildAccessRequest(packet *radius.Packet) protocol.AccessRequest {
    attrs := protocol.AttributeMap{}
    if val := rfc2865.UserName_GetString(packet); val != "" {
        attrs["User-Name"] = val
    }
    if val := rfc2865.UserPassword_GetString(packet); val != "" {
        attrs["User-Password"] = val
    }
    if ip := rfc2865.NASIPAddress_Get(packet); ip != nil {
        attrs["NAS-IP-Address"] = ip.String()
    }
    if val := rfc2865.NASIdentifier_GetString(packet); val != "" {
        attrs["NAS-Identifier"] = val
    }

    vendor := detectVendorFromVSA(packet)
    if vendor != "" {
        attrs["Vendor-Id"] = vendor
    }
    return protocol.ParseAccessRequest(attrs)
}

func detectVendorFromVSA(packet *radius.Packet) string {
    for _, attr := range packet.Attributes {
        if attr.Type != 26 {
            continue
        }
        if len(attr.Attribute) < 4 {
            continue
        }
        vendorID := binary.BigEndian.Uint32(attr.Attribute[0:4])
        switch vendorID {
        case 9:
            return "9"
        case 14988:
            return "14988"
        }
    }
    return ""
}
