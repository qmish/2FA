package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/vendors/mikrotik"

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

func ListenAndServe(addr string, secret string, svc *service.RadiusService) error {
	return ListenAndServeWithContext(context.Background(), addr, secret, svc)
}

func ListenAndServeWithContext(ctx context.Context, addr string, secret string, svc *service.RadiusService) error {
	return serveWithContext(ctx, addr, secret, &Handler{Service: svc})
}

func serveWithContext(ctx context.Context, addr string, secret string, handler radius.Handler) error {
	server := &radius.PacketServer{
		Addr:         addr,
		Network:      "udp",
		Handler:      handler,
		SecretSource: radius.StaticSecretSource([]byte(secret)),
	}
	conn, err := net.ListenPacket(server.Network, server.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	if err := server.Serve(conn); err != nil {
		if ctx.Err() != nil && errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	return nil
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

	applyMikrotikAttributes(packet, attrs)
	applyCiscoAVPair(packet, attrs)
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

func applyMikrotikAttributes(packet *radius.Packet, attrs protocol.AttributeMap) {
	if ip := mikrotik.MikrotikHostIP_Get(packet); ip != nil {
		attrs["Mikrotik-Host-IP"] = ip.String()
	}
	if realm := mikrotik.MikrotikRealm_GetString(packet); realm != "" {
		attrs["Mikrotik-Realm"] = realm
	}
}

func applyCiscoAVPair(packet *radius.Packet, attrs protocol.AttributeMap) {
	for _, attr := range packet.Attributes {
		if attr.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		vendorID, vsa, err := radius.VendorSpecific(attr.Attribute)
		if err != nil || vendorID != 9 {
			continue
		}
		for len(vsa) >= 3 {
			vsaType, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaType == 1 {
				value := string(vsa[2:int(vsaLen)])
				attrs["Cisco-AVPair"] = value
				if parts := strings.SplitN(value, "=", 2); len(parts) == 2 {
					key := "Cisco-AVPair-" + parts[0]
					attrs[key] = parts[1]
				}
			}
			vsa = vsa[int(vsaLen):]
		}
	}
}
