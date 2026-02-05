package providers

import "context"

const (
    DefaultSMSProvider  = "express_mobile"
    DefaultCallProvider = "express_mobile"
    DefaultPushProvider = "fcm"
)

type SMSProvider interface {
    SendSMS(ctx context.Context, to, message string) (string, error)
}

type CallProvider interface {
    StartCall(ctx context.Context, to, text string) (string, error)
}

type PushProvider interface {
    SendPush(ctx context.Context, deviceID, title, body string) (string, error)
}

type Registry struct {
    defaultSMS  string
    defaultCall string
    defaultPush string
    sms             map[string]SMSProvider
    call            map[string]CallProvider
    push            map[string]PushProvider
}

func NewRegistry() *Registry {
    return &Registry{
        defaultSMS:      DefaultSMSProvider,
        defaultCall:     DefaultCallProvider,
        defaultPush:     DefaultPushProvider,
        sms:             map[string]SMSProvider{},
        call:            map[string]CallProvider{},
        push:            map[string]PushProvider{},
    }
}

func (r *Registry) SetDefaultSMS(name string) {
    if name != "" {
        r.defaultSMS = name
    }
}

func (r *Registry) SetDefaultCall(name string) {
    if name != "" {
        r.defaultCall = name
    }
}

func (r *Registry) SetDefaultPush(name string) {
    if name != "" {
        r.defaultPush = name
    }
}

func (r *Registry) RegisterSMS(name string, p SMSProvider) {
    r.sms[name] = p
}

func (r *Registry) RegisterCall(name string, p CallProvider) {
    r.call[name] = p
}

func (r *Registry) RegisterPush(name string, p PushProvider) {
    r.push[name] = p
}

func (r *Registry) SendSMS(ctx context.Context, providerName, to, message string) (string, error) {
    p := r.sms[r.resolve(providerName, r.defaultSMS)]
    if p == nil {
        return "", ErrProviderNotFound
    }
    return p.SendSMS(ctx, to, message)
}

func (r *Registry) StartCall(ctx context.Context, providerName, to, text string) (string, error) {
    p := r.call[r.resolve(providerName, r.defaultCall)]
    if p == nil {
        return "", ErrProviderNotFound
    }
    return p.StartCall(ctx, to, text)
}

func (r *Registry) SendPush(ctx context.Context, providerName, deviceID, title, body string) (string, error) {
    p := r.push[r.resolve(providerName, r.defaultPush)]
    if p == nil {
        return "", ErrProviderNotFound
    }
    return p.SendPush(ctx, deviceID, title, body)
}

func (r *Registry) resolve(name string, fallback string) string {
    if name == "" {
        return fallback
    }
    return name
}
