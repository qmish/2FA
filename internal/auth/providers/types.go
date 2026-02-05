package providers

import "context"

const DefaultProviderName = "express_mobile"

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
    defaultProvider string
    sms             map[string]SMSProvider
    call            map[string]CallProvider
    push            map[string]PushProvider
}

func NewRegistry() *Registry {
    return &Registry{
        defaultProvider: DefaultProviderName,
        sms:             map[string]SMSProvider{},
        call:            map[string]CallProvider{},
        push:            map[string]PushProvider{},
    }
}

func (r *Registry) SetDefaultProvider(name string) {
    if name != "" {
        r.defaultProvider = name
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
    p := r.sms[r.resolve(providerName)]
    if p == nil {
        return "", ErrProviderNotFound
    }
    return p.SendSMS(ctx, to, message)
}

func (r *Registry) StartCall(ctx context.Context, providerName, to, text string) (string, error) {
    p := r.call[r.resolve(providerName)]
    if p == nil {
        return "", ErrProviderNotFound
    }
    return p.StartCall(ctx, to, text)
}

func (r *Registry) SendPush(ctx context.Context, providerName, deviceID, title, body string) (string, error) {
    p := r.push[r.resolve(providerName)]
    if p == nil {
        return "", ErrProviderNotFound
    }
    return p.SendPush(ctx, deviceID, title, body)
}

func (r *Registry) resolve(name string) string {
    if name == "" {
        return r.defaultProvider
    }
    return name
}
