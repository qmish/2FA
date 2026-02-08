package providers

import (
	"context"
	"sync"
	"time"
)

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
	sms         map[string]SMSProvider
	call        map[string]CallProvider
	push        map[string]PushProvider
	smsBreaker  map[string]*breaker
	callBreaker map[string]*breaker
	pushBreaker map[string]*breaker
	retryMax    int
	breakerMax  int
	breakerOpen time.Duration
	mu          sync.Mutex
}

func NewRegistry() *Registry {
	return &Registry{
		defaultSMS:  DefaultSMSProvider,
		defaultCall: DefaultCallProvider,
		defaultPush: DefaultPushProvider,
		sms:         map[string]SMSProvider{},
		call:        map[string]CallProvider{},
		push:        map[string]PushProvider{},
		smsBreaker:  map[string]*breaker{},
		callBreaker: map[string]*breaker{},
		pushBreaker: map[string]*breaker{},
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

func (r *Registry) ConfigureRetry(maxRetries int, breakerFailures int, breakerOpen time.Duration) {
	if maxRetries < 0 {
		maxRetries = 0
	}
	if breakerFailures < 0 {
		breakerFailures = 0
	}
	if breakerOpen < 0 {
		breakerOpen = 0
	}
	r.retryMax = maxRetries
	r.breakerMax = breakerFailures
	r.breakerOpen = breakerOpen
}

func (r *Registry) SendSMS(ctx context.Context, providerName, to, message string) (string, error) {
	p := r.sms[r.resolve(providerName, r.defaultSMS)]
	if p == nil {
		return "", ErrProviderNotFound
	}
	br := r.getBreaker(r.smsBreaker, r.resolve(providerName, r.defaultSMS))
	return r.callWithRetry(ctx, br, func() (string, error) {
		return p.SendSMS(ctx, to, message)
	})
}

func (r *Registry) StartCall(ctx context.Context, providerName, to, text string) (string, error) {
	p := r.call[r.resolve(providerName, r.defaultCall)]
	if p == nil {
		return "", ErrProviderNotFound
	}
	br := r.getBreaker(r.callBreaker, r.resolve(providerName, r.defaultCall))
	return r.callWithRetry(ctx, br, func() (string, error) {
		return p.StartCall(ctx, to, text)
	})
}

func (r *Registry) SendPush(ctx context.Context, providerName, deviceID, title, body string) (string, error) {
	p := r.push[r.resolve(providerName, r.defaultPush)]
	if p == nil {
		return "", ErrProviderNotFound
	}
	br := r.getBreaker(r.pushBreaker, r.resolve(providerName, r.defaultPush))
	return r.callWithRetry(ctx, br, func() (string, error) {
		return p.SendPush(ctx, deviceID, title, body)
	})
}

func (r *Registry) resolve(name string, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
}

func (r *Registry) getBreaker(store map[string]*breaker, name string) *breaker {
	if r.breakerMax == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	br := store[name]
	if br == nil {
		br = newBreaker(r.breakerMax, r.breakerOpen)
		store[name] = br
	}
	return br
}

func (r *Registry) callWithRetry(ctx context.Context, br *breaker, fn func() (string, error)) (string, error) {
	attempts := r.retryMax + 1
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if br != nil && !br.Allow(time.Now()) {
			return "", ErrProviderUnavailable
		}
		res, err := fn()
		if err == nil {
			if br != nil {
				br.Success()
			}
			return res, nil
		}
		if br != nil {
			br.Failure(time.Now())
		}
		if i == attempts-1 {
			return "", err
		}
	}
	return "", ErrProviderRequest
}
