package providers

import (
    "context"
    "fmt"
    "sync/atomic"
)

type ExpressMobileMock struct {
    counter uint64
}

func NewExpressMobileMock() *ExpressMobileMock {
    return &ExpressMobileMock{}
}

func (m *ExpressMobileMock) SendSMS(ctx context.Context, to, message string) (string, error) {
    _ = ctx
    return m.nextID("sms", to), nil
}

func (m *ExpressMobileMock) StartCall(ctx context.Context, to, text string) (string, error) {
    _ = ctx
    return m.nextID("call", to), nil
}

func (m *ExpressMobileMock) SendPush(ctx context.Context, deviceID, title, body string) (string, error) {
    _ = ctx
    return m.nextID("push", deviceID), nil
}

func (m *ExpressMobileMock) nextID(prefix, target string) string {
    n := atomic.AddUint64(&m.counter, 1)
    return fmt.Sprintf("%s-%s-%d", prefix, target, n)
}
