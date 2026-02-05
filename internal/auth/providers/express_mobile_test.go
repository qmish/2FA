package providers

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestExpressMobileSMS(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/sms" {
            t.Fatalf("unexpected path: %s", r.URL.Path)
        }
        if r.Header.Get("Authorization") == "" {
            t.Fatalf("missing Authorization header")
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer server.Close()

    client := NewExpressMobileClient(server.URL, "token")
    _, err := client.SendSMS(context.Background(), "+79990000000", "code")
    if err != nil {
        t.Fatalf("SendSMS error: %v", err)
    }
}
