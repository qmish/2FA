package providers

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestFCMSendPush(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/fcm/send" {
            t.Fatalf("unexpected path: %s", r.URL.Path)
        }
        if r.Header.Get("Authorization") == "" {
            t.Fatalf("missing Authorization header")
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer server.Close()

    client := NewFCMClient("key")
    client.Endpoint = server.URL + "/fcm/send"
    _, err := client.SendPush(context.Background(), "token", "t", "b")
    if err != nil {
        t.Fatalf("SendPush error: %v", err)
    }
}
