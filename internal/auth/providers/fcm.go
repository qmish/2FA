package providers

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "time"
)

type FCMClient struct {
    Endpoint  string
    ServerKey string
    HTTP      *http.Client
}

func NewFCMClient(serverKey string) *FCMClient {
    return &FCMClient{
        Endpoint:  "https://fcm.googleapis.com/fcm/send",
        ServerKey: serverKey,
        HTTP:      &http.Client{Timeout: 10 * time.Second},
    }
}

func (c *FCMClient) SendPush(ctx context.Context, deviceID, title, body string) (string, error) {
    payload := map[string]any{
        "to": deviceID,
        "notification": map[string]string{
            "title": title,
            "body":  body,
        },
    }
    data, _ := json.Marshal(payload)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(data))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")
    if c.ServerKey != "" {
        req.Header.Set("Authorization", "key="+c.ServerKey)
    }
    resp, err := c.HTTP.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return "", ErrProviderRequest
    }
    return "ok", nil
}
