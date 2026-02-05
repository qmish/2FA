package providers

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "time"
)

type ExpressMobileClient struct {
    BaseURL string
    APIKey  string
    HTTP    *http.Client
}

func NewExpressMobileClient(baseURL, apiKey string) *ExpressMobileClient {
    return &ExpressMobileClient{
        BaseURL: baseURL,
        APIKey:  apiKey,
        HTTP:    &http.Client{Timeout: 10 * time.Second},
    }
}

func (c *ExpressMobileClient) SendSMS(ctx context.Context, to, message string) (string, error) {
    payload := map[string]string{"to": to, "message": message}
    return c.post(ctx, c.BaseURL+"/sms", payload)
}

func (c *ExpressMobileClient) StartCall(ctx context.Context, to, text string) (string, error) {
    payload := map[string]string{"to": to, "text": text}
    return c.post(ctx, c.BaseURL+"/call", payload)
}

func (c *ExpressMobileClient) post(ctx context.Context, url string, payload map[string]string) (string, error) {
    body, _ := json.Marshal(payload)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")
    if c.APIKey != "" {
        req.Header.Set("Authorization", "Bearer "+c.APIKey)
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
