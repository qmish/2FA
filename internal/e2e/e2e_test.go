package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func baseURL(t *testing.T) string {
	t.Helper()
	base := strings.TrimRight(os.Getenv("E2E_BASE_URL"), "/")
	if base == "" {
		t.Skip("E2E_BASE_URL is not set")
	}
	return base
}

func TestHealthz(t *testing.T) {
	base := baseURL(t)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("healthz request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestMetrics(t *testing.T) {
	base := baseURL(t)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/metrics")
	if err != nil {
		t.Fatalf("metrics request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAuthLogin(t *testing.T) {
	base := baseURL(t)
	username := strings.TrimSpace(os.Getenv("E2E_USERNAME"))
	password := os.Getenv("E2E_PASSWORD")
	if username == "" || password == "" {
		t.Skip("E2E_USERNAME or E2E_PASSWORD is not set")
	}
	payload := map[string]string{
		"username": username,
		"password": password,
		"channel":  "ui",
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "e2e-tests")
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}
