package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIHandlerIndex(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2FA Console") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Refresh token") {
		t.Fatalf("missing refresh section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Sessions list") {
		t.Fatalf("missing sessions list section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Devices") {
		t.Fatalf("missing devices section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Admin audit") {
		t.Fatalf("missing admin audit section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Admin sessions") {
		t.Fatalf("missing admin sessions section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Admin lockouts") {
		t.Fatalf("missing admin lockouts section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Admin login") {
		t.Fatalf("missing admin login section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Register") {
		t.Fatalf("missing register section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Admin invites") {
		t.Fatalf("missing admin invites section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Export audit CSV") {
		t.Fatalf("missing audit export section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Current session") {
		t.Fatalf("missing current session section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ISO времени") {
		t.Fatalf("missing ISO hint: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Healthcheck") {
		t.Fatalf("missing healthcheck section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Metrics") {
		t.Fatalf("missing metrics section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Recovery codes") {
		t.Fatalf("missing recovery codes section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Factors") {
		t.Fatalf("missing factors section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Passkeys") {
		t.Fatalf("missing passkeys section: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Ошибка") {
		t.Fatalf("missing error badge label: %s", rec.Body.String())
	}
}

func TestUIHandlerAssets(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "initUI") {
		t.Fatalf("unexpected asset body: %s", rec.Body.String())
	}
}

func TestUIHandlerFallbackToIndex(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2FA Console") {
		t.Fatalf("unexpected fallback body: %s", rec.Body.String())
	}
}
