package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestRenderIncludesLatencyBuckets(t *testing.T) {
	reg := NewRegistry()
	reg.ObserveHTTPDuration("GET", "/healthz", 120*time.Millisecond)
	out := reg.Render()
	if !strings.Contains(out, "http_request_duration_ms_bucket") {
		t.Fatalf("missing latency buckets")
	}
	if !strings.Contains(out, `method="GET",path="/healthz",le="250"`) {
		t.Fatalf("missing expected bucket label")
	}
}

func TestSystemErrors(t *testing.T) {
	reg := NewRegistry()
	reg.IncSystemError("db")
	out := reg.Render()
	if !strings.Contains(out, `system_errors_total{component="db"} 1`) {
		t.Fatalf("missing system error counter")
	}
}

func TestLockoutMetrics(t *testing.T) {
	reg := NewRegistry()
	reg.IncLockoutCreated()
	reg.IncLockoutActive()
	reg.AddLockoutCleared(3)
	reg.AddWebauthnSessionsCleared(2)
	out := reg.Render()
	if !strings.Contains(out, "lockout_created_total 1") {
		t.Fatalf("missing lockout_created_total")
	}
	if !strings.Contains(out, "lockout_active_total 1") {
		t.Fatalf("missing lockout_active_total")
	}
	if !strings.Contains(out, "lockout_cleared_total 3") {
		t.Fatalf("missing lockout_cleared_total")
	}
	if !strings.Contains(out, "webauthn_sessions_cleared_total 2") {
		t.Fatalf("missing webauthn_sessions_cleared_total")
	}
}

func TestRadiusMetrics(t *testing.T) {
	reg := NewRegistry()
	reg.IncRadiusRequest("accept")
	reg.IncRadiusRequest("reject")
	out := reg.Render()
	if !strings.Contains(out, `radius_requests_total{result="accept"} 1`) {
		t.Fatalf("missing accept radius counter")
	}
	if !strings.Contains(out, `radius_requests_total{result="reject"} 1`) {
		t.Fatalf("missing reject radius counter")
	}
}
