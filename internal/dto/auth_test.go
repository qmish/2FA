package dto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qmish/2FA/internal/models"
)

func TestLoginResponseJSON(t *testing.T) {
	resp := LoginResponse{
		UserID:      "u1",
		ChallengeID: "c1",
		Method:      models.MethodOTP,
		ExpiresAt:   1738732800,
		Status:      models.ChallengeCreated,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	got := string(data)
	wantFragments := []string{
		"\"user_id\":\"u1\"",
		"\"challenge_id\":\"c1\"",
		"\"method\":\"otp\"",
		"\"expires_at\":1738732800",
		"\"status\":\"created\"",
	}
	for _, frag := range wantFragments {
		if !strings.Contains(got, frag) {
			t.Fatalf("missing json fragment %q in %s", frag, got)
		}
	}
}

func TestChallengeStatusResponseJSON(t *testing.T) {
	resp := ChallengeStatusResponse{
		ChallengeID: "c1",
		Status:      models.ChallengeSent,
		Method:      models.MethodCall,
		ExpiresAt:   1738732800,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	got := string(data)
	wantFragments := []string{
		"\"challenge_id\":\"c1\"",
		"\"status\":\"sent\"",
		"\"method\":\"call\"",
		"\"expires_at\":1738732800",
	}
	for _, frag := range wantFragments {
		if !strings.Contains(got, frag) {
			t.Fatalf("missing json fragment %q in %s", frag, got)
		}
	}
}
