package metrics

import (
	"bytes"
	"strings"
	"testing"

	"signari.dev/engine/internal/audit"
)

// The audit trail's sign-in events become the sign-in and failure counters,
// inside their declared label sets. Both counters were declared and exported
// and nothing incremented them.
func TestSignInEventsAreCounted(t *testing.T) {
	e := NewEngine()
	for _, ev := range []audit.Event{
		{Type: audit.EventLoginSucceeded},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "bad_password"}},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "bad_password", "via": "ldap"}},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "bad_password", "via": "radius"}},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "bad_second_factor"}},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "rate_limited"}},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "access_policy"}},
		{Type: audit.EventLoginFailed, Detail: map[string]any{"reason": "second_factor_required"}},
		{Type: "consent.granted"},
	} {
		e.ObserveAudit(ev)
	}
	var b bytes.Buffer
	e.Registry.Render(&b)
	out := b.String()
	for _, want := range []string{
		`signari_signins_total{outcome="succeeded"} 1`,
		`signari_signins_total{outcome="failed"} 4`,
		`signari_signins_total{outcome="rate_limited"} 1`,
		`signari_signins_total{outcome="refused"} 1`,
		`signari_signins_total{outcome="mfa_required"} 1`,
		`signari_auth_failures_total{mechanism="password"} 1`,
		`signari_auth_failures_total{mechanism="ldap"} 1`,
		`signari_auth_failures_total{mechanism="radius"} 1`,
		`signari_auth_failures_total{mechanism="mfa"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics lacks %s", want)
		}
	}
	// A refusal or a rate limit is not a wrong credential.
	if strings.Count(out, "signari_auth_failures_total{") != 4 {
		t.Errorf("auth failures counted for something other than a wrong credential:\n%s", out)
	}
}
