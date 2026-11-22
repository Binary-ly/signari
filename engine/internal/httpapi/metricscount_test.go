package httpapi

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/metrics"
	"signari.dev/engine/internal/oauth"
)

// Tokens issued are counted by grant when the token endpoint answers 200 and
// not otherwise, and a wrong client secret is counted as a client-secret
// failure. Both counters were exported and incremented by nothing.
func TestTheTokenEndpointCountsWhatItIssuesAndRefuses(t *testing.T) {
	f := newTokenFixture(t)
	met := metrics.NewEngine()
	f.srv.SetMetrics(met)
	render := func() string {
		var b bytes.Buffer
		met.Registry.Render(&b)
		return b.String()
	}

	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", 5*time.Minute)
	if status, body := f.post(t, preAuthForm(code, "")); status != http.StatusOK {
		t.Fatalf("the pre-authorized code gave %d %v", status, body)
	}
	// The same code again is refused, and is not a token issued.
	if status, _ := f.post(t, preAuthForm(code, "")); status == http.StatusOK {
		t.Fatal("a spent code was redeemed twice")
	}
	if out := render(); !strings.Contains(out, `signari_tokens_issued_total{grant="preauthorized_code"} 1`) {
		t.Errorf("one issued pre-authorized code was not counted once:\n%s", out)
	}

	f.enableExchange(t)
	if status, _ := f.post(t, url.Values{
		"grant_type": {oauth.GrantTypeTokenExchange}, "client_id": {f.clientID},
		"client_secret": {"not-the-secret"}, "subject_token": {"x"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}); status != http.StatusUnauthorized {
		t.Fatalf("a wrong client secret gave %d, want 401", status)
	}
	out := render()
	if !strings.Contains(out, `signari_auth_failures_total{mechanism="client_secret"} 1`) {
		t.Errorf("a wrong client secret was not counted:\n%s", out)
	}
	if strings.Contains(out, `grant="token_exchange"`) {
		t.Errorf("a refused exchange was counted as a token issued:\n%s", out)
	}
}
