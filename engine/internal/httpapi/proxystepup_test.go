package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// A program whose token came from a sign-in too weak for a protected host's policy is
// told so in RFC 9470's terms (9.09): 401, insufficient_user_authentication, and the
// acr that would pass, so it can send the person to sign in again. The token of the
// stronger sign-in passes. A refusal no sign-in would change stays a 403, and so does a
// browser's, which is sent to sign in by the proxy and not by a challenge, and a token
// that stands for no session, since nobody is there to sign in.
func TestAWeakSignInIsAskedToStepUpAtAProtectedHost(t *testing.T) {
	pa := newProxyAuthz(t)
	ctx := context.Background()
	client := "proxy:" + pa.own
	setAMR := func(amr ...string) {
		t.Helper()
		if _, err := pa.f.pool.Exec(ctx, `UPDATE core.sessions SET amr = $2 WHERE sid = $1`, pa.sid, amr); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { removePolicy(t, pa.f.srv, pa.f.pool, pa.f.orgID) })
	require := func(conditions, given string) {
		t.Helper()
		applyPolicy(t, pa.f.srv, pa.f.pool, pa.f.orgID, fmt.Sprintf(`
version: 1
policies:
  - name: stronger
    when: {client: %q}
    require: %s
    message: Sign in with a second factor to reach the reports.
tests:
  - name: the sign-in it asks for
    given: {client: %q, %s}
    expect: allow
`, client, conditions, client, given))
	}
	token := pa.mintFor(t, "https://"+pa.own, pa.sid, "")

	setAMR("pwd")
	require(`{mfa: true}`, `mfa: true`)
	rec := pa.verifyBearer(t, token, pa.own)
	challenge := rec.Header().Get("WWW-Authenticate")
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(challenge, `Bearer error="insufficient_user_authentication"`) ||
		!strings.Contains(challenge, `acr_values="2"`) || !strings.Contains(challenge, "second factor") {
		t.Fatalf("one factor where two are required answered %d, %q", rec.Code, challenge)
	}
	// The sign-in a proxy recipe sends a refusal to, as for any other.
	if !strings.Contains(rec.Header().Get("Location"), "/proxy/start") {
		t.Errorf("the challenge has no Location to sign in at, %q, so a proxy that redirects a 401 has nowhere to go",
			rec.Header().Get("Location"))
	}
	setAMR("pwd", "otp")
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusOK {
		t.Errorf("after the second factor the token answered %d: %s", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}

	setAMR("pwd")
	if rec := pa.verify(t, pa.token(t, pa.f.orgID), pa.own, "203.0.113.9:443"); rec.Code != http.StatusForbidden ||
		rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("a browser's cookie answered %d, %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	nobody := pa.mintFor(t, "https://"+pa.own, "", "")
	if rec := pa.verifyBearer(t, nobody, pa.own); rec.Code != http.StatusForbidden {
		t.Errorf("a token with no session answered %d, %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	require(`{phishing_resistant: true}`, `amr: [hwk]`)
	setAMR("pwd", "otp")
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Header().Get("WWW-Authenticate"), `acr_values="4"`) {
		t.Errorf("a code where a device-bound key is required answered %d, %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	require(`{factors_any_of: [otp, hwk]}`, `amr: [otp]`)
	setAMR("pwd")
	rec = pa.verifyBearer(t, token, pa.own)
	if challenge := rec.Header().Get("WWW-Authenticate"); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(challenge, "insufficient_user_authentication") || strings.Contains(challenge, "acr_values") {
		t.Errorf("a list of factors answered %d, %q; no one acr stands for it", rec.Code, challenge)
	}

	group := "finance-" + strings.Split(pa.own, ".")[0]
	require(`{groups: [`+group+`], mfa: true}`, `groups: [`+group+`], mfa: true`)
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusForbidden ||
		rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("a group the person is not in answered %d, %q; no sign-in puts them in it",
			rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
