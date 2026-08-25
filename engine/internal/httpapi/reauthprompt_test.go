package httpapi

import (
	"net/url"
	"strings"
	"testing"
)

// prompt=login must not survive the sign-in it demanded.
//
// The bug this locks down was found by the OIDF conformance suite
// (oidcc-prompt-login) and is invisible to every test that signs in first:
//
//	GET /oauth2/authorize?...&prompt=login   -> the sign-in form
//	POST /login  (correct password)          -> 303 to /oauth2/authorize?...&prompt=login
//	GET that                                 -> the sign-in form, again
//
// SessionSufficient returns StepUpForced for prompt=login however fresh the
// session is -- correct on the way in, fatal on the way back, because the query
// was replayed verbatim. A relying party using prompt=login could never complete
// authentication, and no password would ever be "right".
//
// Consuming it is safe only on this path: the session is committed and the login
// audited before resumeAfterSignIn is reached, and the query comes from the
// signed pending token rather than from the browser.

func promptOf(t *testing.T, resumed string) string {
	t.Helper()
	_, query, _ := strings.Cut(resumed, "?")
	v, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("the resumed query does not parse: %v", err)
	}
	return v.Get("prompt")
}

func TestSignInConsumesTheReauthPromptItSatisfied(t *testing.T) {
	base := "client_id=app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&response_type=code&scope=openid&state=s&nonce=n"

	for _, tc := range []struct {
		name   string
		prompt string
		want   string
	}{
		{"login alone is consumed", "login", ""},
		{"select_account alone is consumed", "select_account", ""},
		{"both together are consumed", "login select_account", ""},
		// consent is NOT satisfied by signing in. Dropping it would grant scopes
		// the person was never shown.
		{"consent survives", "login consent", "consent"},
		{"consent alone is untouched", "consent", "consent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := promptOf(t, resumeAfterSignIn(base+"&prompt="+url.QueryEscape(tc.prompt)))
			if got != tc.want {
				t.Errorf("prompt after sign-in = %q, want %q", got, tc.want)
			}
		})
	}
}

// Consuming the prompt must not disturb anything else in the request.
//
// The query is re-encoded to edit it, and a re-encode is exactly where a
// redirect_uri loses its escaping or a parameter is dropped -- either of which
// turns a working authorization request into an invalid_request the RP cannot
// diagnose.
func TestConsumingThePromptPreservesEveryOtherParameter(t *testing.T) {
	original := url.Values{
		"client_id":     {"app"},
		"redirect_uri":  {"https://app.example.com/cb?dummy1=lorem&dummy2=ipsum"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"a b&c"},
		"nonce":         {"n"},
		"max_age":       {"10000"},
		"prompt":        {"login"},
	}
	resumed := resumeAfterSignIn(original.Encode())
	_, query, _ := strings.Cut(resumed, "?")
	got, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("resumed query does not parse: %v", err)
	}

	for k, want := range original {
		if k == "prompt" {
			continue
		}
		if got.Get(k) != want[0] {
			t.Errorf("%s = %q, want %q", k, got.Get(k), want[0])
		}
	}
	if got.Has("prompt") {
		t.Errorf("prompt survived as %q", got.Get("prompt"))
	}
}

// Granting consent must not leave prompt=consent in the resumed request.
//
// The same defect as prompt=login, on the other resume path, and found the same
// way (oidcc-refresh-token sends prompt=consent). The branch that honours
// prompt=consent deliberately ignores the stored grant and re-lists every scope,
// because the client asked the user to look again -- so replaying the query
// after the decision commits renders the identical page, and pressing Allow
// never gets anywhere.
func TestGrantingConsentConsumesThePromptThatDemandedIt(t *testing.T) {
	base := "client_id=app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&response_type=code&scope=openid+offline_access&state=s&nonce=n"

	for _, tc := range []struct {
		name   string
		prompt string
		want   string
	}{
		{"consent alone is consumed", "consent", ""},
		// login is NOT consumed here: this path proves consent was answered, not
		// that anybody re-authenticated. Dropping it would satisfy a client's
		// demand for a fresh sign-in with a consent click.
		{"login survives the consent step", "login consent", "login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := base + "&prompt=" + url.QueryEscape(tc.prompt)
			got, err := url.ParseQuery(consumePrompt(q, "consent"))
			if err != nil {
				t.Fatalf("resumed query does not parse: %v", err)
			}
			if got.Get("prompt") != tc.want {
				t.Errorf("prompt after consent = %q, want %q", got.Get("prompt"), tc.want)
			}
		})
	}
}

// A parked non-OIDC return path is untouched: forward auth and SAML park
// `return=<local path>`, which has no prompt to consume and must not be rewritten
// into an authorization request.
func TestAParkedReturnPathIsNotRewritten(t *testing.T) {
	parked := url.Values{"return": {"/proxy/start?rd=https://app.example.com/x"}}.Encode()
	got := resumeAfterSignIn(parked)
	if got != "/proxy/start?rd=https://app.example.com/x" {
		t.Errorf("parked return resumed as %q", got)
	}
}

// A query that is not parseable is passed through rather than mangled. Returning
// something half-encoded would be worse than returning it unchanged.
func TestAnUnparseableQueryIsPassedThrough(t *testing.T) {
	bad := "client_id=app&%zz=1&prompt=login"
	got := consumeReauthPrompt(bad)
	if got != bad {
		t.Errorf("consumeReauthPrompt rewrote an unparseable query to %q", got)
	}
}
