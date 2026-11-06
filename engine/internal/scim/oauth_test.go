package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// oauthTarget is a SCIM target with its own token endpoint, which accepts only
// the tokens it issued and can be told to take them back.
type oauthTarget struct {
	*httptest.Server
	issued, requests atomic.Int64
	current          atomic.Value
	expiresIn        atomic.Int64
	tokenType        atomic.Value
	form             atomic.Value
	id, secret       atomic.Value
	refuseToken      atomic.Bool
	alwaysUnknown    atomic.Bool
}

func newOAuthTarget(t *testing.T) *oauthTarget {
	t.Helper()
	f := &oauthTarget{}
	f.tokenType.Store("Bearer")
	f.expiresIn.Store(3600)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.form.Store(r.PostForm)
		id, secret, _ := r.BasicAuth()
		f.id.Store(id)
		f.secret.Store(secret)
		if f.refuseToken.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client",
				"error_description": "no such client"})
			return
		}
		token := "issued-" + time.Now().Format("150405.000000000")
		f.issued.Add(1)
		f.current.Store(token)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": f.tokenType.Load(),
			"expires_in": f.expiresIn.Load()})
	})
	mux.HandleFunc("GET /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		held, _ := f.current.Load().(string)
		if f.alwaysUnknown.Load() || r.Header.Get("Authorization") != "Bearer "+held {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "unknown token"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("id")})
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *oauthTarget) client(secret string) *Client {
	return NewClient(Target{BaseURL: f.URL, Token: secret, OAuthTokenURL: f.URL + "/oauth/token",
		OAuthClientID: "our client", OAuthScope: "scim.write"}, f.Client())
}

// Asked for once, and sent from then on: a token per request is a request per
// person more, at a target whose token endpoint is often the rate-limited one.
func TestAGrantIsAskedForOnceAndKept(t *testing.T) {
	f := newOAuthTarget(t)
	c := f.client("a secret: with/odd%chars")
	ctx := context.Background()
	for range 3 {
		if _, err := c.GetUser(ctx, "u-1"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.issued.Load(); n != 1 {
		t.Errorf("%d tokens were issued for three requests", n)
	}

	// What the far end decodes is what was registered.
	id, _ := url.QueryUnescape(f.id.Load().(string))
	secret, _ := url.QueryUnescape(f.secret.Load().(string))
	if id != "our client" || secret != "a secret: with/odd%chars" {
		t.Errorf("sent %q, %q", id, secret)
	}
	form := f.form.Load().(url.Values)
	if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "scim.write" {
		t.Errorf("asked with %v", form)
	}
	if form.Has("client_secret") {
		t.Error("the secret went in the form as well")
	}
}

// client_secret_post puts the id and the secret in the form and nothing in a
// header, since a client uses one method a request (7.14); the secret arrives as
// registered, odd characters and all.
func TestASecretIsSentInTheFormWhenTheTargetTakesItThere(t *testing.T) {
	f := newOAuthTarget(t)
	c := NewClient(Target{BaseURL: f.URL, Token: "a secret: with/odd%chars", OAuthTokenURL: f.URL + "/oauth/token",
		OAuthClientID: "our client", OAuthScope: "scim.write", OAuthClientAuth: ClientSecretPost}, f.Client())
	if _, err := c.GetUser(context.Background(), "u-1"); err != nil {
		t.Fatal(err)
	}
	form := f.form.Load().(url.Values)
	if form.Get("client_id") != "our client" || form.Get("client_secret") != "a secret: with/odd%chars" ||
		form.Get("grant_type") != "client_credentials" || form.Get("scope") != "scim.write" {
		t.Errorf("asked with %v", form)
	}
	if id, _ := f.id.Load().(string); id != "" {
		t.Errorf("Basic was sent as well, as %q: two methods in one request", id)
	}
	for _, bad := range []string{"", "private_key_jwt", "client_secret_jwt", "Client_Secret_Post"} {
		if CheckClientAuth(bad) == nil {
			t.Errorf("%q was taken as a way to authenticate", bad)
		}
	}
}

func TestAnExpiredTokenIsReplacedBeforeItIsSent(t *testing.T) {
	f := newOAuthTarget(t)
	f.expiresIn.Store(int64(tokenSlack / time.Second))
	c := f.client("s")
	ctx := context.Background()
	for range 2 {
		if _, err := c.GetUser(ctx, "u-1"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.issued.Load(); n != 2 {
		t.Errorf("%d tokens were issued, want a new one each time", n)
	}
	if n := f.requests.Load(); n != 2 {
		t.Errorf("%d requests reached the target: one was sent with a token that had run out", n)
	}
}

// Revoked before its time: asked for once more, then the answer stands.
func TestARefusedTokenIsAskedForOnce(t *testing.T) {
	f := newOAuthTarget(t)
	c := f.client("s")
	ctx := context.Background()
	if _, err := c.GetUser(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	f.current.Store("revoked out from under it")
	if _, err := c.GetUser(ctx, "u-1"); err != nil {
		t.Fatalf("a revoked token was not replaced: %v", err)
	}
	if n := f.issued.Load(); n != 2 {
		t.Errorf("%d tokens were issued", n)
	}

	f.alwaysUnknown.Store(true)
	before, requests := f.issued.Load(), f.requests.Load()
	_, err := c.GetUser(ctx, "u-1")
	var se *Error
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		t.Fatalf("answered %v", err)
	}
	if got := f.issued.Load() - before; got != 1 {
		t.Errorf("%d tokens were asked for", got)
	}
	if got := f.requests.Load() - requests; got != 2 {
		t.Errorf("%d requests were sent", got)
	}
}

func TestARefusalFromTheTokenEndpointIsSaidWithoutTheSecret(t *testing.T) {
	f := newOAuthTarget(t)
	f.refuseToken.Store(true)
	_, err := f.client("the-client-secret").GetUser(context.Background(), "u-1")
	if err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("answered %v", err)
	}
	if strings.Contains(err.Error(), "the-client-secret") {
		t.Errorf("the error holds the secret: %v", err)
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests went to the target with nothing to send", n)
	}
}

// A token of a type this cannot present would be sent as a bearer one, which is
// a credential given to whatever is on the other side in a form it did not ask for.
func TestOnlyABearerTokenIsTaken(t *testing.T) {
	f := newOAuthTarget(t)
	f.tokenType.Store("DPoP")
	if _, err := f.client("s").GetUser(context.Background(), "u-1"); err == nil {
		t.Error("a DPoP token was taken as a bearer one")
	}
	f.tokenType.Store("bearer")
	if _, err := f.client("s").GetUser(context.Background(), "u-1"); err != nil {
		t.Errorf("a lower-case type was refused: %v", err)
	}
}

// A bearer target has nothing to ask and asks nothing.
func TestABearerTargetIsSentItsToken(t *testing.T) {
	f := newOAuthTarget(t)
	f.current.Store("a-long-lived-token")
	c := NewClient(Target{BaseURL: f.URL, Token: "a-long-lived-token"}, f.Client())
	if _, err := c.GetUser(context.Background(), "u-1"); err != nil {
		t.Fatal(err)
	}
	if n := f.issued.Load(); n != 0 {
		t.Errorf("%d tokens were asked for", n)
	}
}
