package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// upstreamFixture is a provider that keeps tokens, and a fake of its token endpoint.
type upstreamFixture struct {
	*tokenFixture
	slug, id  string
	root      *keys.RootKey
	refresh   func(form url.Values) (int, string)
	refreshes int
}

func newUpstreamFixture(t *testing.T) *upstreamFixture {
	t.Helper()
	f := newTokenFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root, f.srv.root = root, root
	u := &upstreamFixture{tokenFixture: f, root: root}
	u.slug = fmt.Sprintf("up-%d", time.Now().UnixNano())
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, token_url, store_tokens)
		VALUES ($1::uuid, $2, 'Upstream', 'oidc', 'signari', 'https://up.test/token', true)
		RETURNING id::text`, f.orgID, u.slug).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE id = $1::uuid`, u.id)
	})
	f.srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			u.refreshes++
			status, body := u.refresh(form)
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	return u
}

func (u *upstreamFixture) keep(t *testing.T, ts federation.TokenSet) {
	t.Helper()
	if err := store.KeepFederatedTokens(context.Background(), u.pool, u.root, u.id, u.userID, u.orgID, ts); err != nil {
		t.Fatal(err)
	}
}

func (u *upstreamFixture) read(t *testing.T, token, slug string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/account/broker/"+slug+"/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	u.srv.Routes().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// An application reads a person's upstream token with a scope naming that provider, gets
// the token and nothing it could keep going with, and the reading is on the record. What
// is stored opens for nobody without the root key (8.17).
func TestAnApplicationReadsAPersonsUpstreamToken(t *testing.T) {
	u := newUpstreamFixture(t)
	ctx := context.Background()
	u.keep(t, federation.TokenSet{AccessToken: "upstream-access", RefreshToken: "upstream-refresh",
		IDToken: "upstream-id", TokenType: "Bearer", ExpiresIn: 3600, Scope: "repo"})

	var sealed []byte
	if err := u.pool.QueryRow(ctx, `SELECT sealed FROM core.federated_tokens WHERE provider_id = $1::uuid`, u.id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "upstream") {
		t.Error("the row holds a token in the clear")
	}

	token := u.mintAccessTokenWithScope(t, []string{"broker." + u.slug})
	code, got := u.read(t, token, u.slug)
	if code != http.StatusOK || got["access_token"] != "upstream-access" || got["token_type"] != "Bearer" || got["scope"] != "repo" {
		t.Fatalf("the answer: %d %v", code, got)
	}
	if in, _ := got["expires_in"].(float64); in < 3500 || in > 3600 {
		t.Errorf("expires_in is %v", got["expires_in"])
	}
	if got["refresh_token"] != nil || got["id_token"] != nil {
		t.Errorf("more than the access token left: %v", got)
	}
	if u.refreshes != 0 {
		t.Error("a token with time left was renewed")
	}
	var provider string
	if err := u.pool.QueryRow(ctx, `SELECT detail->>'provider' FROM core.audit_events
		WHERE event_type = 'federation.token_read' AND subject_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`,
		u.userID).Scan(&provider); err != nil || provider != u.slug {
		t.Errorf("the record: %q, %v", provider, err)
	}

	// The scope is the provider's, so another's opens nothing.
	other := u.mintAccessTokenWithScope(t, []string{"broker.somewhere-else"})
	if code, _ := u.read(t, other, u.slug); code != http.StatusForbidden {
		t.Errorf("a token for another provider: %d", code)
	}
	plain := u.mintAccessTokenWithScope(t, []string{"read"})
	if code, _ := u.read(t, plain, u.slug); code != http.StatusForbidden {
		t.Errorf("a token with no such scope: %d", code)
	}
	if code, _ := u.read(t, "not-a-token", u.slug); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
}

// A token about to end is renewed first, the new one kept, and a provider that sends no
// new refresh token leaves the old one good. One that will not renew it sends the person
// back to sign in.
func TestAnUpstreamTokenIsRenewedBeforeItEnds(t *testing.T) {
	u := newUpstreamFixture(t)
	ctx := context.Background()
	token := u.mintAccessTokenWithScope(t, []string{"broker." + u.slug})
	u.keep(t, federation.TokenSet{AccessToken: "old-access", RefreshToken: "the-refresh", TokenType: "Bearer", ExpiresIn: 10})

	u.refresh = func(form url.Values) (int, string) {
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "the-refresh" || form.Get("client_id") != "signari" {
			t.Errorf("the provider was sent %v", form)
		}
		return http.StatusOK, `{"access_token":"new-access","token_type":"Bearer","expires_in":1800}`
	}
	code, got := u.read(t, token, u.slug)
	if code != http.StatusOK || got["access_token"] != "new-access" {
		t.Fatalf("renewing: %d %v", code, got)
	}
	held, _, err := store.FederatedTokens(ctx, u.pool, u.root, u.id, u.userID)
	if err != nil {
		t.Fatal(err)
	}
	if held.AccessToken != "new-access" || held.RefreshToken != "the-refresh" {
		t.Errorf("kept %+v", held)
	}
	before := u.refreshes
	if code, got := u.read(t, token, u.slug); code != http.StatusOK || got["access_token"] != "new-access" || u.refreshes != before {
		t.Errorf("read again: %d %v, %d renewals", code, got, u.refreshes-before)
	}

	u.keep(t, federation.TokenSet{AccessToken: "old-access", RefreshToken: "the-refresh", TokenType: "Bearer", ExpiresIn: 10})
	u.refresh = func(url.Values) (int, string) { return http.StatusBadRequest, `{"error":"invalid_grant"}` }
	if code, got := u.read(t, token, u.slug); code != http.StatusConflict || got["error"] != "reauthentication_required" {
		t.Errorf("a provider that will not renew: %d %v", code, got)
	}

	u.keep(t, federation.TokenSet{AccessToken: "old-access", TokenType: "Bearer", ExpiresIn: 10})
	if code, got := u.read(t, token, u.slug); code != http.StatusConflict || got["error"] != "reauthentication_required" {
		t.Errorf("nothing to renew with: %d %v", code, got)
	}
}

// What is kept goes with the setting, the link and the person, and a provider not set to
// keep tokens answers as if there were none.
func TestAnUpstreamTokenGoesWhenItsReasonDoes(t *testing.T) {
	u := newUpstreamFixture(t)
	ctx := context.Background()
	token := u.mintAccessTokenWithScope(t, []string{"broker." + u.slug})
	held := func() int {
		t.Helper()
		var n int
		if err := u.pool.QueryRow(ctx, `SELECT count(*) FROM core.federated_tokens WHERE provider_id = $1::uuid`, u.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ts := federation.TokenSet{AccessToken: "a", TokenType: "Bearer", ExpiresIn: 3600}

	if code, _ := u.read(t, token, u.slug); code != http.StatusNotFound {
		t.Errorf("nothing kept: %d", code)
	}

	u.keep(t, ts)
	off := false
	if err := store.ChangeIdentityProvider(ctx, u.pool, u.orgID, u.slug, store.IdentityProviderChange{StoreTokens: &off}); err != nil {
		t.Fatal(err)
	}
	if held() != 0 {
		t.Error("turning it off kept what was kept")
	}
	if code, _ := u.read(t, token, u.slug); code != http.StatusNotFound {
		t.Errorf("a provider set not to keep: %d", code)
	}
	on := true
	if err := store.ChangeIdentityProvider(ctx, u.pool, u.orgID, u.slug, store.IdentityProviderChange{StoreTokens: &on}); err != nil {
		t.Fatal(err)
	}

	u.keep(t, ts)
	if _, err := u.pool.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'upstream-subject')`, u.id, u.userID, u.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UnlinkSubject(ctx, u.pool, u.orgID, u.slug, u.userID, ""); err != nil {
		t.Fatal(err)
	}
	if held() != 0 {
		t.Error("unlinking kept what the link brought")
	}

	// A kind that hands over no token is refused the setting.
	var issuer string
	if err := u.pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, issuer, jwks_url,
		                                     allow_signup, allow_linking)
		VALUES ($1::uuid, $2, 'Assertions', 'assertion', '', 'https://ci.test', 'https://ci.test/jwks', false, false)
		RETURNING slug`, u.orgID, u.slug+"-a").Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = u.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = $1`, issuer)
	})
	if err := store.ChangeIdentityProvider(ctx, u.pool, u.orgID, issuer, store.IdentityProviderChange{StoreTokens: &on}); err == nil {
		t.Error("an assertion issuer was set to keep tokens")
	}
}

// A sign-in keeps what the provider handed over only when the provider is set to, and
// keeps it for the person it signed in. A person erased takes theirs with them.
func TestASignInKeepsAProvidersTokensWhenSetTo(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root, f.srv.root = root, root
	var providerID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, allow_linking, allow_signup)
		VALUES ($1::uuid, 'keep-' || substr(gen_random_uuid()::text, 1, 8), 'Upstream', 'oidc', 'signari', true, true)
		RETURNING id::text`, f.orgID).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UnixNano()
	email := fmt.Sprintf("keeps-%d@example.test", n)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.users WHERE email = $1`, email)
	})
	arrive := func(keep bool) {
		t.Helper()
		cfg := federation.Config{ID: providerID, OrgID: f.orgID, Slug: "upstream", Kind: federation.KindOIDC, StoreTokens: keep,
			Policy: federation.Policy{AllowSignup: true, AllowLinking: true, TrustsEmailVerification: true}}
		rec := httptest.NewRecorder()
		f.srv.completeFederation(rec, httptest.NewRequest(http.MethodGet, "/login/callback", nil), &cfg,
			&store.PendingLogin{ProviderID: providerID, OrgID: f.orgID},
			federation.ExternalIdentity{Subject: "s", Email: email, EmailVerified: true,
				Tokens: &federation.TokenSet{AccessToken: "handed-over", TokenType: "Bearer", IDToken: "the-id-token"}})
		if !strings.Contains(rec.Body.String(), "signed in") {
			t.Fatalf("the sign-in: %d %.200s", rec.Code, rec.Body)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.federated_tokens WHERE provider_id = $1::uuid`, providerID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	arrive(false)
	if count() != 0 {
		t.Fatal("a provider not set to keep tokens had them kept")
	}
	arrive(true)
	if count() != 1 {
		t.Fatal("the sign-in kept nothing")
	}
	var person string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.users WHERE email = $1`, email).Scan(&person); err != nil {
		t.Fatal(err)
	}
	held, _, err := store.FederatedTokens(ctx, f.pool, root, providerID, person)
	if err != nil {
		t.Fatal(err)
	}
	if held.AccessToken != "handed-over" || held.IDToken != "" {
		t.Errorf("kept %+v", held)
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, person); err != nil {
		t.Fatal(err)
	}
	if count() != 0 {
		t.Error("the tokens outlived the person")
	}
}
