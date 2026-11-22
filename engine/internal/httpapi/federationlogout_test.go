package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/store"
)

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

func (f *assertionFixture) logoutToken(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	return f.assert(t, func(c map[string]any) {
		c["aud"] = "unused" // The fixture provider's client id.
		c["events"] = map[string]any{backchannelEvent: map[string]any{}}
		c["jti"] = fmt.Sprintf("lo-%d", time.Now().UnixNano())
		if edit != nil {
			edit(c)
		}
	})
}

func (f *assertionFixture) sendLogout(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"logout_token": {token}}
	r := httptest.NewRequest(http.MethodPost, "/login/callback/"+f.providerSlug+"/backchannel-logout",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (f *assertionFixture) liveSession(t *testing.T) string {
	t.Helper()
	sid := fmt.Sprintf("sid-lo-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '1', ARRAY['pwd'], now(), now() + interval '1 hour')`,
		sid, store.HashToken(sid), f.orgID, f.userID); err != nil {
		t.Fatal(err)
	}
	return sid
}

func (f *assertionFixture) revoked(t *testing.T, sid string) bool {
	t.Helper()
	var gone bool
	if err := f.pool.QueryRow(context.Background(), `SELECT revoked_at IS NOT NULL FROM core.sessions WHERE sid = $1`,
		sid).Scan(&gone); err != nil {
		t.Fatal(err)
	}
	return gone
}

// The token is the whole of the authentication on an open endpoint, so each of these
// reaches a live session and leaves it alone.
func TestAForgedLogoutTokenEndsNothing(t *testing.T) {
	f := newAssertionFixture(t)
	sid := f.liveSession(t)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signedByAStranger := func() string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: stranger},
			(&jose.SignerOptions{}).WithHeader("kid", "sk1"))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"iss": f.issuer, "aud": "unused", "sub": "workload-1", "iat": time.Now().Unix(),
			"jti": "forged", "events": map[string]any{backchannelEvent: map[string]any{}}})
		obj, err := signer.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := obj.CompactSerialize()
		return raw
	}
	for name, token := range map[string]string{
		"signed by a stranger": signedByAStranger(),
		"not a token":          "not.a.token",
		"another issuer":       f.logoutToken(t, func(c map[string]any) { c["iss"] = "https://other.test" }),
		"another audience":     f.logoutToken(t, func(c map[string]any) { c["aud"] = "another-client" }),
		"an ID token":          f.logoutToken(t, func(c map[string]any) { c["nonce"] = "n"; delete(c, "events") }),
		"a nonce":              f.logoutToken(t, func(c map[string]any) { c["nonce"] = "n" }),
		"no event":             f.logoutToken(t, func(c map[string]any) { delete(c, "events") }),
		"another event": f.logoutToken(t, func(c map[string]any) {
			c["events"] = map[string]any{"urn:example:other": map[string]any{}}
		}),
		"no jti":      f.logoutToken(t, func(c map[string]any) { delete(c, "jti") }),
		"no iat":      f.logoutToken(t, func(c map[string]any) { delete(c, "iat") }),
		"too old":     f.logoutToken(t, func(c map[string]any) { c["iat"] = time.Now().Add(-time.Hour).Unix() }),
		"future":      f.logoutToken(t, func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }),
		"nobody":      f.logoutToken(t, func(c map[string]any) { delete(c, "sub") }),
		"a sid alone": f.logoutToken(t, func(c map[string]any) { delete(c, "sub"); c["sid"] = "upstream-session" }),
	} {
		if rec := f.sendLogout(t, token); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d: %s", name, rec.Code, rec.Body.String())
		}
		if f.revoked(t, sid) {
			t.Fatalf("%s ended the session", name)
		}
	}
}

// A real one ends every session the person has, once. A retry of it is done, not
// refused: a provider that lost the answer must not be told it failed.
func TestARealLogoutTokenEndsThePersonsSessions(t *testing.T) {
	f := newAssertionFixture(t)
	ctx := context.Background()
	first, second := f.liveSession(t), f.liveSession(t)
	token := f.logoutToken(t, nil)
	rec := f.sendLogout(t, token)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("answered %d, %q: %s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	if !f.revoked(t, first) || !f.revoked(t, second) {
		t.Fatal("a session outlived the logout")
	}
	var recorded string
	if err := f.pool.QueryRow(ctx, `SELECT detail::text FROM core.audit_events WHERE subject_id = $1::uuid
		AND event_type = 'federation.backchannel_logout'`, f.userID).Scan(&recorded); err != nil {
		t.Fatalf("no record of it: %v", err)
	}
	if !strings.Contains(recorded, `"sessions_ended": 2`) {
		t.Errorf("the record reads %s", recorded)
	}

	// The same token again ends nothing new: a session opened since is safe from it.
	third := f.liveSession(t)
	if rec := f.sendLogout(t, token); rec.Code != http.StatusOK {
		t.Errorf("a retry answered %d: %s", rec.Code, rec.Body.String())
	}
	if f.revoked(t, third) {
		t.Error("a replayed token ended a session opened after it")
	}

	// Somebody nobody here knows is the same outcome, not a way to list who is linked.
	if rec := f.sendLogout(t, f.logoutToken(t, func(c map[string]any) { c["sub"] = "never-linked" })); rec.Code != http.StatusOK {
		t.Errorf("an unknown subject answered %d", rec.Code)
	}
}

// The keys are fetched through the cache: an open endpoint must not be a way to make
// this engine call the provider.
func TestLogoutTokensDoNotFetchKeysEachTime(t *testing.T) {
	f := newAssertionFixture(t)
	fetches := 0
	inner := f.jwksServer.Config.Handler
	f.jwksServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		inner.ServeHTTP(w, r)
	})
	for range 5 {
		if rec := f.sendLogout(t, f.logoutToken(t, nil)); rec.Code != http.StatusOK {
			t.Fatalf("answered %d: %s", rec.Code, rec.Body.String())
		}
	}
	if fetches > 1 {
		t.Errorf("five logout tokens fetched the keys %d times", fetches)
	}
}
