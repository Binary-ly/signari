package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// refreshWith exchanges a refresh token, optionally sending a scope.
func (f *tokenFixture) refreshWith(t *testing.T, refreshToken, scope string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {f.clientID},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return f.post(t, form)
}

// firstRefreshToken runs a code exchange and returns the refresh token.
//
// The grant is widened to three scopes first. The shared fixture grants exactly
// "openid offline_access", and with only those two there is no scope that can be
// dropped without dropping offline_access -- so a "narrowing" test written
// against it narrows to the identical set and passes whether or not narrowing
// works at all.
//
// That is not hypothetical: the first version of this file did exactly that, and
// the mutation which restores the original defect did not fail it.
func (f *tokenFixture) firstRefreshToken(t *testing.T) string {
	t.Helper()
	f.grantExtraScope(t, "profile")
	verifier := strings.Repeat("a", 48)
	code := f.issueCodeWithScopes(t, verifier, []string{"openid", "offline_access", "profile"})
	status, body := f.post(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://rp.test/cb"},
		"client_id":     {f.clientID},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("code exchange failed: %d %v", status, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token in %v", body)
	}
	return rt
}

// TestARefreshMayNotWidenItsScope is the direction that would be an escalation.
func TestARefreshMayNotWidenItsScope(t *testing.T) {
	f := newTokenFixture(t)
	rt := f.firstRefreshToken(t)

	status, body := f.refreshWith(t, rt, "openid offline_access email")
	if status == http.StatusOK {
		t.Fatal("a refresh asked for a scope it was never granted and received tokens; " +
			"6749 6 says the request MUST NOT include a scope not originally granted")
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error %v, want invalid_scope (5.2: the request \"exceeds the "+
			"scope granted by the resource owner\")", body["error"])
	}
	if d, _ := body["error_description"].(string); !strings.Contains(d, "email") {
		t.Errorf("the error does not name the offending scope: %q", d)
	}
}

// grantExtraScope registers one more scope on the fixture client.
func (f *tokenFixture) grantExtraScope(t *testing.T, scope string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.clients
		SET scopes = array_append(scopes, $2)
		WHERE client_id = $1 AND NOT ($2 = ANY(scopes))`, f.clientID, scope); err != nil {
		t.Fatal(err)
	}
}

// issueCodeWithScopes plants a code granting a chosen set.
func (f *tokenFixture) issueCodeWithScopes(t *testing.T, verifier string, scopes []string) string {
	t.Helper()
	ctx := context.Background()

	code, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grant := oauth.GrantRecord{
		ClientID: f.clientID, RedirectURI: "https://rp.test/cb",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
		Nonce: "nonce-1", Scopes: scopes,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.IssueCode(ctx, tx, f.orgID, f.clientID, f.sid, f.userID, grant, hash, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchSessionClient(ctx, tx, f.sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return code
}

// TestARefreshMayNarrowItsScope, and the narrowing must actually take effect.
//
// The assertion that matters is on the RESPONSE's scope, not on the status. The
// old behaviour returned 200 for this request too -- it simply ignored the
// parameter and issued the full scope, which is indistinguishable from success
// unless the scope is checked.
func TestARefreshMayNarrowItsScope(t *testing.T) {
	f := newTokenFixture(t)
	rt := f.firstRefreshToken(t)

	// The grant carries openid, offline_access AND profile. Dropping profile is
	// therefore a real narrowing, which is the only way this test can fail when
	// the parameter is ignored.
	status, body := f.refreshWith(t, rt, "openid offline_access")
	if status != http.StatusOK {
		t.Fatalf("a narrowing refresh was refused: %d %v", status, body)
	}
	got, _ := body["scope"].(string)
	if strings.Contains(got, "profile") {
		t.Errorf("asked for \"openid offline_access\" and the token carries %q; the "+
			"narrowing was ignored, so a client reducing its own blast radius did "+
			"not get what it asked for", got)
	}
	if !strings.Contains(got, "openid") || !strings.Contains(got, "offline_access") {
		t.Errorf("scope %q dropped something that was asked for", got)
	}
}

// TestARefreshWithNoScopeKeepsWhatWasGranted is the half that already worked,
// asserted so the fix above cannot have broken it.
func TestARefreshWithNoScopeKeepsWhatWasGranted(t *testing.T) {
	f := newTokenFixture(t)
	rt := f.firstRefreshToken(t)

	status, body := f.refreshWith(t, rt, "")
	if status != http.StatusOK {
		t.Fatalf("an ordinary refresh was refused: %d %v", status, body)
	}
	got, _ := body["scope"].(string)
	if !strings.Contains(got, "openid") || !strings.Contains(got, "offline_access") {
		t.Errorf("scope %q; omitting the parameter must be treated as equal to what "+
			"was granted", got)
	}
	if body["refresh_token"] == nil {
		t.Error("no successor refresh token")
	}
}

// TestNarrowingAwayOfflineAccessIsRefusedRatherThanEndingTheChain.
//
// A grant without offline_access gets no successor refresh token, so obeying
// this request would consume the client's last one and leave it with a session
// that dies for a reason nobody can find. Some client libraries send a fixed
// `scope` on every refresh out of habit, which makes this a realistic accident
// rather than a hypothetical one.
func TestNarrowingAwayOfflineAccessIsRefusedRatherThanEndingTheChain(t *testing.T) {
	f := newTokenFixture(t)
	rt := f.firstRefreshToken(t)

	status, body := f.refreshWith(t, rt, "openid")
	if status == http.StatusOK {
		if body["refresh_token"] == nil {
			t.Fatal("narrowing away offline_access silently consumed the last refresh " +
				"token and returned no successor")
		}
		t.Fatal("offline_access was narrowed away and a refresh token came back anyway")
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error %v, want invalid_scope", body["error"])
	}

	// And the original token is still usable: a refused request must not have
	// consumed it.
	if s, b := f.refreshWith(t, rt, ""); s != http.StatusOK {
		t.Errorf("the refresh token was consumed by a request that was refused: %d %v", s, b)
	}
}

// TestARefusedScopeDoesNotConsumeTheRefreshToken is the same property stated on
// its own, for the widening case.
func TestARefusedScopeDoesNotConsumeTheRefreshToken(t *testing.T) {
	f := newTokenFixture(t)
	rt := f.firstRefreshToken(t)

	if s, _ := f.refreshWith(t, rt, "openid offline_access admin"); s == http.StatusOK {
		t.Fatal("a widening request succeeded")
	}
	status, body := f.refreshWith(t, rt, "")
	if status != http.StatusOK {
		t.Fatalf("a refused widening burned the refresh token: %d %v", status, body)
	}
	_ = context.Background()
}
