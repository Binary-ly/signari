package httpapi

import (
	"context"
	"time"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// RFC 7662's actual caller: the protected resource.
//
//	§2.1  "The protected resource calls the introspection endpoint..."
//	§4    the authorization server verifies "whether or not the token can be
//	      used at the resource server making the introspection call"
//
// We required the caller to be the client the token was ISSUED TO, which is a
// different relation and excludes the party the endpoint exists for. A resource
// server holding a token audienced to it was answered `active: false` —
// indistinguishable from a forged token — so introspection was unusable in every
// RFC 8707 deployment, which is the case `resource` exists for.
//
// Three parties, because two cannot show the difference: the client the token
// belongs to, the resource server it is addressed to, and a stranger.
func TestAResourceServerInTheAudienceMayIntrospect(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	mk := func(suffix string) (string, string) {
		t.Helper()
		id := f.clientID + suffix
		secret, hash := newTestSecret(t)
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          client_secret_hash, grant_types, scopes, require_pkce)
			VALUES ($1,$2,'RS','confidential',$3, ARRAY['client_credentials'],
			        ARRAY['openid'], true)`, id, f.orgID, hash); err != nil {
			t.Fatalf("client %s: %v", id, err)
		}
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
		})
		return id, secret
	}
	rsID, rsSecret := mk("-rs")
	strangerID, strangerSecret := mk("-stranger")

	// A token issued to the fixture client, addressed to the resource server.
	const verifier = "verifier-for-introspection-audience-0123456789"
	code := f.issueCodeForResource(t, verifier, rsID)
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", body)
	}

	// Only now make the owner confidential: the redemption above is a public
	// PKCE exchange and would be refused for missing credentials afterwards.
	ownerSecret := revocableClient(t, f)

	introspect := func(clientID, secret string) map[string]any {
		t.Helper()
		form := url.Values{"token": {access}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, secret)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		return b
	}

	if got := introspect(rsID, rsSecret); got["active"] != true {
		t.Errorf("the resource server the token is addressed to was told active=%v. "+
			"RFC 7662 §2.1 makes the protected resource the caller, and §4's test is "+
			"whether the token can be used AT that resource server — which this one "+
			"can: %v", got["active"], got)
	}

	if got := introspect(f.clientID, ownerSecret); got["active"] != true {
		t.Errorf("the client the token was issued to was refused: %v", got)
	}

	// A stranger still learns nothing, so this is not a token-scanning oracle.
	got := introspect(strangerID, strangerSecret)
	if got["active"] != false {
		t.Errorf("an unrelated client got active=%v for somebody else's token", got["active"])
	}
	if len(got) != 1 {
		t.Errorf("the refusal carried %d fields; §2.2 allows only `active` for an "+
			"inactive answer, and anything more is a scanning oracle: %v", len(got), got)
	}
}

// issueCodeForResource plants a code whose grant names an RFC 8707 resource, so
// the minted access token is audienced to that resource server rather than to
// the client.
func (f *tokenFixture) issueCodeForResource(t *testing.T, verifier, resource string) string {
	t.Helper()
	ctx := context.Background()

	code, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grant := oauth.GrantRecord{
		ClientID: f.clientID, RedirectURI: "https://rp.test/cb",
		CodeChallenge: oauth.Challenge(verifier), CodeChallengeMethod: "S256",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.IssueCode(ctx, tx, f.orgID, f.clientID, f.sid, f.userID, grant, hash, []string{resource}, nil); err != nil {
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
