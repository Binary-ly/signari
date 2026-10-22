package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/tokens"
)

// A token for the Admin API (6.01) is issued only to a client designated for
// it, only for that audience alone, and through the same check at every place
// a resource is accepted.

func tokenAudience(t *testing.T, tok string) []string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Aud []string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c.Aud
}

func TestOnlyADesignatedClientIsIssuedATokenForTheAdminAPI(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = ARRAY['client_credentials'],
		client_type = 'confidential', client_secret_hash = $2, scopes = ARRAY['api']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	admin := tokens.AdminAudience(tokenTestIssuer)
	ask := func(resources ...string) (int, map[string]any) {
		t.Helper()
		return f.post(t, url.Values{"grant_type": {"client_credentials"}, "client_id": {f.clientID},
			"client_secret": {secret}, "scope": {"api"}, "resource": resources})
	}

	if status, body := ask(admin); status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Errorf("an undesignated client asking for the Admin API answered %d %v", status, body)
	}
	if status, body := ask(); status != http.StatusOK || !slices.Equal(tokenAudience(t, body["access_token"].(string)), []string{f.clientID}) {
		t.Fatalf("an ordinary client_credentials token: %d %v", status, body)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET admin_api = true WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	status, body := ask(admin)
	if status != http.StatusOK {
		t.Fatalf("a designated client asking for the Admin API answered %d %v", status, body)
	}
	if aud := tokenAudience(t, body["access_token"].(string)); !slices.Equal(aud, []string{admin}) {
		t.Errorf("the token is audienced %v, want only %s", aud, admin)
	}
	if status, body := ask(admin, "https://api.example.test"); status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Errorf("the Admin API with another resource answered %d %v: that token would be an admin "+
			"credential the other resource holds", status, body)
	}
}

// The check every grant and every place a resource is accepted share.
func TestTheAdminAudienceIsHeldToTheClientEverywhereAResourceIsAccepted(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	admin := tokens.AdminAudience(tokenTestIssuer)
	org := f.orgID
	for _, c := range []struct {
		why    string
		client *clients.Client
		want   error
	}{
		{"no client", nil, errAdminAudienceRefused},
		{"undesignated", &clients.Client{OrgID: org}, errAdminAudienceRefused},
		{"under an issuer alias", &clients.Client{OrgID: org, AdminAPI: true, IssuerAlias: "https://old.example.test"}, errAdminAudienceRefused},
		{"designated", &clients.Client{OrgID: org, AdminAPI: true}, nil},
	} {
		if err := f.srv.checkResources(ctx, f.pool, c.client, org, []string{admin}); err != c.want {
			t.Errorf("%s: %v, want %v", c.why, err, c.want)
		}
	}
	if err := f.srv.checkResources(ctx, f.pool, &clients.Client{OrgID: org, AdminAPI: true}, org,
		[]string{admin, "https://api.example.test"}); err != errAdminAudienceAlone {
		t.Errorf("with another resource: %v", err)
	}
	if !refusedTarget(errAdminAudienceRefused) || !refusedTarget(errAdminAudienceAlone) {
		t.Error("a refused admin audience is not answered as the client's invalid_target")
	}
}
