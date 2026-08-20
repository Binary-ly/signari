package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"encoding/json"
)

func TestRevokingAnotherClientsTokenIsRefusedRatherThanSilentlyIgnored(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// A second confidential client in the same organisation.
	other := f.clientID + "-other"
	otherSecret, otherHash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2,'Other','confidential',$3, ARRAY['authorization_code','refresh_token'],
		        ARRAY['openid','offline_access'], true)`, other, f.orgID, otherHash); err != nil {
		t.Fatalf("second client: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, other)
	})

	// A refresh token belonging to the FIRST client.
	const verifier = "verifier-for-the-foreign-revoke-0123456789ab"
	code := f.issueCode(t, verifier)
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	access, _ := body["access_token"].(string)
	if refresh == "" || access == "" {
		t.Fatalf("need both tokens: %v", body)
	}

	// Only NOW make the first client confidential. revocableClient rewrites its
	// type, and the redemption above is a public-client PKCE exchange that would
	// be refused for missing credentials if it ran afterwards.
	secret := revocableClient(t, f)

	revoke := func(clientID, clientSecret, token string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		return rec.Code, b
	}

	t.Run("another client's access token", func(t *testing.T) {
		status, b := revoke(other, otherSecret, access)
		if status == http.StatusOK {
			t.Fatal("revoking another client's access token answered 200; the caller " +
				"is told the token was revoked when it was not, and §2.1 requires " +
				"the request to be refused and the client informed")
		}
		if b["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant (RFC 6749 §5.2: a grant "+
				"\"issued to another client\")", b["error"])
		}
	})

	t.Run("another client's refresh token", func(t *testing.T) {
		status, b := revoke(other, otherSecret, refresh)
		if status == http.StatusOK {
			t.Fatal("revoking another client's refresh token answered 200")
		}
		if b["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", b["error"])
		}
	})

	// §2.2 is unchanged and must stay unchanged: an unknown token is 200, because
	// a client cannot act on an error about a token the server never issued.
	t.Run("an unknown token is still 200", func(t *testing.T) {
		if status, b := revoke(f.clientID, secret, "not-a-token-this-server-ever-issued"); status != http.StatusOK {
			t.Errorf("unknown token answered %d %v; §2.2 requires 200", status, b)
		}
	})

	// And the owner can still revoke its own, or this whole endpoint is broken.
	t.Run("the owning client still succeeds", func(t *testing.T) {
		if status, b := revoke(f.clientID, secret, refresh); status != http.StatusOK {
			t.Errorf("the owning client could not revoke its own token: %d %v", status, b)
		}
	})
}
