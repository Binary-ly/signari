package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A dynamic registrant asking for a secret gets one when the policy allows it,
// and a public client otherwise (2.30). The policy was read and nothing could
// set it, so every registered client was public whatever was asked for; and no
// test covered the confidential branch at all.
func TestDynamicRegistrationMintsAConfidentialClientOnlyWhenAllowed(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	register := func(allow bool) (int, map[string]any, string) {
		t.Helper()
		token := registrationToken(t, f)
		if _, err := f.pool.Exec(ctx, `UPDATE core.registration_policies SET allow_confidential = $2
			WHERE org_id = $1::uuid`, f.orgID, allow); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(
			`{"redirect_uris":["https://rp.test/cb"],"client_name":"conf","token_endpoint_auth_method":"client_secret_basic"}`))
		req.RemoteAddr = freshAddress() + ":443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		id, _ := out["client_id"].(string)
		var kind string
		if id != "" {
			t.Cleanup(func() {
				_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
			})
			if err := f.pool.QueryRow(ctx, `SELECT client_type FROM core.clients WHERE client_id = $1`, id).Scan(&kind); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, out, kind
	}

	code, out, kind := register(false)
	if code != http.StatusCreated || kind != "public" || out["client_secret"] != nil {
		t.Errorf("with confidential registration off: %d, client_type %q, secret present %v; want a public client",
			code, kind, out["client_secret"] != nil)
	}
	code, out, kind = register(true)
	if secret, _ := out["client_secret"].(string); code != http.StatusCreated || kind != "confidential" || secret == "" {
		t.Errorf("with confidential registration on: %d, client_type %q, secret %q; want a confidential client "+
			"and its secret", code, kind, secret)
	}
}
