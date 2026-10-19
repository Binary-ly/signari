package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The token_issue provider at work (2.03): what it may contribute reaches the
// access token, at the code and at every refresh after it; what it may not is
// dropped; a claim the engine owns cannot be planted; and its veto stops a
// refresh, where it used to stop the code and nothing after it.
func TestTheTokenProviderShapesAndStopsEveryGrant(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret := revocableClient(t, f)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients
		SET grant_types = ARRAY['authorization_code','refresh_token','client_credentials'],
		    scopes = scopes || ARRAY['api.read']
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	// `gid` is not a protocol claim to the schema's CHECK, so an operator can
	// allow it; it is the engine's, and the token must not take the provider's.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms, allowed_claims)
		VALUES ($1::uuid, 'shaper', 'token_issue', 'https://provider.test/decide', 'fail_closed', 2000,
		        ARRAY['department','gid'])`, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.providers WHERE org_id = $1::uuid AND name = 'shaper'`, f.orgID)
	})

	var asked []string
	veto := false
	f.srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var req struct {
				Grant string `json:"grant_type"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			asked = append(asked, req.Grant)
			answer := `{"decision":true,"claims":{"department":"research","admin":true,"gid":"planted"}}`
			if veto {
				answer = `{"decision":false,"reason":"suspended in the HR system"}`
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
				"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(answer))}, nil
		})}
	}
	confidential := func(form url.Values) url.Values {
		form.Set("client_id", f.clientID)
		form.Set("client_secret", secret)
		return form
	}
	shaped := func(at, grant string) {
		t.Helper()
		claims := decodeJWTPayload(t, at)
		if claims["department"] != "research" {
			t.Errorf("%s: the access token carries department %v, want the provider's", grant, claims["department"])
		}
		if _, ok := claims["admin"]; ok {
			t.Errorf("%s: the access token carries admin, which the provider may not contribute", grant)
		}
		if claims["gid"] == "planted" {
			t.Errorf("%s: the provider planted the access token's gid", grant)
		}
	}

	verifier := "verifier-token-hook-grants-aaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "offline_access"})
	status, body := f.post(t, confidential(url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {verifier}}))
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	shaped(body["access_token"].(string), "authorization_code")
	refresh := body["refresh_token"].(string)

	status, body = f.post(t, confidential(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}))
	if status != http.StatusOK {
		t.Fatalf("refresh gave %d: %v", status, body)
	}
	shaped(body["access_token"].(string), "refresh_token")
	refresh = body["refresh_token"].(string)

	status, body = f.post(t, confidential(url.Values{"grant_type": {"client_credentials"}, "scope": {"api.read"}}))
	if status != http.StatusOK {
		t.Fatalf("client_credentials gave %d: %v", status, body)
	}
	shaped(body["access_token"].(string), "client_credentials")

	veto = true
	status, body = f.post(t, confidential(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}))
	if status != http.StatusForbidden || body["error"] != "access_denied" {
		t.Errorf("a refresh after the provider's veto gave %d %v, want 403 access_denied", status, body)
	}
	if strings.Contains(asString(body["error_description"]), "HR") {
		t.Error("the provider's reason reached the client")
	}
	if status, _ := f.post(t, confidential(url.Values{"grant_type": {"client_credentials"}, "scope": {"api.read"}})); status != http.StatusForbidden {
		t.Errorf("client_credentials after a veto gave %d, want 403", status)
	}

	// A veto does not spend the refresh token: lifted, the same token refreshes.
	veto = false
	if status, body := f.post(t, confidential(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})); status != http.StatusOK {
		t.Errorf("once the veto lifted the same refresh token gave %d %v; a veto must not rotate it", status, body)
	}

	for _, want := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		found := false
		for _, g := range asked {
			found = found || g == want
		}
		if !found {
			t.Errorf("the provider was never asked about %s; it was asked about %v", want, asked)
		}
	}
}
