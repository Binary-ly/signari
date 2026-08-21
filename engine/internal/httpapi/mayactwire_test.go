package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
)

// RFC 8693 §4.4 enforced through the real token endpoint.
//
// The unit tests in internal/oauth prove CheckMayAct decides correctly. They
// cannot prove it is reached with the right data — which is exactly the shape of
// the WebAuthn defect found earlier this session, where a correct function was
// fed a credential nobody had finished loading.
//
// So this drives POST /oauth2/token with a real subject token carrying may_act.
func TestMayActIsEnforcedAtTheTokenEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// Confidential, because token exchange is not available to a public client:
	// `may_exchange` says "this client may act for that user", and a public
	// client cannot prove it is that client.
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients
		   SET may_exchange = true,
		       exchange_audiences = ARRAY['https://api.example'],
		       client_type = 'confidential', client_secret_hash = $2,
		       grant_types = grant_types || ARRAY['urn:ietf:params:oauth:grant-type:token-exchange']
		 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret

	mint := func(t *testing.T, mayAct map[string]any) string {
		t.Helper()
		k, err := f.srv.cfg.Keys.Active(keys.ES256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: f.userID,
			Audience: []string{f.clientID},
			Expiry:   now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			JTI: "mayact-" + t.Name(), ClientID: f.clientID,
			Scope: "openid", MayAct: mayAct,
		}, tokens.TypAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	exchange := func(t *testing.T, subjectToken string) (int, map[string]any) {
		t.Helper()
		form := strings.NewReader(
			"grant_type=urn:ietf:params:oauth:grant-type:token-exchange" +
				"&subject_token=" + subjectToken +
				"&subject_token_type=urn:ietf:params:oauth:token-type:access_token" +
				"&audience=https://api.example" +
				"&client_id=" + f.clientID +
				"&client_secret=" + f.exchangeSecret)
		req := httptest.NewRequest(http.MethodPost, oidc.PathToken, form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	t.Run("may_act naming another client refuses the exchange", func(t *testing.T) {
		code, body := exchange(t, mint(t, map[string]any{"client_id": "somebody-else"}))
		if code == http.StatusOK {
			t.Fatalf("the exchange succeeded despite may_act naming another client: %v", body)
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, "may_act") {
			t.Errorf("the refusal does not mention may_act, so it may be for an "+
				"unrelated reason: %d %v", code, body)
		}
	})

	t.Run("a may_act member we cannot evaluate refuses", func(t *testing.T) {
		code, body := exchange(t, mint(t, map[string]any{
			"client_id": f.clientID, "department": "finance"}))
		if code == http.StatusOK {
			t.Fatalf("an unevaluable may_act member was ignored: %v", body)
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, "department") {
			t.Errorf("the refusal should name the member: %v", body)
		}
	})

	// The control: without may_act the exchange must still work, or this is not
	// an enforcement, it is an outage.
	t.Run("no may_act leaves the exchange working", func(t *testing.T) {
		code, body := exchange(t, mint(t, nil))
		if code != http.StatusOK {
			t.Fatalf("an ordinary exchange was refused: %d %v", code, body)
		}
		if body["access_token"] == nil {
			t.Errorf("no access_token in the response: %v", body)
		}
	})
}
