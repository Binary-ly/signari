package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// A token issued elsewhere, exchanged for one here (8.32), and what RFC 8693 §2.2.2 says a
// refusal of any subject or actor token is called.

const foreignAudience = "https://api.example.test"

func (f *assertionFixture) mayExchange(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients
		SET may_exchange = true, exchange_audiences = $2 WHERE client_id = $1`,
		f.clientID, []string{foreignAudience}); err != nil {
		t.Fatal(err)
	}
}

func (f *assertionFixture) exchange(t *testing.T, token string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {oauth.GrantTypeTokenExchange}, "client_id": {f.clientID},
		"client_secret": {f.secret}, "subject_token": {token}, "subject_token_type": {oauth.TokenTypeJWT}}
	for k, v := range extra {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.handleToken(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestATokenFromARegisteredIssuerIsExchangedForThePersonItNames(t *testing.T) {
	f := newAssertionFixture(t)
	f.mayExchange(t)
	expires := time.Now().Add(2 * time.Minute).Unix()
	status, body := f.exchange(t, f.assert(t, func(c map[string]any) { c["exp"] = expires }),
		url.Values{"audience": {foreignAudience}, "scope": {"api.read"}})
	if status != http.StatusOK {
		t.Fatalf("answered %d %v", status, body)
	}
	if body["issued_token_type"] != oauth.TokenTypeAccess {
		t.Errorf("issued %v", body["issued_token_type"])
	}
	claims := claimsOfJWT(t, body["access_token"].(string))
	if claims["sub"] != f.userID {
		t.Errorf("the token is about %v, want the linked person %s", claims["sub"], f.userID)
	}
	if claims["iss"] != "https://jb-test.example" {
		t.Errorf("issued by %v", claims["iss"])
	}
	if act, _ := claims["act"].(map[string]any); act["sub"] != f.clientID {
		t.Errorf("act is %v, want the calling client", claims["act"])
	}
	if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != foreignAudience {
		if claims["aud"] != foreignAudience {
			t.Errorf("addressed to %v", claims["aud"])
		}
	}
	if claims["scope"] != "api.read" {
		t.Errorf("scope is %v", claims["scope"])
	}
	if exp, _ := claims["exp"].(float64); int64(exp) > expires {
		t.Errorf("the token outlives what it was exchanged from: %d > %d", int64(exp), expires)
	}
	if sid, present := claims["sid"]; present {
		t.Errorf("no session stands behind it, and it names %v", sid)
	}
}

func TestAForeignTokenBuysNoMoreThanTheClientIsRegisteredFor(t *testing.T) {
	f := newAssertionFixture(t)
	f.mayExchange(t)
	if status, body := f.exchange(t, f.assert(t, nil), url.Values{"scope": {"api.admin"}}); status != http.StatusBadRequest ||
		body["error"] != "invalid_scope" {
		t.Errorf("a scope nobody registered answered %d %v", status, body)
	}
	if status, body := f.exchange(t, f.assert(t, nil), url.Values{"audience": {"https://elsewhere.test"}}); status != http.StatusBadRequest ||
		body["error"] != "invalid_target" {
		t.Errorf("an audience nobody allowed answered %d %v", status, body)
	}
	// A `scope` claim is its issuer's own vocabulary, and buys nothing here.
	status, body := f.exchange(t, f.assert(t, func(c map[string]any) { c["scope"] = "api.admin" }), nil)
	if status != http.StatusOK || strings.Contains(body["scope"].(string), "api.admin") {
		t.Errorf("answered %d %v", status, body)
	}
}

func TestAForeignTokenCannotAskUsToSayWeAuthenticated(t *testing.T) {
	f := newAssertionFixture(t)
	f.mayExchange(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET scopes = ARRAY['openid','api.read']
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if status, body := f.exchange(t, f.assert(t, nil), nil); status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Errorf("a client whose registration carries openid answered %d %v", status, body)
	}
}

func TestAForeignTokenIsSpentByItsFirstExchange(t *testing.T) {
	f := newAssertionFixture(t)
	f.mayExchange(t)
	token := f.assert(t, nil)
	if status, body := f.exchange(t, token, nil); status != http.StatusOK {
		t.Fatalf("answered %d %v", status, body)
	}
	if status, body := f.exchange(t, token, nil); status != http.StatusBadRequest || body["error"] != "invalid_request" ||
		body["error_description"] != assertionRefused {
		t.Errorf("a second exchange answered %d %v", status, body)
	}
	// One token, however it is spent.
	second := f.assert(t, nil)
	if status, body := f.exchange(t, second, nil); status != http.StatusOK {
		t.Fatalf("answered %d %v", status, body)
	}
	if status, body := f.grant(t, second, nil); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("the jwt-bearer grant then answered %d %v", status, body)
	}
}

// Every way of not being entitled reads alike, or the answers map who is trusted.
func TestEveryForeignRefusalIsOneSentence(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(t *testing.T, f *assertionFixture) string{
		"unknown issuer": func(t *testing.T, f *assertionFixture) string {
			return f.assert(t, func(c map[string]any) { c["iss"] = "https://nobody.test" })
		},
		"signed by another key": func(t *testing.T, f *assertionFixture) string {
			f.signKey = other
			return f.assert(t, nil)
		},
		"addressed elsewhere": func(t *testing.T, f *assertionFixture) string {
			return f.assert(t, func(c map[string]any) { c["aud"] = "https://elsewhere.test" })
		},
		"expired": func(t *testing.T, f *assertionFixture) string {
			return f.assert(t, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
		},
		"nobody linked": func(t *testing.T, f *assertionFixture) string {
			return f.assert(t, func(c map[string]any) { c["sub"] = "somebody-else" })
		},
		"client not paired": func(t *testing.T, f *assertionFixture) string {
			f.setClient(t, `jwt_bearer_providers = '{}'`)
			return f.assert(t, nil)
		},
		"issuer not opted in": func(t *testing.T, f *assertionFixture) string {
			if _, err := f.pool.Exec(context.Background(), `UPDATE core.identity_providers
				SET allow_jwt_bearer = false WHERE id = $1::uuid`, f.providerID); err != nil {
				t.Fatal(err)
			}
			return f.assert(t, nil)
		},
		"deactivated person": func(t *testing.T, f *assertionFixture) string {
			if _, err := f.pool.Exec(context.Background(), `UPDATE core.users SET status = 'deactivated'
				WHERE id = $1::uuid`, f.userID); err != nil {
				t.Fatal(err)
			}
			return f.assert(t, nil)
		},
		"consent withdrawn": func(t *testing.T, f *assertionFixture) string {
			if _, err := f.pool.Exec(context.Background(), `INSERT INTO core.consents
				(user_id, client_id, scopes, withdrawn_at) VALUES ($1::uuid, $2, '{}', now())`,
				f.userID, f.clientID); err != nil {
				t.Fatal(err)
			}
			return f.assert(t, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAssertionFixture(t)
			f.mayExchange(t)
			status, body := f.exchange(t, spoil(t, f), nil)
			if status != http.StatusBadRequest || body["error"] != "invalid_request" || body["error_description"] != assertionRefused {
				t.Errorf("answered %d %v", status, body)
			}
		})
	}
}

func (f *assertionFixture) setClient(t *testing.T, set string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET `+set+` WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
}

// A client that may not exchange makes nobody's keys be fetched by trying.
func TestAClientThatMayNotExchangeFetchesNothing(t *testing.T) {
	f := newAssertionFixture(t)
	f.srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			t.Errorf("fetched %s", r.URL)
			return nil, http.ErrUseLastResponse
		})}
	}
	if status, body := f.exchange(t, f.assert(t, nil), nil); status != http.StatusBadRequest || body["error"] != "unauthorized_client" {
		t.Errorf("answered %d %v", status, body)
	}
}

// Who may act and who has acted hold wherever the token was issued.
func TestWhatAForeignTokenSaysAboutActingHolds(t *testing.T) {
	f := newAssertionFixture(t)
	f.mayExchange(t)
	status, body := f.exchange(t, f.assert(t, func(c map[string]any) {
		c["may_act"] = map[string]any{"client_id": "somebody-else"}
	}), nil)
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Errorf("a token naming another actor answered %d %v", status, body)
	}
	status, body = f.exchange(t, f.assert(t, func(c map[string]any) {
		c["may_act"] = map[string]any{"client_id": f.clientID}
		c["act"] = map[string]any{"sub": "first-hop"}
	}), nil)
	if status != http.StatusOK {
		t.Fatalf("answered %d %v", status, body)
	}
	act, _ := claimsOfJWT(t, body["access_token"].(string))["act"].(map[string]any)
	prior, _ := act["act"].(map[string]any)
	if act["sub"] != f.clientID || prior["sub"] != "first-hop" {
		t.Errorf("the chain reads %v", act)
	}
}

// An access token from elsewhere means only what its issuer says it means, and nothing asks it.
func TestAForeignAccessTokenIsNotExchanged(t *testing.T) {
	f := newAssertionFixture(t)
	f.mayExchange(t)
	status, body := f.exchange(t, f.assert(t, nil), url.Values{"subject_token_type": {oauth.TokenTypeAccess}})
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Errorf("answered %d %v", status, body)
	}
}

func TestAnOrdinarySubjectTokenRefusalIsInvalidRequest(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	token := f.mintAccessTokenWithScope(t, []string{"read"})
	base := url.Values{"grant_type": {oauth.GrantTypeTokenExchange}, "client_id": {f.clientID},
		"client_secret": {f.exchangeSecret}, "audience": {exchangeAudience},
		"subject_token_type": {oauth.TokenTypeAccess}}
	with := func(extra url.Values) url.Values {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		for k, v := range extra {
			form[k] = v
		}
		return form
	}
	for name, form := range map[string]url.Values{
		"a subject token that is nothing": with(url.Values{"subject_token": {"not-a-token"}}),
		"an actor token that is nothing": with(url.Values{"subject_token": {token}, "actor_token": {"not-a-token"},
			"actor_token_type": {oauth.TokenTypeAccess}}),
	} {
		if status, body := f.post(t, form); status != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Errorf("%s answered %d %v", name, status, body)
		}
	}
	// One that has ended, by the check a Txn-Token shares under another code.
	claims := claimsOfJWT(t, token)
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.RevokeJTI(ctx, tx, claims["jti"].(string), f.clientID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if status, body := f.post(t, with(url.Values{"subject_token": {token}})); status != http.StatusBadRequest ||
		body["error"] != "invalid_request" {
		t.Errorf("a revoked subject token answered %d %v", status, body)
	}
}
