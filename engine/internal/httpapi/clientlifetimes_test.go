package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// tokenTimes reads exp and iat from a signed token's payload.
func tokenTimes(t *testing.T, tok string) (exp, iat int64) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ Exp, Iat int64 }
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c.Exp, c.Iat
}

func setLifetimes(t *testing.T, f *tokenFixture, s store.ClientSettings) error {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetClientSettings(ctx, tx, f.clientID, s); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A client's access tokens live as long as the client is set to, in the token
// and in expires_in. Every grant minted with the built-in five minutes, and the
// column the console showed was read by nothing (2.23).
func TestAClientsAccessTokensLiveAsLongAsItIsSet(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = ARRAY['client_credentials'],
		client_type = 'confidential', client_secret_hash = $2, scopes = ARRAY['api']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	grant := func() (int64, int64, float64) {
		t.Helper()
		status, body := f.post(t, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {f.clientID},
			"client_secret": {secret}, "scope": {"api"},
		})
		if status != http.StatusOK {
			t.Fatalf("client_credentials answered %d %v", status, body)
		}
		exp, iat := tokenTimes(t, body["access_token"].(string))
		return exp, iat, body["expires_in"].(float64)
	}

	if exp, iat, in := grant(); exp-iat != 300 || in != 300 {
		t.Fatalf("before any setting the token lived %ds (expires_in %v), want the default 300", exp-iat, in)
	}
	ten := 10 * time.Minute
	if err := setLifetimes(t, f, store.ClientSettings{AccessTokenTTL: &ten}); err != nil {
		t.Fatal(err)
	}
	if exp, iat, in := grant(); exp-iat != 600 || in != 600 {
		t.Errorf("set to 10m, the token lived %ds (expires_in %v)", exp-iat, in)
	}

	for _, bad := range []time.Duration{30 * time.Second, 2 * time.Hour, 90500 * time.Millisecond} {
		if err := setLifetimes(t, f, store.ClientSettings{AccessTokenTTL: &bad}); err == nil {
			t.Errorf("an access lifetime of %s was accepted", bad)
		}
	}
	for _, bad := range []time.Duration{time.Minute, 400 * 24 * time.Hour} {
		if err := setLifetimes(t, f, store.ClientSettings{RefreshTokenTTL: &bad}); err == nil {
			t.Errorf("a refresh lifetime of %s was accepted", bad)
		}
	}
	// The schema holds the bound for a writer that does not go through the store.
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET access_token_ttl_s = 7200 WHERE client_id = $1`,
		f.clientID); err == nil {
		t.Error("the schema accepted a two-hour access token lifetime")
	}
}

// An exchanged token lives the calling client's lifetime and never past the
// subject token's own expiry: exchange delegates, it does not extend.
func TestAnExchangedTokenDoesNotOutliveItsSubjectToken(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET client_type = 'confidential',
		client_secret_hash = $2 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetClientExchange(ctx, tx, f.clientID, true, []string{exchangeAudience}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	subject := f.subjectTokenWithDetails(t, "verifier-lifetime-exchange-aaaaaaaaaaaaaaaaaa", nil)
	subjectExp, _ := tokenTimes(t, subject)

	hour := time.Hour
	if err := setLifetimes(t, f, store.ClientSettings{AccessTokenTTL: &hour}); err != nil {
		t.Fatal(err)
	}
	status, body := f.post(t, url.Values{
		"grant_type": {oauth.GrantTypeTokenExchange}, "client_id": {f.clientID},
		"client_secret": {f.exchangeSecret}, "subject_token": {subject},
		"subject_token_type": {oauth.TokenTypeAccess}, "audience": {exchangeAudience},
	})
	if status != http.StatusOK {
		t.Fatalf("the exchange answered %d %v", status, body)
	}
	exp, _ := tokenTimes(t, body["access_token"].(string))
	if exp > subjectExp {
		t.Errorf("the exchanged token expires %ds after the subject token it was exchanged for",
			exp-subjectExp)
	}
	if in := body["expires_in"].(float64); int64(in) > subjectExp-time.Now().Unix()+1 {
		t.Errorf("expires_in %v reaches past the subject token", in)
	}

	// And the authorization code grant mints with the client's lifetime too.
	later := f.subjectTokenWithDetails(t, "verifier-lifetime-code-aaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if exp, iat := tokenTimes(t, later); exp-iat != 3600 {
		t.Errorf("set to an hour, a code-grant access token lived %ds", exp-iat)
	}
}
