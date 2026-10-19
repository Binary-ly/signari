package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Token exchange is granted and withdrawn by store.SetClientExchange, the one
// writer behind `client set-exchange`, the Admin API's client PATCH and
// `signari apply`. Discovery advertised the grant while nothing could set the
// permission it checks, so no client could ever be given it (2.12).
func TestTokenExchangeIsGrantedAndWithdrawnByItsWriter(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	// A confidential client with a secret: the setting under test is the
	// permission, not the client type.
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET client_type = 'confidential',
		client_secret_hash = $2, may_exchange = false, exchange_audiences = '{}'
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret
	subject := f.subjectTokenWithDetails(t, "verifier-set-exchange-aaaaaaaaaaaaaaaaaaaaaa", nil)

	exchange := func(audience string) (int, map[string]any) {
		t.Helper()
		return f.post(t, url.Values{
			"grant_type": {oauth.GrantTypeTokenExchange}, "client_id": {f.clientID},
			"client_secret": {f.exchangeSecret}, "subject_token": {subject},
			"subject_token_type": {oauth.TokenTypeAccess}, "audience": {audience},
		})
	}
	set := func(may bool, audiences ...string) error {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.SetClientExchange(ctx, tx, f.clientID, may, audiences); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	if status, body := exchange(exchangeAudience); status == http.StatusOK || body["error"] != "unauthorized_client" {
		t.Fatalf("before the grant the exchange answered %d %v", status, body)
	}

	if err := set(true, " "+exchangeAudience+" ", exchangeAudience, ""); err != nil {
		t.Fatal(err)
	}
	if status, body := exchange(exchangeAudience); status != http.StatusOK {
		t.Fatalf("after the grant the exchange answered %d %v", status, body)
	}
	if status, body := exchange("https://elsewhere.example/api"); status == http.StatusOK || body["error"] != "invalid_target" {
		t.Errorf("an audience outside the grant answered %d %v", status, body)
	}
	var stored []string
	if err := f.pool.QueryRow(ctx, `SELECT exchange_audiences FROM core.clients WHERE client_id = $1`,
		f.clientID).Scan(&stored); err != nil || len(stored) != 1 || stored[0] != exchangeAudience {
		t.Errorf("the audiences were stored as %q (%v), want one, trimmed and de-duplicated", stored, err)
	}

	if err := set(false); err != nil {
		t.Fatal(err)
	}
	if status, body := exchange(exchangeAudience); status == http.StatusOK || body["error"] != "unauthorized_client" {
		t.Errorf("after withdrawing, the exchange answered %d %v", status, body)
	}

	// Refused outright rather than stored as a grant the endpoint would refuse.
	if err := set(true, "has space"); !errors.Is(err, store.ErrInvalidExchangeAudience) {
		t.Errorf("an audience with a space answered %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET client_type = 'public' WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	if err := set(true, exchangeAudience); !errors.Is(err, store.ErrExchangeNeedsConfidentialClient) {
		t.Errorf("granting a public client answered %v", err)
	}
	if err := set(true); !errors.Is(err, store.ErrExchangeNeedsConfidentialClient) {
		t.Errorf("granting a public client with no audiences answered %v", err)
	}
	// Withdrawing from a public client is always allowed: it removes nothing
	// anyone could use.
	if err := set(false); err != nil {
		t.Errorf("withdrawing from a public client answered %v", err)
	}
}
