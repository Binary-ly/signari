package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

func tokenIssuer(t *testing.T, tok string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ Iss string }
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c.Iss
}

// A token minted under a registered alias verifies at userinfo, and once the
// alias is retired it does not, and the pinned client is minted under the
// deployment's own issuer. Aliases could not be registered (2.25), nor a
// client pinned to one (2.23), and the set was read once at startup.
func TestATokenMintedUnderAnAliasVerifiesUntilTheAliasRetires(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	var instanceID, ownIssuer string
	if err := f.pool.QueryRow(ctx, `SELECT i.id::text, i.issuer FROM core.organizations o
		JOIN core.instances i ON i.id = o.instance_id WHERE o.id = $1::uuid`,
		f.orgID).Scan(&instanceID, &ownIssuer); err != nil {
		t.Fatal(err)
	}
	f.srv.SetInstance(instanceID)
	alias := fmt.Sprintf("https://legacy-%d.test", time.Now().UnixNano())
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `UPDATE core.clients SET issuer_alias = NULL WHERE client_id = $1`, f.clientID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.instance_issuer_aliases WHERE issuer = $1`, alias)
	})
	pin := func(a string) error {
		t.Helper()
		return setClientSettings(t, f, store.ClientSettings{IssuerAlias: &a})
	}
	if err := pin(alias); !errors.Is(err, store.ErrInvalidClientSetting) {
		t.Fatalf("pinning to an alias nobody registered answered %v", err)
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	for _, bad := range []struct {
		alias  string
		retire *time.Time
	}{
		{"http://plaintext.test", nil}, {alias + "/", nil}, {alias + "?q=1", nil},
		{ownIssuer, nil}, {alias, &past},
	} {
		if err := store.AddIssuerAlias(ctx, tx, instanceID, bad.alias, bad.retire); !errors.Is(err, store.ErrInvalidIssuerAlias) {
			// Fatal, before the commit below writes whatever was wrongly accepted.
			t.Fatalf("registering %q (retire %v) answered %v", bad.alias, bad.retire, err)
		}
	}
	if err := store.AddIssuerAlias(ctx, tx, instanceID, alias, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pin(alias); err != nil {
		t.Fatal(err)
	}

	userinfo := func(tok string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	tok := f.subjectTokenWithDetails(t, "verifier-issuer-alias-aaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if got := tokenIssuer(t, tok); got != alias {
		t.Fatalf("a pinned client's token carries iss %q, want the alias", got)
	}
	if code := userinfo(tok); code != http.StatusOK {
		t.Fatalf("a token minted under a registered alias answered %d at userinfo", code)
	}

	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RetireIssuerAlias(ctx, tx, instanceID, alias, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if code := userinfo(tok); code == http.StatusOK {
		t.Error("a token minted under a retired alias is still accepted at userinfo")
	}
	if got := tokenIssuer(t, f.subjectTokenWithDetails(t, "verifier-issuer-alias-bbbbbbbbbbbbbbbbbbbbbbbbb", nil)); got != f.srv.cfg.Issuer {
		t.Errorf("after retirement the pinned client is minted under %q, want %q", got, f.srv.cfg.Issuer)
	}
	if err := pin(alias); !errors.Is(err, store.ErrInvalidClientSetting) {
		t.Errorf("pinning to a retired alias answered %v", err)
	}
}
