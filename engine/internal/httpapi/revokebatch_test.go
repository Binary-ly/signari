package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// instanceOf points the fixture's server at its organisation's instance, as serve does, so
// that what it reads per instance (the issuer aliases) is read.
func instanceOf(t *testing.T, f *tokenFixture) string {
	t.Helper()
	var instanceID string
	if err := f.pool.QueryRow(context.Background(), `SELECT instance_id::text FROM core.organizations
		WHERE id = $1::uuid`, f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	f.srv.SetInstance(instanceID)
	return instanceID
}

func userinfoStatus(t *testing.T, f *tokenFixture, token string) int {
	t.Helper()
	code, _ := f.userinfoSub(t, token)
	return code
}

// A client revoking its own access token puts the jti on the denylist in one statement
// (E.23), and nothing else is asked first: not whether a signed token of ours is a refresh
// token, nor the instance's issuer aliases, nor a transaction for one statement. The
// record is written as before, and the token is revoked.
func TestRevokingItsOwnAccessTokenIsOneStatementAndItsRecord(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, clientAuthPerPairWindow)
	instanceOf(t, f)
	secret := revocableClient(t, f)
	access := f.signsIn(t, secret, "openid")["access_token"].(string)
	if code := userinfoStatus(t, f, access); code != http.StatusOK {
		t.Fatalf("the token was refused at userinfo before it was revoked: %d", code)
	}
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.19.%d.%d", n%250, (n/250)%250+1)

	trips := countRoundTrips(t, f)
	if status, got := postTokenAdmin(t, f, "/oauth2/revoke", addr,
		url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "token": {access}}); status != http.StatusOK {
		t.Fatalf("revoking its own access token answered %d: %v", status, got)
	}
	trips.mu.Lock()
	var denylisted, recorded int
	for _, s := range trips.what {
		switch {
		case s == "batch:" || strings.HasPrefix(s, "in the batch: "):
		case strings.HasPrefix(s, "INSERT INTO core.revoked_jtis"):
			denylisted++
		case strings.HasPrefix(s, "SELECT core.audit_append("):
			recorded++
		case s == "begin" || s == "commit" || strings.HasPrefix(s, "SELECT $1::jsonb::text"):
			// The record's own transaction, and its canonical form.
		default:
			t.Errorf("revoking its own access token also ran %q", s)
		}
	}
	trips.mu.Unlock()
	if denylisted != 1 || recorded != 1 {
		t.Errorf("the jti was denylisted %d times and the revocation recorded %d:%s", denylisted, recorded, trips)
	}
	if got := trips.n.Load(); got != 6 {
		t.Errorf("revoking its own access token took %d round trips, want 6 (the client, the denylist, "+
			"the record's four):%s", got, trips)
	}
	if code := userinfoStatus(t, f, access); code == http.StatusOK {
		t.Error("a revoked access token is still accepted at userinfo")
	}
}

// A token minted under a registered alias names an issuer that is not the instance's own,
// so it is revoked the whole way, with the aliases read, as it was before the common case
// was taken first.
func TestAnAccessTokenMintedUnderAnAliasIsRevoked(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	clearOfWindowEdge(t, clientAuthPerPairWindow)
	instanceID := instanceOf(t, f)
	secret := revocableClient(t, f)
	alias := fmt.Sprintf("https://legacy-revoke-%d.test", time.Now().UnixNano())
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `UPDATE core.clients SET issuer_alias = NULL WHERE client_id = $1`, f.clientID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.instance_issuer_aliases WHERE issuer = $1`, alias)
	})
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddIssuerAlias(ctx, tx, instanceID, alias, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := setClientSettings(t, f, store.ClientSettings{IssuerAlias: &alias}); err != nil {
		t.Fatal(err)
	}
	access := f.signsIn(t, secret, "openid")["access_token"].(string)
	if got := tokenIssuer(t, access); got != alias {
		t.Fatalf("the pinned client's token carries iss %q, want the alias", got)
	}
	if code := userinfoStatus(t, f, access); code != http.StatusOK {
		t.Fatalf("a token minted under the alias was refused at userinfo before it was revoked: %d", code)
	}
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.19.%d.%d", n%250, (n/250)%250+1)
	if status, got := postTokenAdmin(t, f, "/oauth2/revoke", addr,
		url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "token": {access}}); status != http.StatusOK {
		t.Fatalf("revoking a token minted under an alias answered %d: %v", status, got)
	}
	if code := userinfoStatus(t, f, access); code == http.StatusOK {
		t.Error("a token minted under an alias was answered 200 at revocation and is still accepted")
	}
	status, got := postTokenAdmin(t, f, oidc.PathIntrospection, addr,
		url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "token": {access}})
	if status != http.StatusOK || got["active"] != false {
		t.Errorf("introspecting the revoked alias token answered %d %v", status, got)
	}
}
