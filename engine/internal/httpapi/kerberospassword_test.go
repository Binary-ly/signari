package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/kerberos"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A person with no password here, signing in with the one their realm knows: asked at
// every sign-in, nothing kept, a refusal charged as a wrong password, and a KDC that
// cannot be believed or cannot be reached charged to nobody.
func TestARealmIsAskedAtEverySignInAndNothingIsKept(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerAccountWindow)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	if _, err := f.pool.Exec(ctx, `DELETE FROM core.password_credentials WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET migration_state = 'pending' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for name, bad := range map[string]store.MigrationSourceConfig{
		"no realm":           {Kind: "kerberos", DisplayName: "Corp"},
		"a URL":              {Kind: "kerberos", DisplayName: "Corp", URL: "https://kdc.example.com"},
		"a client as well":   {Kind: "kerberos", DisplayName: "Corp", URL: "EXAMPLE.COM", ClientID: "c"},
		"a directory's DN":   {Kind: "kerberos", DisplayName: "Corp", URL: "EXAMPLE.COM", BindDNTemplate: "uid={username}"},
		"nothing to call it": {Kind: "kerberos", URL: "EXAMPLE.COM"},
	} {
		if _, err := store.SetMigrationSource(ctx, tx, root, f.orgID, bad); !errors.Is(err, store.ErrInvalidMigrationSource) {
			t.Errorf("%s: %v", name, err)
		}
	}
	source, err := store.SetMigrationSource(ctx, tx, root, f.orgID, store.MigrationSourceConfig{
		Kind: "kerberos", DisplayName: "Corp", URL: "example.com"})
	if err != nil {
		t.Fatalf("a realm: %v", err)
	}
	if err := store.SetMigrationSourceEnabled(ctx, tx, f.orgID, true); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.migration_sources WHERE id = $1::uuid`, source)
	})

	// The organisation's own keytab for the realm, not the deployment's.
	spn := fmt.Sprintf("HTTP/sso-%d.test", time.Now().UnixNano())
	_, ownKeytab := serviceKeytab(t, "EXAMPLE.COM", spn)
	if _, err := store.AddKerberosRealm(ctx, f.pool, root, f.orgID, store.KerberosRealmSpec{Realm: "EXAMPLE.COM",
		Host: strings.TrimPrefix(spn, "HTTP/"), ServicePrincipal: spn, Keytab: ownKeytab}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.kerberos_realms WHERE service_principal = $1`, spn)
	})
	if src, err := store.MigrationSourceToTest(ctx, f.pool, root, f.orgID); err != nil ||
		!bytes.Equal(src.Keytab, ownKeytab) || src.ServicePrincipal != spn {
		t.Errorf("testing the source would not use the organisation's keytab: %v", err)
	}

	const good = "the-password-the-realm-knows"
	var answer error
	var asked []string
	f.srv.delegator.Kerberos = func(_ context.Context, realm delegated.Source, username, password string) error {
		asked = append(asked, realm.TokenEndpoint+" "+username)
		if !bytes.Equal(realm.Keytab, ownKeytab) || realm.ServicePrincipal != spn {
			t.Errorf("the realm was asked with a keytab of %d bytes as %q", len(realm.Keytab), realm.ServicePrincipal)
		}
		if answer != nil {
			return answer
		}
		if password != good {
			return kerberos.ErrRefused
		}
		return nil
	}
	held := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.password_credentials WHERE user_id = $1::uuid`, f.userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	failures := func() (n, ok int) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT delegated_failures, delegated_successes FROM core.migration_sources WHERE id = $1::uuid`, source).Scan(&n, &ok); err != nil {
			t.Fatal(err)
		}
		return n, ok
	}

	for range 2 {
		if got := f.attempt(t, f.email, good); !got.signedIn() {
			t.Fatalf("the realm's password: %+v", got)
		}
	}
	if len(asked) != 2 || asked[0] != "EXAMPLE.COM "+f.email {
		t.Errorf("the realm was asked %q", asked)
	}
	if held() != 0 {
		t.Error("a hash was kept, which goes on working after the realm changes its mind")
	}
	var state string
	if err := f.pool.QueryRow(ctx, `SELECT migration_state FROM core.users WHERE id = $1::uuid`, f.userID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "pending" {
		t.Errorf("the person is %q, and would not be asked about again", state)
	}
	if _, ok := failures(); ok != 2 {
		t.Errorf("%d sign-ins counted", ok)
	}

	if got := f.attempt(t, f.email, "not-the-password"); got.signedIn() {
		t.Fatal("a password the realm refused signed somebody in")
	}
	if n, _ := failures(); n != 1 {
		t.Errorf("a refusal counted %d", n)
	}

	for name, fault := range map[string]error{
		"a KDC that cannot prove itself": kerberos.ErrKDCUnproven,
		"a KDC that does not answer":     errors.New("the KDC did not answer within 10s"),
	} {
		answer = fault
		got := f.attempt(t, f.email, good)
		if got.signedIn() {
			t.Errorf("%s signed somebody in", name)
		}
		if !strings.Contains(got.body, "temporarily unavailable") {
			t.Errorf("%s was told to the person as: %.300s", name, got.body)
		}
	}
	answer = nil
	if got := f.attempt(t, f.email, good); !got.signedIn() {
		t.Errorf("after the outage: %+v", got)
	}

	// Somebody with a name here is asked about by it, however they typed themselves:
	// the realm has a principal, not an address.
	name := fmt.Sprintf("ada-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET username = $2 WHERE id = $1::uuid`, f.userID, name); err != nil {
		t.Fatal(err)
	}
	asked = nil
	if got := f.attempt(t, f.email, good); !got.signedIn() {
		t.Errorf("signing in by address: %+v", got)
	}
	if len(asked) != 1 || asked[0] != "EXAMPLE.COM "+name {
		t.Errorf("the realm was asked %q", asked)
	}
}
