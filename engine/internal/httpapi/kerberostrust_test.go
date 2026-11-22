package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/store"
)

// optedRealm is a realm with 8.12's two opt-ins, as an operator would set them.
func optedRealm(t *testing.T, f *signInFixture, strip bool, trusted []string, create bool) *testRealm {
	t.Helper()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	stamp := time.Now().UnixNano()
	r := &testRealm{org: f.orgID, realm: fmt.Sprintf("HOME%d.TEST", stamp), host: fmt.Sprintf("sso-opt-%d.test", stamp)}
	r.spn = "HTTP/" + r.host
	var raw []byte
	r.keytab, raw = serviceKeytab(t, r.realm, r.spn)
	if _, err := store.AddKerberosRealm(context.Background(), f.pool, root, f.orgID, store.KerberosRealmSpec{
		Realm: r.realm, Host: r.host, ServicePrincipal: r.spn, Keytab: raw, StripRealm: strip,
		TrustedRealms: trusted, CreateAccounts: create}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.kerberos_realms WHERE host = $1`, r.host)
	})
	return r
}

func TestATicketFromATrustedRealmSignsInAsItsOwnPerson(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	partner := fmt.Sprintf("PARTNER%d.TEST", time.Now().UnixNano())
	elsewhere := fmt.Sprintf("ELSEWHERE%d.TEST", time.Now().UnixNano())
	r := optedRealm(t, f, true, []string{partner}, false)

	// Somebody of this realm called ada, whom a stripped name would reach.
	var home, theirs string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, username)
		VALUES ($1::uuid, decode(repeat(md5(random()::text),4),'hex'), 'ada') RETURNING id::text`, f.orgID).Scan(&home); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, decode(repeat(md5(random()::text),4),'hex'), $2) RETURNING id::text`,
		f.orgID, "ada@"+strings.ToLower(partner)).Scan(&theirs); err != nil {
		t.Fatal(err)
	}

	rec := kerberosAt(f, r.host, ticket(t, r.keytab, "ada", r.realm, r.spn, r.realm))
	if user, _ := signedInAs(t, f, rec); user != home {
		t.Errorf("this realm's ada signed in as %q, not %q: %d", user, home, rec.Code)
	}
	rec = kerberosAt(f, r.host, ticket(t, r.keytab, "ada", partner, r.spn, r.realm))
	if user, _ := signedInAs(t, f, rec); user != theirs {
		t.Errorf("the partner's ada signed in as %q, not %q: %d %.200s", user, theirs, rec.Code, rec.Body.String())
	}
	if rec = kerberosAt(f, r.host, ticket(t, r.keytab, "ada", elsewhere, r.spn, r.realm)); rec.Code != http.StatusForbidden {
		t.Errorf("a realm nobody named answered %d", rec.Code)
	}
}

func TestAnAccountIsMadeForATicketOnlyWhereTheRealmSaysSo(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	existsAs := func(name string) string {
		t.Helper()
		var status string
		if err := f.pool.QueryRow(ctx, `SELECT COALESCE(max(status), '') FROM core.users
			WHERE org_id = $1::uuid AND username_fold = lower($2)`, f.orgID, name).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}

	shut := optedRealm(t, f, true, nil, false)
	stranger := fmt.Sprintf("stranger%d", stamp)
	rec := kerberosAt(f, shut.host, ticket(t, shut.keytab, stranger, shut.realm, shut.spn, shut.realm))
	if rec.Code != http.StatusForbidden || existsAs(stranger) != "" {
		t.Errorf("a realm that did not opt in answered %d and made %q", rec.Code, existsAs(stranger))
	}

	open := optedRealm(t, f, true, nil, true)
	newcomer := fmt.Sprintf("newcomer%d", stamp)
	rec = kerberosAt(f, open.host, ticket(t, open.keytab, newcomer, open.realm, open.spn, open.realm))
	user, _ := signedInAs(t, f, rec)
	if user == "" || existsAs(newcomer) != "active" {
		t.Fatalf("no account was made (%d, %q): %.200s", rec.Code, existsAs(newcomer), rec.Body.String())
	}
	if amr := sessionAMR(t, f, rec); len(amr) != 1 || amr[0] != "krb" {
		t.Errorf("the session says amr %v", amr)
	}
	var recorded int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE subject_id = $1 AND event_type = 'kerberos.user_created'`,
		user).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Errorf("%d records of the account being made", recorded)
	}
	// The next ticket finds it rather than making another.
	again := kerberosAt(f, open.host, ticket(t, open.keytab, newcomer, open.realm, open.spn, open.realm))
	if second, _ := signedInAs(t, f, again); second != user {
		t.Errorf("the second ticket signed in %q, not %q", second, user)
	}

	// Somebody deactivated stays that way, however good the ticket.
	gone := fmt.Sprintf("gone%d", stamp)
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.users (org_id, user_handle, username, status)
		VALUES ($1::uuid, decode(repeat(md5(random()::text),4),'hex'), $2, 'deactivated')`, f.orgID, gone); err != nil {
		t.Fatal(err)
	}
	rec = kerberosAt(f, open.host, ticket(t, open.keytab, gone, open.realm, open.spn, open.realm))
	if rec.Code != http.StatusForbidden || existsAs(gone) != "deactivated" {
		t.Errorf("a deactivated name answered %d and is now %q", rec.Code, existsAs(gone))
	}
}

func TestTheUserCreateHookCanRefuseAnAccountForATicket(t *testing.T) {
	f := newSignInFixture(t)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookUserCreate)
	r := optedRealm(t, f, true, nil, true)
	stamp := time.Now().UnixNano()

	welcome := fmt.Sprintf("welcome%d", stamp)
	rec := kerberosAt(f, r.host, ticket(t, r.keytab, welcome, r.realm, r.spn, r.realm))
	if user, _ := signedInAs(t, f, rec); user == "" {
		t.Fatalf("a service saying yes refused it: %d %.200s", rec.Code, rec.Body.String())
	}
	if asked := service.lastAsked(); asked["email"] != welcome || asked["source"] != "kerberos" {
		t.Errorf("the service was told %v", asked)
	}

	service.says(`{"decision":false,"reason":"not on the list"}`)
	refused := fmt.Sprintf("refused%d", stamp)
	rec = kerberosAt(f, r.host, ticket(t, r.keytab, refused, r.realm, r.spn, r.realm))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "not on the list") {
		t.Errorf("a refusal answered %d %.200s", rec.Code, rec.Body.String())
	}
	var made int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.users WHERE org_id = $1::uuid AND username_fold = lower($2)`,
		f.orgID, refused).Scan(&made); err != nil {
		t.Fatal(err)
	}
	if made != 0 {
		t.Error("a refused ticket made an account")
	}
	if hook, reason := lastRefusal(t, f.pool, f.orgID); hook != "user_create" || reason != "not on the list" {
		t.Errorf("recorded %q, %q", hook, reason)
	}
}
