package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/store"
)

// A directory source, the Duo integration and the migration source in a
// configuration file (6.25): each one's secret named by reference, needed to
// make it and again to point it somewhere new; switched off rather than
// deleted where its records are what undoes it; carried by an export without
// its secret.
func TestTheOrganisationsSourcesAreDeclaredWithTheirSecretsByReference(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	env := map[string]string{"AD_PASSWORD": "first-bind", "DUO_SECRET": strings.Repeat("d", 40)}
	plan := func(org, raw string, prune bool) (*File, *Plan, error) {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.ResolveSecrets(func(r SecretRef) (string, error) {
			if v, ok := env[r.Env]; ok {
				return v, nil
			}
			return "", fmt.Errorf("%s is not set", r.Env)
		}); err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlanWith(ctx, tx, org, f, prune, Options{Root: root})
		return f, p, err
	}
	apply := func(org, raw string, prune bool) *Plan {
		t.Helper()
		f, p, err := plan(org, raw, prune)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const sources = `groups: [{name: eng}]
directory_sources:
  - {slug: ad, kind: ldap, url: '%s', bind_dn: 'CN=svc,DC=corp,DC=test', password: {env: AD_PASSWORD},
     base_dn: 'DC=corp,DC=test', flavour: ad, on_missing: deactivate, max_deactivate_percent: 5, dry_run: false,
     group_map: [{remote: 'CN=Engineering,DC=corp,DC=test', group: eng}]}
duo: {client_id: DIABCDEFGHIJKLMNOPQR, secret: {env: DUO_SECRET}, api_host: api-1234abcd.duosecurity.com}
migration_source: {kind: ldap, name: Old directory, url: 'ldaps://old.corp.test',
  bind_dn_template: 'uid={username},ou=people,dc=corp,dc=test'}
`
	at := func(url string) string { return fmt.Sprintf(sources, url) }
	const ad = "ldaps://dc.corp.test"

	p := apply(org, at(ad), false)
	if !strings.Contains(p.String(), "password from $AD_PASSWORD") || !strings.Contains(p.String(), "not checked against Duo") ||
		!strings.Contains(p.String(), "off until enabled") {
		t.Errorf("the creates were planned as\n%s", p)
	}
	held, err := directory.SourceSettingsOf(ctx, tx, org)
	if err != nil || held["ad"].DryRun || held["ad"].OnMissing != "deactivate" || held["ad"].MaxDeactivate != 5 {
		t.Errorf("the source is %+v (%v)", held["ad"], err)
	}
	if creds, _ := directory.SourceCredentials(ctx, tx, root, org, "ad"); string(creds) != "first-bind" {
		t.Errorf("the source binds with %q", creds)
	}
	if m, _ := store.MigrationSourceOf(ctx, tx, org); m == nil || m.Enabled {
		t.Errorf("the migration source is %+v", m)
	}
	if _, p, _ := plan(org, at(ad), false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}

	env["AD_PASSWORD"] = "rotated-bind"
	if p := apply(org, at(ad), false); !strings.Contains(p.String(), "~ directory_source ad   password") {
		t.Errorf("a rotated bind password was planned as\n%s", p)
	}
	if creds, _ := directory.SourceCredentials(ctx, tx, root, org, "ad"); string(creds) != "rotated-bind" {
		t.Error("the source kept the password the file no longer names")
	}
	// Pointed elsewhere without the password, it would bind there with it.
	noPassword := strings.Replace(at("ldaps://evil.test"), "password: {env: AD_PASSWORD},", "", 1)
	if strings.Contains(noPassword, "AD_PASSWORD") {
		t.Fatal("the test's file still names the password")
	}
	if _, _, err := plan(org, noPassword, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "sent there") {
		t.Errorf("moving the source without its password answered %v", err)
	}
	if err := directory.UpdateSource(ctx, tx, root, org, "ad", directory.SourceSpec{Kind: "ldap", LDAPURL: "ldaps://evil.test",
		LDAPBindDN: "CN=svc,DC=corp,DC=test", LDAPBaseDN: "DC=corp,DC=test", LDAPFlavour: "ad"}, false); !errors.Is(err,
		directory.ErrCredentialsForAnotherDirectory) {
		t.Errorf("the writer moved the source without its password: %v", err)
	}

	// Duo: a setting changed without the secret keeps the one held; a new
	// integration key without one is refused.
	keepSecret := strings.Replace(strings.Replace(at(ad), "secret: {env: DUO_SECRET}, ", "", 1), "duosecurity.com}",
		"duosecurity.com, fail_open: true}", 1)
	apply(org, keepSecret, false)
	if s, _ := store.DuoSecretOf(ctx, tx, root, org); s != env["DUO_SECRET"] {
		t.Error("changing fail_open lost the Duo secret")
	}
	if _, _, err := plan(org, strings.Replace(keepSecret, "DIABCDEFGHIJKLMNOPQR", "DIZZZZZZZZZZZZZZZZZZ", 1), false); !errors.Is(err,
		ErrRefused) {
		t.Errorf("a new integration key without its secret answered %v", err)
	}

	// The export carries no secret; applied elsewhere the source asks for its
	// password, and given it plans nothing afterwards.
	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "rotated-bind") || strings.Contains(string(out), env["DUO_SECRET"]) {
		t.Errorf("the export carries a secret:\n%s", out)
	}
	other := freshOrg(t, ctx, tx)
	body := strings.TrimPrefix(string(out), "version: 1\n")
	if _, _, err := plan(other, body, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "password") {
		t.Errorf("the export applied elsewhere answered %v", err)
	}
	given := strings.Replace(strings.Replace(body, "      url: ", "      password: {env: AD_PASSWORD}\n      url: ", 1),
		"    client_id: DIABCDEFGHIJKLMNOPQR\n", "    client_id: DIABCDEFGHIJKLMNOPQR\n    secret: {env: DUO_SECRET}\n", 1)
	apply(other, given, false)
	if _, p, _ := plan(other, given, false); !p.Empty() {
		t.Errorf("the export applied elsewhere plans\n%s", p)
	}

	// Pruned: the source and the migration source switched off and kept,
	// Duo removed, each said.
	apply(org, "groups: [{name: eng}]\nmigration_source: {kind: ldap, name: Old directory, url: 'ldaps://old.corp.test',"+
		" bind_dn_template: 'uid={username},ou=people,dc=corp,dc=test', enabled: true}\n", false)
	p = apply(org, "groups: [{name: eng}]\n", true)
	for _, want := range []string{keptSource, keptMigration, "the Duo stage stops being offered"} {
		if !strings.Contains(p.String(), want) {
			t.Errorf("the pruned plan does not say %q:\n%s", want, p)
		}
	}
	if held, _ := directory.SourceSettingsOf(ctx, tx, org); held["ad"].Enabled {
		t.Error("the pruned source is still enabled")
	}
	if _, p, _ := plan(org, "groups: [{name: eng}]\n", true); !p.Empty() {
		t.Errorf("pruned again it plans\n%s", p)
	}

	for name, raw := range map[string]string{
		"an LDAP source with credentials": "directory_sources: [{slug: a, kind: ldap, credentials: {env: X}}]",
		"a Google source with a bind":     "directory_sources: [{slug: a, kind: google, url: 'ldaps://x', credentials: {env: X}}]",
		"a ceiling past a hundred":        "directory_sources: [{slug: a, kind: ldap, max_deactivate_percent: 150}]",
		"Duo at somebody else's host":     "duo: {client_id: DIABCDEFGHIJKLMNOPQR, api_host: duo.evil.test}",
		"a migration in clear":            "migration_source: {kind: oidc_password, name: o, url: 'http://old.test/token', client_id: c}",
		"a bind with no username":         "migration_source: {kind: ldap, name: o, url: 'ldaps://old.test', bind_dn_template: 'uid=x'}",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
