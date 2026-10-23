package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// What a client, a SAML provider and a network device are told of group
// membership (6.25): each release names its groups or says all_groups, is the
// organisation's own application's, and a pruned group is not released.
func TestGroupReleasesAndRADIUSAuthorizationsAreDeclared(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org := freshOrg(t, ctx, tx)
	n := time.Now().UnixNano()
	plan := func(raw string, prune bool) (*File, *Plan, error) {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlan(ctx, tx, org, f, prune)
		return f, p, err
	}
	apply := func(raw string, prune bool) *Plan {
		t.Helper()
		f, p, err := plan(raw, prune)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	apps := fmt.Sprintf(`groups: [{name: staff}, {name: ops}]
clients: [{client_id: wiki-%[1]d, redirect_uris: ['https://wiki.example.test/cb']}]
saml_providers: [{entity_id: 'https://sp-%[1]d.example.test', acs_urls: ['https://sp-%[1]d.example.test/acs']}]
`, n)
	releases := apps + fmt.Sprintf(`group_releases:
  - {client_id: wiki-%[1]d, groups: [staff]}
  - {saml_provider: 'https://sp-%[1]d.example.test', all_groups: true, attribute: memberOf}
radius_authorizations: [{group: ops, vlan: 20, priority: 5}]
`, n)
	apply(releases, false)
	if only, released, err := store.GroupReleaseOf(ctx, tx, fmt.Sprintf("wiki-%d", n)); err != nil || !released ||
		len(only) != 1 || only[0] != "staff" {
		t.Errorf("the client is told %v (released %v, %v)", only, released, err)
	}
	sps, err := store.SAMLProviders(ctx, tx, org)
	if err != nil || len(sps) != 1 || !sps[0].ReleasesGroups || len(sps[0].OnlyGroups) != 0 ||
		sps[0].GroupAttribute != "memberOf" {
		t.Errorf("the service provider is %+v (%v)", sps, err)
	}
	if auths, err := store.RADIUSAuthorizations(ctx, tx, org, nil); err != nil || len(auths) != 1 ||
		auths[0].VLAN == nil || *auths[0].VLAN != 20 || auths[0].Priority != 5 {
		t.Errorf("the RADIUS authorizations are %+v (%v)", auths, err)
	}
	if _, p, _ := plan(releases, false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}

	// Pruned, a group the file leaves out is deleted, so a release naming it
	// would release nothing: refused, not planned.
	keepsRelease := strings.Replace(releases, "{name: staff}, ", "", 1)
	if _, _, err := plan(keepsRelease, true); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "staff") {
		t.Errorf("a release of a group the prune deletes answered %v", err)
	}
	// Pruned of releases, each is stopped and the plan says what that does.
	p := apply(apps, true)
	if len(p.Destructive()) != 3 || !strings.Contains(p.String(), "stops being told which groups") {
		t.Errorf("the pruned plan reads\n%s", p)
	}
	if _, released, _ := store.GroupReleaseOf(ctx, tx, fmt.Sprintf("wiki-%d", n)); released {
		t.Error("the pruned release still tells the client")
	}

	// Another organisation's client is not this file's to release to.
	other := freshOrg(t, ctx, tx)
	theirs := fmt.Sprintf("theirs-%d", n)
	if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash, grant_types, scopes) VALUES ($1, $2::uuid, 'T', 'public', '', '{authorization_code}',
		'{openid}')`, theirs, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plan(fmt.Sprintf("groups: [{name: staff}]\ngroup_releases: [{client_id: %s, all_groups: true}]\n",
		theirs), false); !errors.Is(err, ErrRefused) {
		t.Errorf("a release to another organisation's client answered %v", err)
	}

	for name, raw := range map[string]string{
		"a release to nobody":             "group_releases: [{groups: [a]}]",
		"a release to both":               "group_releases: [{client_id: c, saml_provider: s, groups: [a]}]",
		"a release of nothing named":      "group_releases: [{client_id: c}]",
		"a release of all and some":       "group_releases: [{client_id: c, groups: [a], all_groups: true}]",
		"an attribute for a client":       "group_releases: [{client_id: c, groups: [a], attribute: memberOf}]",
		"an authorization of nothing":     "radius_authorizations: [{group: a}]",
		"a VLAN past twelve bits":         "radius_authorizations: [{group: a, vlan: 5000}]",
		"the same group authorized twice": "radius_authorizations: [{group: a, vlan: 1}, {group: a, vlan: 2}]",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
