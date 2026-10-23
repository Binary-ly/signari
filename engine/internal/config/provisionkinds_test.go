package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/store"
)

// A provisioning target in a configuration file (6.19): its token named by
// reference, needed to make it and followed when it changes; its address moved
// only with a token for the new one; switched off, never deleted, by a pruned
// file; and exported without the token, so the export applied elsewhere asks
// for one.
func TestAProvisioningTargetIsDeclaredWithItsTokenByReference(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	env := map[string]string{"SLACK_TOKEN": "xoxp-first"}
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
	held := func(org string) (store.SCIMTargetRow, string) {
		t.Helper()
		rows, err := store.SCIMTargets(ctx, tx, org)
		if err != nil || len(rows) != 1 {
			t.Fatalf("the targets are %+v (%v)", rows, err)
		}
		token, err := store.SCIMTargetSecret(ctx, tx, root, org, rows[0].Slug)
		if err != nil {
			t.Fatal(err)
		}
		return rows[0], token
	}
	const target = "groups: [{name: staff}]\nscim_targets:\n  - {slug: slack, base_url: 'https://%s.example.test/scim/v2', " +
		"token: {env: SLACK_TOKEN}, dry_run: true, scope_group: staff}\n"

	p := apply(org, fmt.Sprintf(target, "api"), false)
	if !strings.Contains(p.String(), "token from $SLACK_TOKEN; nothing is sent until it is synced") {
		t.Errorf("the create was planned as\n%s", p)
	}
	if h, token := held(org); token != "xoxp-first" || !h.DryRun || h.ScopeGroup != "staff" || !h.Enabled {
		t.Errorf("the target is %+v holding %q", h, token)
	}
	if _, p, _ := plan(org, fmt.Sprintf(target, "api"), false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}
	env["SLACK_TOKEN"] = "xoxp-reissued"
	if p := apply(org, fmt.Sprintf(target, "api"), false); !strings.Contains(p.String(), "~ scim_target    slack   token") {
		t.Errorf("a reissued token was planned as\n%s", p)
	}
	if _, token := held(org); token != "xoxp-reissued" {
		t.Error("the target kept the token the file no longer names")
	}

	// Moved without the token, the held one would go to the new address.
	noToken := "scim_targets: [{slug: slack, base_url: 'https://elsewhere.example.test/scim/v2'}]\n"
	if _, _, err := plan(org, noToken, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "needs the token too") {
		t.Errorf("moving the target without its token answered %v", err)
	}
	if err := provision.UpdateTarget(ctx, tx, root, org, "slack", "scim", provision.TargetChange{
		BaseURL: ptr("https://elsewhere.example.test/scim/v2")}); !errors.Is(err, provision.ErrTargetInvalid) {
		t.Errorf("the writer moved the target without its token: %v", err)
	}
	apply(org, fmt.Sprintf(target, "elsewhere"), false)
	if h, _ := held(org); h.BaseURL != "https://elsewhere.example.test/scim/v2" {
		t.Errorf("moved with its token, the target is at %s", h.BaseURL)
	}
	if _, _, err := plan(org, "scim_targets: [{slug: slack, kind: entra, credentials: {env: SLACK_TOKEN}}]\n",
		false); !errors.Is(err, ErrRefused) {
		t.Errorf("a target's kind changed in place: %v", err)
	}

	// The export carries no token; applied elsewhere it asks for one, and
	// given one it plans nothing afterwards.
	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "xoxp") || strings.Contains(string(out), "token") {
		t.Errorf("the export carries the token:\n%s", out)
	}
	other := freshOrg(t, ctx, tx)
	body := strings.TrimPrefix(string(out), "version: 1\n")
	if _, _, err := plan(other, body, false); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "scim_targets[slack].token: name it by reference") {
		t.Errorf("the export applied elsewhere answered %v", err)
	}
	given := strings.Replace(body, "base_url:", "token: {env: SLACK_TOKEN}\n      base_url:", 1)
	apply(other, given, false)
	if _, p, _ := plan(other, given, false); !p.Empty() {
		t.Errorf("the export applied elsewhere plans\n%s", p)
	}

	// Pruned, it is switched off and kept, links and all; the group it is
	// limited to is not pruned out from under it, which would widen it.
	if _, _, err := plan(org, "", true); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "widen") {
		t.Errorf("pruning the group the kept target is limited to answered %v", err)
	}
	const kept = "groups: [{name: staff}]\n"
	if p := apply(org, kept, true); !strings.Contains(p.String(), keptTarget) || p.Destructive() != nil {
		t.Errorf("the pruned plan reads\n%s", p)
	}
	if h, _ := held(org); h.Enabled {
		t.Error("the pruned target is still enabled")
	}
	if _, p, _ := plan(org, kept, true); !p.Empty() {
		t.Errorf("pruned again it plans\n%s", p)
	}
	// Moved to everybody in the same file, the group can go.
	apply(org, "scim_targets: [{slug: slack, base_url: 'https://elsewhere.example.test/scim/v2', scope_group: ''}]\n",
		true)
	if h, _ := held(org); h.ScopeGroup != "" {
		t.Errorf("the target is still limited to %q", h.ScopeGroup)
	}
}

func ptr[T any](v T) *T { return &v }

// What a file may not say about a target, refused before anything is read.
func TestATargetTheFileCannotDescribeIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"a target in clear":           "scim_targets: [{slug: a, base_url: 'http://a.example.test/', token: {env: T}}]",
		"a SCIM target with no URL":   "scim_targets: [{slug: a, token: {env: T}}]",
		"a SCIM target's credentials": "scim_targets: [{slug: a, base_url: 'https://a.example.test/', credentials: {env: T}}]",
		"Google with no domain":       "scim_targets: [{slug: a, kind: google, impersonate: admin@a.test, credentials: {env: T}}]",
		"Entra impersonating":         "scim_targets: [{slug: a, kind: entra, impersonate: admin@a.test, credentials: {env: T}}]",
		"Google with a token":         "scim_targets: [{slug: a, kind: google, impersonate: x, target_domain: y, token: {env: T}}]",
		"a kind nobody speaks":        "scim_targets: [{slug: a, kind: ldap, credentials: {env: T}}]",
		"a deactivation unknown":      "scim_targets: [{slug: a, base_url: 'https://a.example.test/', token: {env: T}, on_deactivate: erase}]",
		"the engine's own token":      "scim_targets: [{slug: a, base_url: 'https://a.example.test/', token: {env: SIGNARI_ADMIN_TOKEN}}]",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org := freshOrg(t, ctx, tx)
	plan := func(raw, value string) error {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.ResolveSecrets(func(SecretRef) (string, error) { return value, nil }); err != nil {
			t.Fatal(err)
		}
		_, err = BuildPlanWith(ctx, tx, org, f, false, Options{Root: testRoot(t)})
		return err
	}
	if err := plan("scim_targets: [{slug: g, kind: google, impersonate: admin@a.test, target_domain: a.test, "+
		"credentials: {env: SA}}]", "not a service account"); !errors.Is(err, ErrRefused) {
		t.Errorf("credentials that will not parse answered %v", err)
	}
	if err := plan("scim_targets: [{slug: s, base_url: 'https://a.example.test/', token: {env: T}, "+
		"scope_group: nobody-has-this}]", "tok"); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no group") {
		t.Errorf("a target limited to a group nobody has answered %v", err)
	}
	f, err := Parse([]byte("version: 1\nscim_targets: [{slug: g, kind: google, impersonate: x, target_domain: y, " +
		"credentials: {file: sa.json}}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.SecretReferences(); len(got) != 1 || got[0] != "scim_targets[g].credentials" {
		t.Errorf("the references are %v", got)
	}
}
