package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// freshOrg is an organisation of the test's own, in tx: a provider is keyed on
// its hook, of which there are two, so the shared organisation may hold one.
func freshOrg(t *testing.T, ctx context.Context, tx pgx.Tx) string {
	t.Helper()
	n := time.Now().UnixNano()
	var org string
	if err := tx.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'probe') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $2, 'probe' FROM i RETURNING id::text`,
		fmt.Sprintf("https://signing-%d.invalid", n), fmt.Sprintf("signing-%d", n)).Scan(&org); err != nil {
		t.Fatal(err)
	}
	return org
}

func testRoot(t *testing.T) *keys.RootKey {
	t.Helper()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// A provider's and a subscription's signing secrets (6.19): minted when the
// file names none and reported once, the named one held when it does and
// followed when it changes, and never in an export, which applied to an empty
// organisation mints its own and plans nothing afterwards.
func TestSigningSecretsAreMintedOnceOrNamedAndNeverExported(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	env := map[string]string{"SIEM_SECRET": strings.Repeat("s", 40), "PDP_SECRET": strings.Repeat("p", 40)}
	read := func(r SecretRef) (string, error) {
		if v, ok := env[r.Env]; ok {
			return v, nil
		}
		return "", fmt.Errorf("%s is not set", r.Env)
	}
	apply := func(org string, f *File) *Plan {
		t.Helper()
		if err := f.ResolveSecrets(read); err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlanWith(ctx, tx, org, f, false, Options{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	parse := func(raw string) *File {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	const raw = `providers:
  - {hook: token_issue, url: 'https://hooks.example.test/claims', mode: fail_open, claims: [department]}
  - {hook: authorize, url: 'https://pdp.example.test/', mode: fail_closed, secret: {env: PDP_SECRET}}
event_subscriptions:
  - {name: siem, url: 'https://siem.example.test/in', event_types: [login.failed], secret: {env: SIEM_SECRET}}
`
	p := apply(org, parse(raw))
	if len(p.Minted) != 1 || p.Minted[0].Kind != "provider" || p.Minted[0].Name != "token_issue" {
		t.Fatalf("minted %+v, want the provider's alone", p.Minted)
	}
	if !strings.Contains(p.String(), "signing secret from $SIEM_SECRET") ||
		!strings.Contains(p.String(), "a signing secret is minted and shown once") {
		t.Errorf("the plan does not say where each secret comes from:\n%s", p)
	}
	if held, err := store.ProviderSecret(ctx, tx, root, org, "token_issue"); err != nil || held != p.Minted[0].Secret {
		t.Errorf("the provider holds %q (%v), not the secret reported", held, err)
	}
	if held, err := store.SubscriptionSecret(ctx, tx, root, org, "siem"); err != nil || held != env["SIEM_SECRET"] {
		t.Errorf("the subscription holds %q (%v), not the one the file names", held, err)
	}
	if held, err := store.ProviderSecret(ctx, tx, root, org, "authorize"); err != nil || held != env["PDP_SECRET"] {
		t.Errorf("the authorize provider holds %q (%v), not the one the file names", held, err)
	}
	var minted bool
	if err := tx.QueryRow(ctx, `SELECT bool_or((detail->>'secret_minted')::boolean) FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type = 'config.applied'`, org).Scan(&minted); err != nil || !minted {
		t.Errorf("no applied change records that a secret was minted (%v)", err)
	}

	if p := apply(org, parse(raw)); !p.Empty() || len(p.Minted) != 0 {
		t.Errorf("applied again it planned\n%s\nand minted %d", p, len(p.Minted))
	}
	// The secret changed where it is kept: the plan says so, and the apply
	// follows.
	env["SIEM_SECRET"], env["PDP_SECRET"] = strings.Repeat("t", 40), strings.Repeat("q", 40)
	if p := apply(org, parse(raw)); !strings.Contains(p.String(), "~ event_subscription siem   secret") ||
		!strings.Contains(p.String(), "~ provider       authorize   secret") {
		t.Errorf("a changed secret was planned as\n%s", p)
	}
	if held, _ := store.SubscriptionSecret(ctx, tx, root, org, "siem"); held != env["SIEM_SECRET"] {
		t.Error("the subscription kept the secret the file no longer names")
	}
	if held, _ := store.ProviderSecret(ctx, tx, root, org, "authorize"); held != env["PDP_SECRET"] {
		t.Error("the authorize provider kept the secret the file no longer names")
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "secret") || len(exported.SecretReferences()) != 0 {
		t.Errorf("the export carries a secret:\n%s", out)
	}
	other := freshOrg(t, ctx, tx)
	if p := apply(other, parse(strings.TrimPrefix(string(out), "version: 1\n"))); len(p.Minted) != 3 {
		t.Errorf("the export applied elsewhere minted %+v, want one for each", p.Minted)
	}
	if p := apply(other, parse(strings.TrimPrefix(string(out), "version: 1\n"))); !p.Empty() {
		t.Errorf("the export applied twice plans\n%s", p)
	}
}

// Where a secret cannot be read or sealed, or is not one, the plan refuses it
// as the caller's mistake, before anything is written; what the file alone
// shows is wrong, Validate refuses.
func TestASecretThatCannotBeHeldIsRefusedByThePlan(t *testing.T) {
	for name, raw := range map[string]string{
		"a reference to the root key": "event_subscriptions: [{name: a, url: 'https://a.example.test/', " +
			"secret: {env: SIGNARI_ROOT_KEY}}]",
		"a reference to the database's password": "event_subscriptions: [{name: a, url: 'https://a.example.test/', " +
			"secret: {env: PGPASSWORD}}]",
		"a reference to two places": "event_subscriptions: [{name: a, url: 'https://a.example.test/', " +
			"secret: {env: A, file: a.txt}}]",
		"a reference to nothing":  "event_subscriptions: [{name: a, url: 'https://a.example.test/', secret: {}}]",
		"an expression":           "event_subscriptions: [{name: a, url: 'https://a.example.test/', secret: {env: '$(id)'}}]",
		"a subscription in clear": "event_subscriptions: [{name: a, url: 'http://a.example.test/'}]",
		"an event nobody records": "event_subscriptions: [{name: a, url: 'https://a.example.test/', event_types: [login.failure]}]",
		"a provider with no mode": "providers: [{hook: authorize, url: 'https://a.example.test/'}]",
		"a hook nothing calls":    "providers: [{hook: logout, url: 'https://a.example.test/', mode: fail_open}]",
		"claims on authorize":     "providers: [{hook: authorize, url: 'https://a.example.test/', mode: fail_closed, claims: [x]}]",
		"a protocol claim": "providers: [{hook: token_issue, url: 'https://a.example.test/', mode: fail_open, " +
			"claims: [sub]}]",
		"a timeout past the ceiling": "providers: [{hook: authorize, url: 'https://a.example.test/', mode: fail_closed, " +
			"timeout: 1m}]",
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
	plan := func(raw string, value string, opts Options) error {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if value != "" {
			if err := f.ResolveSecrets(func(SecretRef) (string, error) { return value, nil }); err != nil {
				t.Fatal(err)
			}
		}
		_, err = BuildPlanWith(ctx, tx, org, f, false, opts)
		return err
	}
	named := "event_subscriptions: [{name: a, url: 'https://a.example.test/', secret: {env: A_SECRET}}]"
	if err := plan(named, "", Options{Root: testRoot(t)}); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "only `signari apply` reads") {
		t.Errorf("a reference nothing read answered %v", err)
	}
	if err := plan(named, "short", Options{Root: testRoot(t)}); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "at least 32") {
		t.Errorf("a short secret answered %v", err)
	}
	if err := plan("providers: [{hook: authorize, url: 'https://a.example.test/', mode: fail_closed}]", "",
		Options{}); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "SIGNARI_ROOT_KEY") {
		t.Errorf("a provider planned with no root key answered %v", err)
	}
	if err := plan(named, strings.Repeat("x", 32), Options{}); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "SIGNARI_ROOT_KEY") {
		t.Errorf("a named secret planned with no root key answered %v", err)
	}
	// Nothing needing the key, nothing refused for the want of it.
	if err := plan("groups: [{name: g}]", "", Options{}); err != nil {
		t.Errorf("a file holding no secret, planned with no root key: %v", err)
	}
	f, err := Parse([]byte("version: 1\n" + named + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.SecretReferences(); len(got) != 1 || got[0] != "event_subscriptions[a].secret" {
		t.Errorf("the references are %v", got)
	}
}

// A subscription's switch, which the deliveries also throw: left alone when
// the file says nothing, and thrown either way when it does.
func TestASubscriptionIsSwitchedOnlyWhenTheFileSaysSo(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	apply := func(enabled string) *Plan {
		t.Helper()
		f, err := Parse([]byte("version: 1\nevent_subscriptions: [{name: siem, url: 'https://siem.example.test/'" +
			enabled + "}]\n"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlanWith(ctx, tx, org, f, false, Options{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	state := func() (bool, string) {
		t.Helper()
		var on bool
		var reason string
		if err := tx.QueryRow(ctx, `SELECT enabled, COALESCE(disabled_reason, '') FROM core.event_subscriptions
			WHERE org_id = $1::uuid AND display_name = 'siem'`, org).Scan(&on, &reason); err != nil {
			t.Fatal(err)
		}
		return on, reason
	}
	apply(", enabled: false")
	if on, reason := state(); on || reason != disabledByFile {
		t.Errorf("created switched off, it is enabled=%v (%q)", on, reason)
	}
	if p := apply(""); !p.Empty() {
		t.Errorf("a file silent on it planned\n%s", p)
	}
	apply(", enabled: true")
	if on, _ := state(); !on {
		t.Error("a file switching it on left it off")
	}
	// Given up on by the deliveries, it is not switched back on by a file
	// that does not say to.
	if _, err := tx.Exec(ctx, `UPDATE core.event_subscriptions SET enabled = false, disabled_at = now(),
		disabled_reason = 'gave up' WHERE org_id = $1::uuid AND display_name = 'siem'`, org); err != nil {
		t.Fatal(err)
	}
	if p := apply(""); !p.Empty() {
		t.Errorf("a file silent on it planned\n%s", p)
	}
	if p := apply(", enabled: true"); !strings.Contains(p.String(), "enabled") {
		t.Errorf("switching back on what was given up on planned\n%s", p)
	}
	if on, reason := state(); !on || reason != "" {
		t.Errorf("switched back on, it is enabled=%v (%q)", on, reason)
	}
}
