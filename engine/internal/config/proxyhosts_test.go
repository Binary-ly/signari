package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/proxyrules"
)

// Forward-auth hosts were read on every return from sign-in and written by
// nothing. `apply` is one of the three ways in now.

func TestAProxyHostIsWrittenAsStored(t *testing.T) {
	for doc, want := range map[string]string{
		"version: 1\nproxy_hosts:\n  - host: Grafana.Example.com\n":                    "write \"Grafana.Example.com\" as \"grafana.example.com\"",
		"version: 1\nproxy_hosts:\n  - host: https://grafana.example.com\n":            "not a URL",
		"version: 1\nproxy_hosts:\n  - host: a.example.com\n  - host: a.example.com\n": "appears twice",
	} {
		_, err := Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", doc, err, want)
		}
	}
	if _, err := Parse([]byte("version: 1\nproxy_hosts:\n  - host: wiki.example.com:8443\n")); err != nil {
		t.Errorf("a host with a port was refused: %v", err)
	}
}

// Rules are a host's, declared in a file, kept by one that does not name them, moved by
// a change of order, since the order is what they mean, and exported to be applied again.
func TestAHostsRulesAreDeclared(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	host := fmt.Sprintf("rules-%d.example.com", time.Now().UnixNano())
	public := proxyrules.Rule{Effect: proxyrules.EffectPublic, Path: "/static/**", Methods: []string{"GET"}}
	deny := proxyrules.Rule{Effect: proxyrules.EffectDeny, Path: "/static/private/**"}
	with := func(rules ...proxyrules.Rule) *File {
		return &File{ProxyHosts: []ProxyHost{{Host: host, Rules: &rules}}}
	}
	planOf := func(f *File) *Plan {
		t.Helper()
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	apply := func(f *File) {
		t.Helper()
		if err := Apply(ctx, tx, org, f, planOf(f)); err != nil {
			t.Fatal(err)
		}
	}
	held := func() []proxyrules.Rule {
		t.Helper()
		var rules []proxyrules.Rule
		if err := tx.QueryRow(ctx, `SELECT rules FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, org, host).
			Scan(&rules); err != nil {
			t.Fatal(err)
		}
		return rules
	}

	apply(with(public, deny))
	if got := held(); len(got) != 2 || got[0].Effect != proxyrules.EffectPublic || got[1].Effect != proxyrules.EffectDeny {
		t.Fatalf("held %+v", got)
	}
	if plan := planOf(with(public, deny)); len(plan.Changes) != 0 {
		t.Errorf("the same rules planned %+v", plan.Changes)
	}
	if plan := planOf(with(deny, public)); len(plan.Changes) != 1 {
		t.Errorf("the same rules in another order planned %+v", plan.Changes)
	}

	apply(&File{ProxyHosts: []ProxyHost{{Host: host}}})
	if got := held(); len(got) != 2 {
		t.Errorf("a file that does not name them left %+v", got)
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range exported.ProxyHosts {
		if h.Host == host {
			found = h.Rules != nil && len(*h.Rules) == 2
		}
	}
	if !found {
		t.Error("the export has no rules for the host")
	}

	apply(with())
	if got := held(); len(got) != 0 {
		t.Errorf("an empty list left %+v", got)
	}

	if _, err := Parse([]byte("version: 1\nproxy_hosts:\n  - host: a.example.com\n    rules:\n      - {effect: allow, path: /x}\n")); err == nil {
		t.Error("a file with a rule that cannot be meant was read")
	}
}

func TestApplyRegistersUpdatesAndPrunesProxyHosts(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	host := fmt.Sprintf("app-%d.example.com", time.Now().UnixNano())
	state := func() (bool, bool) {
		t.Helper()
		var enabled bool
		err := tx.QueryRow(ctx,
			`SELECT enabled FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, org, host).
			Scan(&enabled)
		return err == nil, enabled
	}
	apply := func(f *File, prune bool) {
		t.Helper()
		plan, err := BuildPlan(ctx, tx, org, f, prune)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
	}

	apply(&File{ProxyHosts: []ProxyHost{{Host: host}}}, false)
	if ok, enabled := state(); !ok || !enabled {
		t.Fatalf("applying a host left it (exists %v, enabled %v)", ok, enabled)
	}

	off := false
	apply(&File{ProxyHosts: []ProxyHost{{Host: host, Enabled: &off}}}, false)
	if _, enabled := state(); enabled {
		t.Fatal("enabled: false in the file did not disable the host")
	}

	// Pruning deletes whatever the file does not name, so the file names
	// everything this organisation holds except this test's host -- the prune
	// then removes that host and nothing another test is using.
	current, err := read(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	keep := &File{}
	for _, g := range current.groups {
		keep.Groups = append(keep.Groups, g)
	}
	for _, c := range current.clients {
		keep.Clients = append(keep.Clients, c)
	}
	for _, s := range current.samlProviders {
		keep.SAMLProviders = append(keep.SAMLProviders, s)
	}
	for _, r := range current.radiusClients {
		keep.RADIUSClients = append(keep.RADIUSClients, r)
	}
	for name, h := range current.proxyHosts {
		if name != host {
			keep.ProxyHosts = append(keep.ProxyHosts, h)
		}
	}
	apply(keep, true)
	if ok, _ := state(); ok {
		t.Fatal("-prune left a host the file no longer names")
	}
}
