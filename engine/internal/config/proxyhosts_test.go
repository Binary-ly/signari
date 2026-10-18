package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
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
