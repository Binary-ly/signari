package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A remote-access connection in a configuration file (6.19): its credentials
// named by reference and followed when they change, moved to another machine
// only with them, switched off rather than deleted by a pruned file, and
// exported without them.
func TestARemoteAccessConnectionIsDeclaredWithItsCredentialsByReference(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	env := map[string]string{"BUILD_LOGIN": "deploy", "BUILD_PASSWORD": "first"}
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
	held := func(org string) (store.RACListing, store.RACCredentials) {
		t.Helper()
		rows, err := store.RACConnections(ctx, tx, org)
		if err != nil || len(rows) != 1 {
			t.Fatalf("the connections are %+v (%v)", rows, err)
		}
		creds, err := store.HeldRACCredentials(ctx, tx, root, org, rows[0].Slug)
		if err != nil {
			t.Fatal(err)
		}
		return rows[0], creds
	}
	const machine = "groups: [{name: builders}]\nrac_connections:\n  - {slug: build, protocol: ssh, host: %s, " +
		"login: {env: BUILD_LOGIN}, password: {env: BUILD_PASSWORD}, require_group: builders, " +
		"recording_path: /var/lib/guacd/build, parameters: {font-size: '12'}}\n"

	p := apply(org, fmt.Sprintf(machine, "build.internal"), false)
	if !strings.Contains(p.String(), "credentials from $BUILD_LOGIN and $BUILD_PASSWORD") {
		t.Errorf("the create was planned as\n%s", p)
	}
	if h, creds := held(org); creds != (store.RACCredentials{Login: "deploy", Password: "first"}) || h.Port != 22 ||
		h.RequireGroup != "builders" || !h.Recorded || h.Parameters["font-size"] != "12" {
		t.Errorf("the connection is %+v", h)
	}
	if _, p, _ := plan(org, fmt.Sprintf(machine, "build.internal"), false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}
	env["BUILD_PASSWORD"] = "rotated"
	if p := apply(org, fmt.Sprintf(machine, "build.internal"), false); !strings.Contains(p.String(), "credentials") {
		t.Errorf("a changed password was planned as\n%s", p)
	}
	if _, creds := held(org); creds.Password != "rotated" {
		t.Error("the connection kept the password the file no longer names")
	}

	// Moved without its credentials, guacd would type them into the new host.
	moved := "rac_connections: [{slug: build, protocol: ssh, host: elsewhere.internal}]\n"
	if _, _, err := plan(org, moved, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "typed into") {
		t.Errorf("moving the connection without its credentials answered %v", err)
	}
	host := "elsewhere.internal"
	if err := store.UpdateRACConnection(ctx, tx, root, org, "build", store.RACChange{Host: &host}); !errors.Is(err,
		store.ErrRACCredentialsForAnotherMachine) {
		t.Errorf("the writer moved the connection without its credentials: %v", err)
	}
	apply(org, fmt.Sprintf(machine, host), false)
	if h, _ := held(org); h.Host != host {
		t.Errorf("moved with its credentials, the connection names %s", h.Host)
	}
	if _, _, err := plan(org, "rac_connections: [{slug: build, protocol: rdp, host: x}]\n", false); !errors.Is(err,
		ErrRefused) {
		t.Errorf("a connection's protocol changed in place: %v", err)
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "rotated") || strings.Contains(string(out), "login") {
		t.Errorf("the export carries the credentials:\n%s", out)
	}
	other := freshOrg(t, ctx, tx)
	body := strings.TrimPrefix(string(out), "version: 1\n")
	if p := apply(other, body, false); !strings.Contains(p.String(), "holds no credentials") {
		t.Errorf("the export applied elsewhere was planned as\n%s", p)
	}
	if _, p, _ := plan(other, body, false); !p.Empty() {
		t.Errorf("the export applied elsewhere plans\n%s", p)
	}
	// Holding none, it moves freely.
	if _, _, err := plan(other, strings.Replace(body, host, "third.internal", 1), false); err != nil {
		t.Errorf("a connection holding no credentials could not move: %v", err)
	}

	if p := apply(org, "groups: [{name: builders}]\n", true); !strings.Contains(p.String(), keptConnection) ||
		p.Destructive() != nil {
		t.Errorf("the pruned plan reads\n%s", p)
	}
	if h, _ := held(org); h.Enabled {
		t.Error("the pruned connection is still enabled")
	}
	if _, p, _ := plan(org, "groups: [{name: builders}]\n", true); !p.Empty() {
		t.Errorf("pruned again it plans\n%s", p)
	}
}

// What a file may not say about a connection, refused before anything is read.
func TestAConnectionTheFileCannotDescribeIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"a protocol guacd is not asked to speak": "rac_connections: [{slug: a, protocol: telnet, host: a}]",
		"no host":                                "rac_connections: [{slug: a, protocol: ssh}]",
		"a port that is not one":                 "rac_connections: [{slug: a, protocol: ssh, host: a, port: 70000}]",
		"a credential as a parameter":            "rac_connections: [{slug: a, protocol: ssh, host: a, parameters: {password: x}}]",
		"the engine's own setting":               "rac_connections: [{slug: a, protocol: ssh, host: a, password: {env: SIGNARI_DSN}}]",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	f, err := Parse([]byte("version: 1\nrac_connections: [{slug: a, protocol: ssh, host: a, login: {env: L}, " +
		"password: {file: p.txt}}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.SecretReferences(); len(got) != 2 || got[0] != "rac_connections[a].login" ||
		got[1] != "rac_connections[a].password" {
		t.Errorf("the references are %v", got)
	}
}
