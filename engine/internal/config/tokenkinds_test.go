package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Outposts, inbound SCIM sources, Shared Signals and the authorization model
// in a configuration file (6.25): the tokens the engine generates minted and
// shown once and never chosen, a stream moved only with its receiver's token,
// a source a file says nothing about left switched off, and what a pruned
// file leaves out switched off where deleting it would take its record.
func TestOutpostsSourcesAndSignalsAreDeclared(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	n := time.Now().UnixNano()
	env := map[string]string{"RECEIVER_TOKEN": "receiver-first"}
	plan := func(raw string, prune bool) (*File, *Plan, error) {
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
	rp := fmt.Sprintf("rp-%d", n)
	file := fmt.Sprintf(`groups: [{name: directory-readers}]
clients: [{client_id: %[1]s, redirect_uris: ['https://rp.example.test/cb']}]
outposts:
  - {name: ldap-front, kind: ldap, search_group: directory-readers}
  - {name: wifi, kind: radius}
scim_sources: [{slug: hr, name: HR system, on_delete: deactivate}]
ssf_streams:
  - {client_id: %[1]s, endpoint: '%%s', receiver_token: {env: RECEIVER_TOKEN}, events: [%[2]s]}
ssf_sources:
  - {issuer: 'https://idp.partner.test', name: Partner, jwks_uri: 'https://idp.partner.test/jwks',
     audience: 'https://us.example.test', events: [%[2]s]}
authorization_model: |
  types:
    document:
      relations:
        owner: []
        viewer: [owner]
      permissions:
        read: [viewer]
`, rp, "'https://schemas.openid.net/secevent/caep/event-type/session-revoked'")
	at := func(endpoint string) string { return fmt.Sprintf(file, endpoint) }
	const endpoint = "https://rp.example.test/ssf"

	p := apply(at(endpoint), false)
	kinds := map[string]bool{}
	for _, m := range p.Minted {
		if len(m.Secret) < 32 {
			t.Errorf("the %s %s token is %d characters", m.Kind, m.Name, len(m.Secret))
		}
		kinds[m.Kind+" "+m.Name] = true
	}
	if len(p.Minted) != 3 || !kinds["outpost ldap-front"] || !kinds["outpost wifi"] || !kinds["scim_source hr"] {
		t.Errorf("minted %v", kinds)
	}
	if token, _ := store.StreamReceiverToken(ctx, tx, root, org, rp); token != "receiver-first" {
		t.Errorf("the stream holds %q", token)
	}
	if source, _ := store.ModelSource(ctx, tx, org); !strings.Contains(source, "viewer: [owner]") {
		t.Errorf("the model in force is %q", source)
	}
	if _, p, _ := plan(at(endpoint), false); !p.Empty() || len(p.Minted) != 0 {
		t.Errorf("applied again it plans\n%s", p)
	}

	// Moved without the receiver's token, it would be pushed elsewhere.
	moved := strings.Replace(at("https://elsewhere.example.test/ssf"), "receiver_token: {env: RECEIVER_TOKEN}, ", "", 1)
	if _, _, err := plan(moved, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "sent there") {
		t.Errorf("moving the stream without its token answered %v", err)
	}
	if err := store.UpdateStream(ctx, tx, root, org, store.StreamSpec{ClientID: rp,
		Endpoint: "https://elsewhere.example.test/ssf"}, false); !errors.Is(err, store.ErrStreamTokenForAnotherEndpoint) {
		t.Errorf("the writer moved the stream without its token: %v", err)
	}
	env["RECEIVER_TOKEN"] = "receiver-rotated"
	if p := apply(at(endpoint), false); !strings.Contains(p.String(), "receiver_token") {
		t.Errorf("a rotated receiver token was planned as\n%s", p)
	}
	if _, _, err := plan(strings.Replace(at(endpoint), "kind: radius", "kind: proxy", 1), false); !errors.Is(err, ErrRefused) {
		t.Errorf("an outpost's kind changed in place: %v", err)
	}
	if _, _, err := plan(strings.Replace(at(endpoint), "on_delete: deactivate", "on_delete: delete", 1), false); !errors.Is(err,
		ErrRefused) {
		t.Errorf("a SCIM source's deprovisioning changed in place: %v", err)
	}

	// Switched off by the deliveries' operator, a source the file says
	// nothing about stays off when the file changes it otherwise.
	if err := store.SetSSFSourceEnabled(ctx, tx, org, "https://idp.partner.test", false); err != nil {
		t.Fatal(err)
	}
	apply(strings.Replace(at(endpoint), "name: Partner", "name: Partner Inc", 1), false)
	if srcs, _ := store.Sources(ctx, tx, org); len(srcs) != 1 || srcs[0].Enabled || srcs[0].Name != "Partner Inc" {
		t.Errorf("the source is %+v", srcs)
	}

	p = apply(fmt.Sprintf("groups: [{name: directory-readers}]\nclients: [{client_id: %s, redirect_uris: "+
		"['https://rp.example.test/cb']}]\n", rp), true)
	for _, want := range []string{keptOutpost, keptSCIMSource, "the receiver stops being told",
		"every relation check finds nothing"} {
		if !strings.Contains(p.String(), want) {
			t.Errorf("the pruned plan does not say %q:\n%s", want, p)
		}
	}
	if outposts, _ := store.Outposts(ctx, tx, org); len(outposts) != 2 || outposts[0].Enabled || outposts[1].Enabled {
		t.Errorf("pruned, the outposts are %+v", outposts)
	}

	other := freshOrg(t, ctx, tx)
	theirs := fmt.Sprintf("theirs-%d", n)
	if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash, grant_types, scopes) VALUES ($1, $2::uuid, 'T', 'public', '', '{authorization_code}',
		'{openid}')`, theirs, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plan(fmt.Sprintf("ssf_streams: [{client_id: %s, poll: true}]\n", theirs), false); !errors.Is(err,
		ErrRefused) {
		t.Errorf("a stream for another organisation's client answered %v", err)
	}

	for name, raw := range map[string]string{
		"an outpost of no kind":         "outposts: [{name: o, kind: mainframe}]",
		"a search group off LDAP":       "outposts: [{name: o, kind: radius, search_group: g}]",
		"a SCIM source erasing oddly":   "scim_sources: [{slug: s, on_delete: shred}]",
		"a push stream in clear":        "ssf_streams: [{client_id: c, endpoint: 'http://rp.test/ssf'}]",
		"a poll stream with a token":    "ssf_streams: [{client_id: c, poll: true, receiver_token: {env: T}}]",
		"a source for nobody":           "ssf_sources: [{issuer: 'https://i.test', name: n, jwks_uri: 'https://i.test/k', events: [e]}]",
		"a model that will not compile": "authorization_model: \"types: [nope]\"",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
