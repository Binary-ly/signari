package config

import (
	"strings"
	"testing"
)

// A configuration file is applied by someone who did not write it, on a day
// something is already wrong. Every refusal below is one that would otherwise
// become a production incident, so each is checked with the message it gives.

func TestValidConfigParses(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
org: 11111111-1111-1111-1111-111111111111
groups:
  - name: platform
clients:
  - client_id: wiki
    name: Wiki
    redirect_uris: [https://wiki.example.com/cb]
saml_providers:
  - entity_id: urn:sp
    acs_urls: [https://sp.example.com/acs]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Clients) != 1 || f.Clients[0].ClientID != "wiki" {
		t.Errorf("clients did not parse: %+v", f.Clients)
	}
}

// A misspelled key is a line that does nothing, and silence is the worst
// possible answer to "I configured that and it had no effect".
func TestUnknownKeysAreRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
clients:
  - client_id: wiki
    redirect_uris: [https://wiki.example.com/cb]
    redirect_uris_typo: [https://elsewhere.example.com/cb]
`))
	if err == nil {
		t.Fatal("a misspelled key was silently ignored")
	}
}

func TestDangerousValuesAreRefused(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			"a wildcard redirect URI",
			"clients:\n  - client_id: a\n    redirect_uris: [\"https://*.example.com/cb\"]\n",
			"wildcard",
		},
		{
			"a plaintext redirect URI",
			"clients:\n  - client_id: a\n    redirect_uris: [http://app.example.com/cb]\n",
			"https",
		},
		{
			"a plaintext SAML ACS URL",
			"saml_providers:\n  - entity_id: urn:a\n    acs_urls: [http://sp.example.com/acs]\n",
			"https",
		},
		{
			// The one that puts a credential in everybody's git clone.
			"a RADIUS secret in the file",
			"radius_clients:\n  - name: ap\n    network: 10.0.0.0/8\n    secret: hunter2\n",
			"repository",
		},
		{
			"a client with no redirect URI",
			"clients:\n  - client_id: a\n",
			"redirect_uri",
		},
		{
			"a duplicated client",
			"clients:\n  - client_id: a\n    redirect_uris: [https://x.test/cb]\n" +
				"  - client_id: a\n    redirect_uris: [https://y.test/cb]\n",
			"twice",
		},
		{
			"an unknown NameID format",
			"saml_providers:\n  - entity_id: urn:a\n    acs_urls: [https://sp.test/acs]\n" +
				"    name_id_format: whatever\n",
			"name_id_format",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte("version: 1\n" + tc.yaml))
			if err == nil {
				t.Fatalf("accepted:\n%s", tc.yaml)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error should mention %q so somebody can act on it: %v",
					tc.want, err)
			}
		})
	}
}

// Every problem is reported at once. A file with three mistakes should not need
// three runs to find them, and a validation that stops at the first is how a
// twenty-line change takes an afternoon.
func TestAllProblemsAreReportedTogether(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
clients:
  - client_id: a
    redirect_uris: [http://a.test/cb]
  - client_id: b
    redirect_uris: ["https://*.b.test/cb"]
saml_providers:
  - entity_id: urn:c
    acs_urls: [http://c.test/acs]
`))
	if err == nil {
		t.Fatal("three separate problems were accepted")
	}
	if !strings.Contains(err.Error(), "3 problem(s)") {
		t.Errorf("all three should be reported at once: %v", err)
	}
}

// Nothing is applied when validation fails. Half-applied configuration looks
// like it worked and fails somewhere in the middle.
func TestFailedValidationSaysNothingChanged(t *testing.T) {
	_, err := Parse([]byte("version: 1\nclients:\n  - client_id: a\n"))
	if err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Errorf("the error must say nothing was changed: %v", err)
	}
}

func TestVersionIsRequired(t *testing.T) {
	if _, err := Parse([]byte("clients: []\n")); err == nil {
		t.Fatal("a file with no version was accepted")
	}
}

// Ordering within a list carries no meaning to the engine, and reporting it as
// a change is how a diff comes to be ignored.
func TestListOrderIsNotAChange(t *testing.T) {
	a := Client{ClientID: "x", RedirectURIs: []string{"https://a/cb", "https://b/cb"}}
	b := Client{ClientID: "x", RedirectURIs: []string{"https://b/cb", "https://a/cb"}}
	if d := clientDiff(a, b); d != "" {
		t.Errorf("reordering reported a change: %q", d)
	}
	c := Client{ClientID: "x", RedirectURIs: []string{"https://a/cb"}}
	if d := clientDiff(a, c); d == "" {
		t.Error("removing a redirect URI was not reported as a change")
	}
}

// The plan is ordered, so two runs can be compared.
func TestPlanIsDeterministicallyOrdered(t *testing.T) {
	p := &Plan{}
	p.Add(Change{Action: "delete", Kind: "client", Name: "z"})
	p.Add(Change{Action: "create", Kind: "group", Name: "b"})
	p.Add(Change{Action: "create", Kind: "client", Name: "a"})
	p.Add(Change{Action: "update", Kind: "client", Name: "m"})
	sortPlan(p)

	var got []string
	for _, c := range p.Changes {
		got = append(got, c.Action+":"+c.Name)
	}
	want := []string{"create:a", "create:b", "update:m", "delete:z"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plan order = %v, want %v (creates, then updates, then deletes)",
				got, want)
		}
	}
}

func TestDestructiveChangesAreSeparable(t *testing.T) {
	p := &Plan{}
	p.Add(Change{Action: "create", Kind: "client", Name: "a"})
	p.Add(Change{Action: "delete", Kind: "client", Name: "b", Destructive: true})
	if len(p.Destructive()) != 1 {
		t.Errorf("destructive changes must be separable so they can be shown first")
	}
}
