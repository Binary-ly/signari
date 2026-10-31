package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Every attribute a group can be given round-trips through a file (7.06): set,
// read back, and a second apply of the same file plans nothing. A field left out
// of the comparison would show as a change on every apply, or, worse, of the
// write, and a file would silently take a device's Session-Timeout away.
func TestRADIUSAttributesAreDeclaredAndComparedInAFile(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org := freshOrg(t, ctx, tx)
	group := fmt.Sprintf("net-%d", time.Now().UnixNano())

	apply := func(raw string) *Plan {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	file := fmt.Sprintf(`groups: [{name: %[1]s}]
radius_authorizations:
  - group: %[1]s
    vlan: 20
    session_timeout: 28800
    class: staff
    vendor_attributes:
      - {vendor: 9, type: 1, value: "shell:priv-lvl=15"}
`, group)
	apply(file)
	held, err := store.RADIUSAuthorizations(ctx, tx, org, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].SessionTimeout != 28800 || held[0].Class != "staff" ||
		len(held[0].Vendor) != 1 || held[0].Vendor[0].Value != "shell:priv-lvl=15" {
		t.Fatalf("read back %+v", held)
	}
	if p := apply(file); strings.Contains(p.String(), "radius_authorization") {
		t.Errorf("the same file again planned a change:\n%s", p)
	}
	if p := apply(strings.ReplaceAll(file, "28800", "3600")); !strings.Contains(p.String(), "session_timeout") {
		t.Errorf("a changed timeout planned:\n%s", p)
	}
	if p := apply(strings.ReplaceAll(file, "priv-lvl=15", "priv-lvl=1")); !strings.Contains(p.String(), "vendor_attributes") {
		t.Errorf("a changed vendor attribute planned:\n%s", p)
	}
}

func TestABadRADIUSAttributeIsRefusedBeforeAnything(t *testing.T) {
	for name, raw := range map[string]string{
		"a negative timeout": "radius_authorizations: [{group: a, session_timeout: -1}]",
		"a long class":       "radius_authorizations: [{group: a, class: " + strings.Repeat("x", 254) + "}]",
		"a vendor of nobody": "radius_authorizations: [{group: a, vendor_attributes: [{type: 1, value: x}]}]",
		"a type too large":   "radius_authorizations: [{group: a, vendor_attributes: [{vendor: 9, type: 300, value: x}]}]",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw)); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}
