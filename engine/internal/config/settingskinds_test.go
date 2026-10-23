package config

import (
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// The settings an organisation has one of (6.25): dynamic registration turned
// off rather than deleted, a WebAuthn policy compared as stored so an AAGUID
// typed in capitals is not a change on every plan, UMA's intervention, and
// all three carried by an export to another organisation.
func TestTheOrganisationsSettingsAreDeclaredAndRoundTrip(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org := freshOrg(t, ctx, tx)
	plan := func(org, raw string, prune bool) (*File, *Plan) {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlan(ctx, tx, org, f, prune)
		if err != nil {
			t.Fatal(err)
		}
		return f, p
	}
	apply := func(org, raw string, prune bool) *Plan {
		t.Helper()
		f, p := plan(org, raw, prune)
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const settings = `registration: {max_clients: 5}
webauthn_policy: {attestation: direct, allowed_aaguids: [EE882879-721C-4913-9775-3DFCCE97072A], timeout_seconds: 120}
uma: {owner_intervention: true, poll_interval: 10s}
`
	apply(org, settings, false)
	reg, err := store.LoadRegistrationPolicy(ctx, tx, org)
	if err != nil || !reg.Enabled || reg.MaxClients != 5 || !sameSet(reg.AllowedScopes, store.DefaultRegistrationScopes) {
		t.Errorf("registration is %+v (%v)", reg, err)
	}
	wa, err := store.LoadWebAuthnPolicy(ctx, tx, org)
	if err != nil || wa.Conveyance != "direct" || len(wa.AllowedAAGUIDs) != 1 ||
		wa.AllowedAAGUIDs[0] != "ee882879-721c-4913-9775-3dfcce97072a" || wa.TimeoutSeconds != 120 || !wa.RefuseCloned {
		t.Errorf("the WebAuthn policy is %+v (%v)", wa, err)
	}
	if u, _ := store.LoadUMASettings(ctx, tx, org); !u.OwnerIntervention || u.PollInterval.Seconds() != 10 {
		t.Errorf("UMA is %+v", u)
	}
	if _, p := plan(org, settings, false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	other := freshOrg(t, ctx, tx)
	apply(other, strings.TrimPrefix(string(out), "version: 1\n"), false)
	if _, p := plan(other, strings.TrimPrefix(string(out), "version: 1\n"), false); !p.Empty() {
		t.Errorf("the export applied elsewhere plans\n%s", p)
	}

	// Off, registration keeps its policy and tokens for when it is on again.
	apply(org, "registration: {enabled: false}\n", false)
	if reg, _ := store.LoadRegistrationPolicy(ctx, tx, org); reg.Enabled || reg.MaxClients != 5 {
		t.Errorf("turned off, registration is %+v", reg)
	}
	if _, p := plan(org, "registration: {enabled: false}\n", false); !p.Empty() {
		t.Errorf("off again it plans\n%s", p)
	}

	// Pruned: registration turned off, the policy back to the defaults (which
	// admits any model, so the plan says so), UMA's refusals final again.
	p := apply(other, "", true)
	for _, want := range []string{registrationOff, "any model admitted", "a refused request is final again"} {
		if !strings.Contains(p.String(), want) {
			t.Errorf("the pruned plan does not say %q:\n%s", want, p)
		}
	}
	if wa, _ := store.LoadWebAuthnPolicy(ctx, tx, other); !samePolicy(wa, store.DefaultWebAuthnPolicy()) {
		t.Errorf("pruned, the policy is %+v", wa)
	}
	if _, p := plan(other, "", true); !p.Empty() {
		t.Errorf("pruned again it plans\n%s", p)
	}

	for name, raw := range map[string]string{
		"an allow-list nothing vouches for": "webauthn_policy: {allowed_aaguids: [ee882879-721c-4913-9775-3dfcce97072a]}",
		"an algorithm nobody offers":        "webauthn_policy: {algorithms: [999]}",
		"a ceremony too short":              "webauthn_policy: {timeout_seconds: 10}",
		"polling every second":              "uma: {owner_intervention: true, poll_interval: 1s}",
		"a negative ceiling":                "registration: {max_clients: -1}",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
