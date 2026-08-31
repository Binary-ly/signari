package store

import (
	"testing"

	"signari.dev/engine/internal/provider"
)

// What a token provider may contribute, and what it may never.
//
// The bound is the whole reason this extension point is safe to offer. A
// provider that could set `sub` would issue tokens impersonating any subject at
// every relying party trusting this issuer; one that could set `scope` would
// grant itself access. Neither is a hypothetical failure of an external
// service — it is what the extension point would BE if the bound were missing.

func TestAProviderMayContributeOnlyWhatWasAllowed(t *testing.T) {
	p := &provider.Provider{AllowedClaims: []string{"department", "cost_centre"}}

	for _, allowed := range []string{"department", "cost_centre"} {
		if !p.MayContribute(allowed) {
			t.Errorf("%q was listed and refused", allowed)
		}
	}
	for _, denied := range []string{"clearance", "groups", "anything_else"} {
		if p.MayContribute(denied) {
			t.Errorf("%q was not listed and was permitted", denied)
		}
	}
}

// A protocol claim is refused even when an operator lists it.
//
// Two checks rather than one: the database constraint stops the configuration
// being written, and this stops a row that predates the constraint or one
// written by some future path that forgot it.
func TestAProviderCanNeverContributeAProtocolClaim(t *testing.T) {
	// An operator who somehow got these into the column.
	p := &provider.Provider{AllowedClaims: []string{
		"sub", "iss", "aud", "exp", "acr", "amr", "scope", "cnf", "client_id",
	}}
	for _, claim := range p.AllowedClaims {
		if p.MayContribute(claim) {
			t.Errorf("a provider was permitted to set the protocol claim %q. "+
				"Setting `sub` alone would let an external service issue tokens "+
				"impersonating any subject at every relying party.", claim)
		}
	}
}

// An empty list means veto-only, which is a legitimate configuration.
func TestAProviderWithNoAllowedClaimsContributesNothing(t *testing.T) {
	p := &provider.Provider{}
	if p.MayContribute("anything") {
		t.Fatal("a provider with no allow-list contributed a claim")
	}
}

// The token_issue hook is declared as actually called.
//
// `Hook.Called()` exists because this codebase has shipped a configurable thing
// that governed nothing. Wiring a hook and leaving the predicate false would be
// the same bug pointed the other way: an operator told their provider is not
// consulted when it is.
func TestTheTokenHookIsDeclaredCalled(t *testing.T) {
	if !provider.HookTokenIssue.Called() {
		t.Fatal("HookTokenIssue is wired and Called() says it is not")
	}
	if !provider.HookTokenIssue.Known() {
		t.Fatal("HookTokenIssue is not in the known set")
	}
}

// The database refuses a protocol claim in the allow-list.
func TestTheSchemaRefusesAProtocolClaimInTheAllowList(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms, allowed_claims)
		VALUES ($1::uuid, 'p', 'token_issue', 'https://p.test/hook', 'fail_closed', 500,
		        ARRAY['department','sub'])`, orgID)
	if err == nil {
		t.Fatal("a provider registration listing `sub` was accepted. An operator " +
			"would find out never, because the claim would be silently dropped " +
			"at every mint while the configuration read as working.")
	}
}
