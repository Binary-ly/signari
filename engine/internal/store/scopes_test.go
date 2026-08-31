package store

import (
	"fmt"
	"testing"
	"time"
)

// Scopes as declared objects.
//
// The point is not a new gate — a client already cannot request a scope it is
// not registered for. The point is that a scope stops being a word typed twice
// with nothing connecting the two places, where a typo is silent and fails in
// the direction that looks correct.

func TestAStandardScopeCannotBeRedeclared(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	for _, name := range StandardScopes {
		if err := DeclareScope(ctx, tx, orgID, Scope{Name: name}); err == nil {
			t.Errorf("declaring the standard scope %q was accepted. A row "+
				"redefining it would be a setting that changes nothing.", name)
		}
	}
}

func TestADeclaredScopeIsAdvertisedUnlessItOptsOut(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)
	stamp := time.Now().UnixNano()

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	shown := fmt.Sprintf("shown_%d", stamp)
	hidden := fmt.Sprintf("hidden_%d", stamp)
	must(t, DeclareScope(ctx, tx, orgID, Scope{Name: shown, Advertise: true}))
	must(t, DeclareScope(ctx, tx, orgID, Scope{Name: hidden, Advertise: false}))

	got := AdvertisedScopes(ctx, tx, orgID)

	var sawShown, sawHidden, sawOpenID bool
	for _, s := range got {
		switch s {
		case shown:
			sawShown = true
		case hidden:
			sawHidden = true
		case "openid":
			sawOpenID = true
		}
	}
	if !sawOpenID {
		t.Error("the standard scopes are missing from the advertised set")
	}
	if !sawShown {
		t.Error("a declared, advertised scope is not advertised")
	}
	if sawHidden {
		t.Error("a scope that opted out of advertising is advertised. Every " +
			"advertised scope is a hint about what this deployment holds.")
	}
}

// Discovery still answers when the catalogue cannot be read.
func TestAdvertisedScopesFallsBackToTheStandardSet(t *testing.T) {
	ctx, _, _ := profileFixture(t)
	conn := connect(t)

	got := AdvertisedScopes(ctx, conn, "")
	if len(got) != len(StandardScopes) {
		t.Fatalf("with no organisation, advertised = %v; discovery must not "+
			"become unanswerable because an optional catalogue is absent", got)
	}
}

// An undeclared, non-standard scope is reported at registration time.
func TestUndeclaredScopesAreReported(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)
	stamp := time.Now().UnixNano()

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	declared := fmt.Sprintf("known_%d", stamp)
	must(t, DeclareScope(ctx, tx, orgID, Scope{Name: declared, Advertise: true}))

	got, err := UndeclaredScopes(ctx, tx, orgID,
		[]string{"openid", "email", declared, "hr_recrods"})
	must(t, err)
	if len(got) != 1 || got[0] != "hr_recrods" {
		t.Fatalf("undeclared = %v, want just the typo. Standard scopes and "+
			"declared ones must not be reported.", got)
	}
}

// A consent screen is told about every requested scope, declared or not.
func TestDescribeScopesCoversEveryRequestedScope(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)
	stamp := time.Now().UnixNano()

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("records_%d", stamp)
	must(t, DeclareScope(ctx, tx, orgID, Scope{
		Name: name, Description: "See your records.", Advertise: true,
	}))

	got := DescribeScopes(ctx, tx, orgID, []string{name, "openid", "mystery"})
	if len(got) != 3 {
		t.Fatalf("described %d of 3 requested scopes. A consent screen that "+
			"omits one shows a person less than they are agreeing to.", len(got))
	}
	if got[name].Description != "See your records." {
		t.Errorf("declared description missing: %+v", got[name])
	}
	if _, ok := got["mystery"]; !ok {
		t.Error("an undeclared requested scope was dropped from the consent set")
	}
}
