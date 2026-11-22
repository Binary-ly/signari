package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A client's token lifetimes are set by `apply`, read from the file as Go
// durations, left alone when omitted, and refused by `plan` when out of
// bounds (2.23).
func TestApplySetsTokenLifetimes(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := fmt.Sprintf("cfg-lifetimes-%d", time.Now().UnixNano())
	parse := func(lines string) *File {
		t.Helper()
		f, err := Parse([]byte("version: 1\nclients:\n  - client_id: " + id +
			"\n    redirect_uris: [https://app.test/cb]\n" + lines))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	apply := func(f *File) *Plan {
		t.Helper()
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}

	apply(parse("    access_token_ttl: 10m\n    refresh_token_ttl: 168h\n"))
	if got, err := store.ClientSettingsOf(ctx, tx, id); err != nil ||
		got.AccessTokenTTL != 10*time.Minute || got.RefreshTokenTTL != 168*time.Hour {
		t.Fatalf("after apply: %v / %v (%v)", got.AccessTokenTTL, got.RefreshTokenTTL, err)
	}
	if plan := apply(parse("")); !plan.Empty() {
		t.Errorf("a file naming neither planned %+v", plan.Changes)
	}
	if got, _ := store.ClientSettingsOf(ctx, tx, id); got.AccessTokenTTL != 10*time.Minute {
		t.Errorf("an omitted lifetime changed to %v", got.AccessTokenTTL)
	}
	if plan := apply(parse("    access_token_ttl: 15m\n")); plan.Empty() ||
		!strings.Contains(fmt.Sprint(plan.Changes), "access_token_ttl") {
		t.Errorf("a changed lifetime planned %+v", plan.Changes)
	}

	f, err := Parse([]byte("version: 1\nclients:\n  - client_id: x\n    redirect_uris: [https://app.test/cb]\n" +
		"    access_token_ttl: 2h\n"))
	if err == nil {
		err = f.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "access token lifetime") {
		t.Errorf("a two-hour access lifetime was not refused before applying: %v", err)
	}
}
