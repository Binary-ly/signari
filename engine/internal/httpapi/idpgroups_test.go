package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/store"
)

// What a provider's groups grant here (8.14), through the sign-in that applies them.
func TestAProvidersGroupsGrantOnlyWhatIsMapped(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	slug := fmt.Sprintf("up-%d", stamp)
	name := func(group string) string { return fmt.Sprintf("%s-%d", group, stamp) }
	var providerID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, allow_linking)
		VALUES ($1::uuid, $2, 'Upstream', 'oidc', 'signari', true) RETURNING id::text`, f.orgID, slug).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"mapped", "handmade", "powerful"} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
			VALUES ($1::uuid, $2, 'Group', $3)`, f.orgID, name(group), group == "powerful"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.groups WHERE name LIKE '%-' || $1::text`, fmt.Sprint(stamp))
	})

	// A group that may impersonate is refused both ways round.
	if err := store.SetIdPGroupMap(ctx, f.pool, f.orgID, slug, "Admins", name("powerful")); !errors.Is(err, store.ErrIdPGroupImpersonates) {
		t.Errorf("mapping a group that may impersonate answered %v", err)
	}
	if err := store.SetIdPGroupMap(ctx, f.pool, f.orgID, slug, "Eng", name("mapped")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.groups SET may_impersonate = true WHERE org_id = $1::uuid AND name = $2`,
		f.orgID, name("mapped")); err == nil {
		t.Error("a group a provider grants was given impersonation")
	}
	if err := store.SetIdPGroupMap(ctx, f.pool, f.orgID, slug, "Eng", "no-such-group"); !errors.Is(err, store.ErrIdPGroupUnknown) {
		t.Errorf("mapping a group nobody has answered %v", err)
	}

	ext := federation.ExternalIdentity{Subject: "groups-" + f.userID}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LinkFederatedIdentity(ctx, tx, providerID, f.userID, f.orgID, ext, false); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT id, $2::uuid, org_id FROM core.groups WHERE org_id = $1::uuid AND name = $3`, f.orgID, f.userID, name("handmade")); err != nil {
		t.Fatal(err)
	}
	signIn := func(claims map[string]any) {
		t.Helper()
		raw, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		ext.RawClaims = raw
		cfg := federation.Config{ID: providerID, OrgID: f.orgID, Slug: slug, Kind: federation.KindOIDC,
			Policy: federation.Policy{AllowLinking: true}}
		rec := httptest.NewRecorder()
		f.srv.completeFederation(rec, httptest.NewRequest(http.MethodGet, "/login/callback", nil), &cfg,
			&store.PendingLogin{ProviderID: providerID, OrgID: f.orgID}, ext)
		if !strings.Contains(rec.Body.String(), "signed in") {
			t.Fatalf("the sign-in answered %d: %.200s", rec.Code, rec.Body.String())
		}
	}
	in := func(group string) bool {
		t.Helper()
		var member bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.group_members m JOIN core.groups g ON g.id = m.group_id
			WHERE m.user_id = $1::uuid AND g.org_id = $2::uuid AND g.name = $3)`, f.userID, f.orgID, name(group)).Scan(&member); err != nil {
			t.Fatal(err)
		}
		return member
	}

	signIn(map[string]any{"sub": ext.Subject, "groups": []string{"Eng", "Sales"}})
	if !in("mapped") {
		t.Error("a mapped group did not grant its local one")
	}
	if !in("handmade") {
		t.Error("a sign-in touched a group no mapping names")
	}
	var named int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.groups WHERE org_id = $1::uuid AND name = 'Sales'`, f.orgID).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Error("a remote name nobody mapped made a group")
	}

	// No claim says nothing: a provider leaves it out for reasons of its own.
	signIn(map[string]any{"sub": ext.Subject})
	if !in("mapped") {
		t.Error("a sign-in with no groups claim took somebody out of a group")
	}

	// Named as one string, as a provider with one to report may send it.
	signIn(map[string]any{"sub": ext.Subject, "groups": "Eng"})
	if !in("mapped") {
		t.Error("one group sent as a string took somebody out")
	}

	// Gone upstream, gone here, at the next sign-in.
	signIn(map[string]any{"sub": ext.Subject, "groups": []string{"Sales"}})
	if in("mapped") {
		t.Error("a group lost at the provider outlived the sign-in")
	}
	if !in("handmade") {
		t.Error("a sign-in took somebody out of a group no mapping names")
	}

	// Another claim, when the provider is told it is.
	claim := "roles"
	if err := store.ChangeIdentityProvider(ctx, f.pool, f.orgID, slug, store.IdentityProviderChange{GroupClaim: &claim}); err != nil {
		t.Fatal(err)
	}
	signIn(map[string]any{"sub": ext.Subject, "roles": []string{"Eng"}, "groups": []string{}})
	if !in("mapped") {
		t.Error("the configured claim was not read")
	}

	// Unmapping ends the governing and not the membership.
	if err := store.RemoveIdPGroupMap(ctx, f.pool, f.orgID, slug, "Eng", name("mapped")); err != nil {
		t.Fatal(err)
	}
	signIn(map[string]any{"sub": ext.Subject, "roles": []string{}})
	if !in("mapped") {
		t.Error("a provider took somebody out of a group it no longer governs")
	}
	if err := store.RemoveIdPGroupMap(ctx, f.pool, f.orgID, slug, "Eng", name("mapped")); !errors.Is(err, store.ErrIdPMappingUnknown) {
		t.Errorf("removing what is not mapped answered %v", err)
	}
}
