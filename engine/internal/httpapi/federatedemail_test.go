package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/store"
)

// An address a provider vouches for is verified here (2.46). `verified` reached the
// writer and stopped there, so everybody who arrived through a provider was told to
// applications as `email_verified: false`, however sure the provider was.
func TestAnAddressAProviderVouchesForIsVerifiedHere(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	var providerID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, allow_linking, allow_signup)
		VALUES ($1::uuid, 'up-' || substr(gen_random_uuid()::text, 1, 8), 'Upstream', 'oidc', 'signari', true, true)
		RETURNING id::text`, f.orgID).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UnixNano()
	address := func(name string) string { return fmt.Sprintf("%s-%d@example.test", name, n) }
	vouched, unsure, untrusted := address("vouched"), address("unsure"), address("untrusted")
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.users WHERE email = ANY($1)`, []string{vouched, unsure, untrusted})
	})

	signIn := func(trust bool, subject, email string, claimed bool) {
		t.Helper()
		cfg := federation.Config{ID: providerID, OrgID: f.orgID, Slug: "upstream", Kind: federation.KindOIDC,
			Policy: federation.Policy{AllowSignup: true, AllowLinking: true, TrustsEmailVerification: trust}}
		rec := httptest.NewRecorder()
		f.srv.completeFederation(rec, httptest.NewRequest(http.MethodGet, "/login/callback", nil), &cfg,
			&store.PendingLogin{ProviderID: providerID, OrgID: f.orgID},
			federation.ExternalIdentity{Subject: subject, Email: email, EmailVerified: claimed})
		if !strings.Contains(rec.Body.String(), "signed in") {
			t.Fatalf("%s did not sign in: %d %.200s", subject, rec.Code, rec.Body.String())
		}
	}
	verified := func(email string) bool {
		t.Helper()
		var is bool
		if err := f.pool.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM core.users WHERE email = $1`,
			email).Scan(&is); err != nil {
			t.Fatalf("%s: %v", email, err)
		}
		return is
	}

	signIn(true, "new-vouched", vouched, true)
	if !verified(vouched) {
		t.Error("a new person the provider vouched for is not verified")
	}
	signIn(true, "new-unsure", unsure, false)
	if verified(unsure) {
		t.Error("a new person the provider did not vouch for is verified")
	}
	signIn(false, "new-untrusted", untrusted, true)
	if verified(untrusted) {
		t.Error("a provider trusted for nothing verified an address")
	}

	// Someone who has an account, signing in again.
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET email_verified_at = NULL WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'linked')`, providerID, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	signIn(true, "linked", address("elsewhere"), true)
	if verified(f.email) {
		t.Error("a provider vouching for another address verified the one this account holds")
	}
	signIn(true, "linked", f.email, false)
	if verified(f.email) {
		t.Error("an address the provider did not vouch for was verified")
	}
	signIn(true, "linked", f.email, true)
	if !verified(f.email) {
		t.Error("the provider vouched for the address this account holds, and it is not verified")
	}
}
