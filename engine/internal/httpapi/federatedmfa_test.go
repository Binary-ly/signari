package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/store"
)

// An upstream's multi-factor authentication satisfies an `mfa` stage when the
// operator trusts the value it is asserted with, and only then (2.13). A
// federated sign-in recorded amr `fed` alone, so under an unconditional `mfa`
// stage everybody arriving through a provider with no factor enrolled here was
// refused, however strongly the provider had authenticated them.
func TestAnUpstreamsTrustedMFASatisfiesTheMFAStage(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	f.applyFlow(t, `
version: 1
flows:
  - name: mfa-for-everyone
    on: authentication
    stages:
      # A provider is a way in of its own: a sign-in's proving stage must be
      # the proof presented (2.49), so a flow naming only password refuses it.
      - one_of:
          - {stage: federated, when: proved_by_federated}
          - {stage: password}
      - mfa
      - session
    tests:
      - name: always challenged
        given: {}
        expect: [password, mfa, session]
      - name: through a provider
        given: {proved_by_federated: true}
        expect: [federated, mfa, session]
`)

	var providerID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, allow_linking)
		VALUES ($1::uuid, 'up-' || substr(gen_random_uuid()::text, 1, 8), 'Upstream', 'oidc', 'signari', true)
		RETURNING id::text`, f.orgID).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
	})
	ext := federation.ExternalIdentity{Subject: "upstream-" + f.userID}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LinkFederatedIdentity(ctx, tx, providerID, f.userID, f.orgID, ext, true); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	signIn := func(trustAMR, trustACR []string, amr []string, acr string) []string {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"sub": ext.Subject, "amr": amr, "acr": acr})
		ext.RawClaims = raw
		cfg := federation.Config{ID: providerID, OrgID: f.orgID, Slug: "upstream", Kind: federation.KindOIDC,
			Policy: federation.Policy{AllowLinking: true}, MFAAMR: trustAMR, MFAACR: trustACR}
		before := f.sessionRows(t)
		rec := httptest.NewRecorder()
		f.srv.completeFederation(rec, httptest.NewRequest(http.MethodGet, "/login/callback", nil),
			&cfg, &store.PendingLogin{ProviderID: providerID, OrgID: f.orgID}, ext)
		if f.sessionRows(t) == before {
			return nil
		}
		var got []string
		if err := f.pool.QueryRow(ctx, `SELECT amr FROM core.sessions WHERE user_id = $1::uuid
			ORDER BY created_at DESC LIMIT 1`, f.userID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	if amr := signIn(nil, nil, []string{"pwd", "mfa"}, ""); amr != nil {
		t.Errorf("with nothing trusted, an upstream claiming mfa signed in as %v under an mfa stage", amr)
	}
	if amr := signIn([]string{"mfa"}, nil, []string{"pwd", "otp"}, ""); amr != nil {
		t.Errorf("an upstream amr with no trusted value signed in as %v", amr)
	}
	if amr := signIn([]string{"mfa"}, nil, []string{"pwd", "mfa"}, ""); !slices.Contains(amr, "mfa") || !slices.Contains(amr, "fed") {
		t.Errorf("a trusted upstream amr signed in as %v, want fed and mfa", amr)
	}
	const multi = "urn:example:loa:multi"
	if amr := signIn(nil, []string{multi}, []string{"pwd"}, multi); !slices.Contains(amr, "mfa") {
		t.Errorf("a trusted upstream acr signed in as %v, want mfa", amr)
	}
}
