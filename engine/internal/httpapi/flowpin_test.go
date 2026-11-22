package httpapi

import (
	"context"
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

// A flow pinned to a provider (8.22), through the real ways in.
func TestAFlowPinnedToAProviderIsHeldToIt(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	corp, other := fmt.Sprintf("corp-%d", stamp), fmt.Sprintf("other-%d", stamp)
	ids := map[string]string{}
	for _, slug := range []string{corp, other} {
		var id string
		if err := f.pool.QueryRow(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id,
			authorize_url, allow_linking) VALUES ($1::uuid, $2, 'Upstream', 'oidc', 'signari', 'https://idp.test/authorize', true)
			RETURNING id::text`, f.orgID, slug).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[slug] = id
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = ANY($1)`, []string{corp, other})
	})

	pinned := func(stages string) string {
		return fmt.Sprintf(`
version: 1
flows:
  - name: pinned
    on: authentication
    stages:
%s
      - session
    tests:
      - name: walks
        given: {proved_by_federated: true}
        expect: [federated, session]
`, stages)
	}
	only := pinned("      - {stage: federated, provider: " + corp + "}")
	f.applyFlow(t, only)

	// Nobody signed in goes straight there, whatever a hint would have said.
	rec := f.authorizeWith(t, "", nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login/with/"+corp) {
		t.Fatalf("a request with one way in answered %d %q", rec.Code, rec.Header().Get("Location"))
	}

	signIn := func(slug string) *httptest.ResponseRecorder {
		t.Helper()
		ext := federation.ExternalIdentity{Subject: "pinned-" + f.userID}
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.LinkFederatedIdentity(ctx, tx, ids[slug], f.userID, f.orgID, ext, false); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		cfg := federation.Config{ID: ids[slug], OrgID: f.orgID, Slug: slug, Kind: federation.KindOIDC,
			Policy: federation.Policy{AllowLinking: true}}
		out := httptest.NewRecorder()
		f.srv.completeFederation(out, httptest.NewRequest(http.MethodGet, "/login/callback", nil), &cfg,
			&store.PendingLogin{ProviderID: ids[slug], OrgID: f.orgID}, ext)
		return out
	}
	if rec := signIn(other); strings.Contains(rec.Body.String(), "signed in") {
		t.Errorf("a provider the flow does not name signed somebody in: %.200s", rec.Body.String())
	}
	if rec := signIn(corp); !strings.Contains(rec.Body.String(), "signed in") {
		t.Errorf("the pinned provider did not sign somebody in: %d %.200s", rec.Code, rec.Body.String())
	}

	// With another way in the page has something to offer, and is shown.
	f.applyFlow(t, pinned("      - one_of:\n          - {stage: federated, provider: "+corp+
		", when: proved_by_federated}\n          - {stage: password}"))
	if rec := f.authorizeWith(t, "", nil); rec.Code != http.StatusOK || !parkedAuthz.MatchString(rec.Body.String()) {
		t.Errorf("with a password besides answered %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// A pin on a provider gone or switched off shows the page, not a redirect to nothing.
	f.applyFlow(t, only)
	if _, err := f.pool.Exec(ctx, `UPDATE core.identity_providers SET enabled = false WHERE slug = $1`, corp); err != nil {
		t.Fatal(err)
	}
	if rec := f.authorizeWith(t, "", nil); strings.Contains(rec.Header().Get("Location"), "/login/with/") {
		t.Errorf("a disabled provider was sent to: %q", rec.Header().Get("Location"))
	}

	// And it is refused when applied, as it would refuse everybody who signs in.
	if _, err := store.ApplySignInFlow(ctx, f.pool, f.orgID, []byte(only)); !errors.Is(err, store.ErrInvalidDocument) {
		t.Errorf("a flow pinning a disabled provider applied: %v", err)
	}
}
