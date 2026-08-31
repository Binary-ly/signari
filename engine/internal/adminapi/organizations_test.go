package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tenant provisioning, and the boundary that makes it safe.
//
// # The escalation this prevents
//
// Creating an organisation is the one write with no organisation to be scoped
// to. If a token scoped to one tenant could do it, that tenant could create a
// sibling — and then act on the sibling with a token issued for it. The
// isolation the rest of the product enforces by GRANT, by RLS and by
// `requireOrg` would have a door in it, reachable by the ordinary API.
//
// The handler calls `requireOrg(ctx, "")`, which already means exactly "only an
// unscoped token": `MayActOn` returns nil for an unscoped principal and refuses
// a scoped one that has not named its organisation. These tests hold that
// property from the outside, against the router, rather than by re-asserting
// what `MayActOn` does — because the question is whether the handler CALLS it.

func TestCreatingAnOrganisationRequiresAnUnscopedToken(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	// A principal scoped to one organisation, injected the way auth() would.
	scoped := &Principal{OrgID: anyOrgID(t, s), Scopes: []string{ScopeOrganizationsWrite}}

	body := fmt.Sprintf(`{"slug":"escalate-%d","display_name":"Escalation","instance_id":%q}`,
		time.Now().UnixNano(), anyInstanceID(t, s))
	r := httptest.NewRequest(http.MethodPost, "/admin/organizations",
		strings.NewReader(body)).WithContext(withPrincipal(ctx, scoped))
	r.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.createOrganization(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("an organisation-scoped token created a tenant: %d %s. A "+
			"tenant that can provision tenants has escaped the isolation "+
			"boundary the whole product rests on.", rec.Code, rec.Body.String())
	}
}

func TestAnUnscopedTokenCreatesAnOrganisation(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	slug := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPost, "/admin/organizations",
		fmt.Sprintf(`{"slug":%q,"display_name":"A Tenant","instance_id":%q}`,
			slug, anyInstanceID(t, s)), ""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("gave %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		ID            string `json:"id"`
		Slug          string `json:"slug"`
		ConfigVersion int    `json:"config_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Slug != slug || body.ID == "" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if body.ConfigVersion == 0 {
		t.Error("the mutation did not bump the configuration version")
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.organizations WHERE id = $1::uuid`, body.ID)
	})

	// The audit event is filed under the NEW organisation, so the tenant has a
	// record of its own beginning rather than the record living wherever the
	// caller happened to be pointed.
	var n int
	if err := s.db.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type = 'admin.organization_created'`,
		body.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("found %d creation events for the new organisation, want 1", n)
	}
}

// A slug that would need escaping somewhere downstream is refused up front.
//
// `Upper` is in the list on purpose. Case is REFUSED rather than folded: the
// uniqueness index is on the raw slug, so folding would be the only thing
// keeping "Upper" and "upper" from being two organisations nobody can tell apart
// in a URL — and folding has its own cost, since a caller who sends "Upper" then
// holds an identifier the deployment does not have. Refusing avoids both.
//
// A path-traversal slug is included because a slug reaches URLs; one that
// survived validation would be the kind of value that turns up in somebody
// else's path handling later.
func TestAnUnusableSlugIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	instance := anyInstanceID(t, s)

	for _, slug := range []string{
		"", "-leading", "trailing-", "Upper", "has space", "has/slash",
		"has.dot", "../escape", "under_score",
	} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPost, "/admin/organizations",
			fmt.Sprintf(`{"slug":%q,"display_name":"X","instance_id":%q}`, slug, instance), ""))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("slug %q gave %d, want 400: %s", slug, rec.Code, rec.Body.String())
		}
	}
}

// The pattern must not be so strict that ordinary slugs are refused.
//
// The other half of the test above: a validator that rejected everything would
// satisfy it completely.
func TestAnOrdinarySlugIsAccepted(t *testing.T) {
	s, _ := newTestServer(t)
	instance := anyInstanceID(t, s)
	stamp := time.Now().UnixNano()

	for i, slug := range []string{
		fmt.Sprintf("a%d", stamp),          // short, starts with a letter
		fmt.Sprintf("acme-corp-%d", stamp), // hyphenated
		fmt.Sprintf("%d", stamp),           // all digits
	} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPost, "/admin/organizations",
			fmt.Sprintf(`{"slug":%q,"display_name":"X","instance_id":%q}`, slug, instance), ""))
		if rec.Code != http.StatusCreated {
			t.Errorf("case %d: slug %q was refused (%d): %s. The pattern is too "+
				"strict.", i, slug, rec.Code, rec.Body.String())
			continue
		}
		var body struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		id := body.ID
		t.Cleanup(func() {
			_, _ = s.db.Exec(context.Background(),
				`DELETE FROM core.organizations WHERE id = $1::uuid`, id)
		})
	}
}

// The same slug twice on one instance is a 409, not a 500.
func TestADuplicateSlugConflicts(t *testing.T) {
	s, _ := newTestServer(t)
	slug := fmt.Sprintf("dup-%d", time.Now().UnixNano())
	instance := anyInstanceID(t, s)
	payload := fmt.Sprintf(`{"slug":%q,"display_name":"X","instance_id":%q}`, slug, instance)

	var created string
	for i, want := range []int{http.StatusCreated, http.StatusConflict} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPost, "/admin/organizations", payload, ""))
		if rec.Code != want {
			t.Fatalf("attempt %d gave %d, want %d: %s", i+1, rec.Code, want, rec.Body.String())
		}
		if i == 0 {
			var body struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			created = body.ID
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.organizations WHERE id = $1::uuid`, created)
	})
}

// An instance that does not exist is the caller's error, not a server fault.
func TestAnUnknownInstanceIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPost, "/admin/organizations",
		fmt.Sprintf(`{"slug":"orphan-%d","display_name":"X",`+
			`"instance_id":"00000000-0000-0000-0000-000000000000"}`,
			time.Now().UnixNano()), ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("gave %d, want 400: %s", rec.Code, rec.Body.String())
	}
}
