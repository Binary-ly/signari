package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/uma"
)

// UMA 2.0, end to end.
//
// The flow hands a stranger a ticket and later hands them a token for it, so the
// cases that matter are the refusals: a ticket presented twice, a ticket from
// another organisation, a permission policy does not allow.

// permission asks for a ticket as a resource server would.
func (f *cibaFixture) permission(t *testing.T, clientID, secret, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/uma2/permission", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if clientID != "" {
		req.SetBasicAuth(clientID, secret)
	}
	rec := httptest.NewRecorder()
	f.srv.handleUMAPermission(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// exchange presents a ticket at the token endpoint.
func (f *cibaFixture) exchange(t *testing.T, clientID, ticket string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {uma.GrantType}}
	if ticket != "" {
		form.Set("ticket", ticket)
	}
	for k, v := range extra {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	c, err := f.srv.lookupClient(context.Background(), clientID)
	if err != nil || c == nil {
		t.Fatalf("looking up %s: %v", clientID, err)
	}
	rec := httptest.NewRecorder()
	f.srv.handleUMAGrant(rec, req, c)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

const onePermission = `{"resource_type":"document","resource_id":"42","resource_scopes":["read"]}`

// allow makes the org's authorization model permit the fixture client.
func (f *cibaFixture) allowClientOn(t *testing.T, resourceType, resourceID, relation string) {
	t.Helper()
	model := `
types:
  ` + resourceType + `:
    relations:
      viewer: []
    permissions:
      read: [viewer]
tests:
  - name: a viewer may read
    subject: client:x
    action: read
    resource: ` + resourceType + `:1
    relations: [viewer]
    allow: true
`
	// Parsed and saved through the same path `signari authz model set` uses, so
	// the fixture cannot install a model the product would reject.
	//
	// t.Fatalf, never t.Skipf. The first version of this helper skipped when the
	// insert failed, and it did fail -- I had guessed the column names. Four of
	// the seven tests here reported SKIP and the package reported ok, which is
	// exactly how a suite goes quietly green while its most important cases never
	// run.
	m, err := authzen.ParseModel([]byte(model))
	if err != nil {
		t.Fatalf("the fixture's own authorization model does not parse: %v", err)
	}
	if err := store.SaveModel(context.Background(), f.pool, f.orgID, model, m, ""); err != nil {
		t.Fatalf("installing the authorization model: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'client', $2, $3, $4, $5)`,
		f.orgID, f.clientID, relation, resourceType, resourceID); err != nil {
		t.Fatalf("granting the relation: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.relations WHERE org_id = $1::uuid`, f.orgID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.authorization_models WHERE org_id = $1::uuid`, f.orgID)
	})
}

// TestAPermissionTicketBecomesAnRPTWhenPolicyAllows.
func TestAPermissionTicketBecomesAnRPTWhenPolicyAllows(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")

	code, body := f.permission(t, f.clientID, f.secret, onePermission)
	if code != http.StatusCreated {
		t.Fatalf("permission endpoint: %d %v (§3.2 says 201)", code, body)
	}
	ticket, _ := body["ticket"].(string)
	if ticket == "" {
		t.Fatalf("no ticket in %v", body)
	}

	code, body = f.exchange(t, f.clientID, ticket, nil)
	if code != http.StatusOK {
		t.Fatalf("exchanging the ticket: %d %v", code, body)
	}
	if body["access_token"] == nil {
		t.Error("no RPT in the response")
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer (§3.3.5)", body["token_type"])
	}
	// The RPT's scope names the resource, not merely the verb: a resource server
	// given a token whose scope said only `read` would have to trust that it was
	// read on the right thing.
	if s, _ := body["scope"].(string); !strings.Contains(s, "document:42#read") {
		t.Errorf("scope = %q, want it to name the resource and the scope", s)
	}
}

// TestAPermissionTicketIsSingleUse is §3.3.1's MUST.
//
// "Permission tickets MUST be single-use. This prevents susceptibility to a
// session fixation attack."
func TestAPermissionTicketIsSingleUse(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)

	if code, b := f.exchange(t, f.clientID, ticket, nil); code != http.StatusOK {
		t.Fatalf("first exchange: %d %v", code, b)
	}
	code, b := f.exchange(t, f.clientID, ticket, nil)
	if code == http.StatusOK {
		t.Fatal("a permission ticket was redeemed twice; §3.3.1 makes single use a " +
			"MUST because a reusable ticket is a session fixation primitive")
	}
	if b["error"] != "invalid_grant" {
		t.Errorf("error %v, want invalid_grant (§3.3.6)", b["error"])
	}
}

// TestARefusedRequestStillSpendsTheTicket.
//
// §3.3.1 invalidates on PRESENTATION, not on success. Otherwise a client can
// grind one ticket against policy until something changes underneath it.
func TestARefusedRequestStillSpendsTheTicket(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")

	// Ask for something policy does not allow.
	_, body := f.permission(t, f.clientID, f.secret,
		`{"resource_type":"document","resource_id":"99","resource_scopes":["read"]}`)
	ticket, _ := body["ticket"].(string)

	code, b := f.exchange(t, f.clientID, ticket, nil)
	if code != http.StatusForbidden {
		t.Fatalf("a refused permission answered %d %v; §3.3.6 assigns 403 to "+
			"request_denied", code, b)
	}
	if b["error"] != "request_denied" {
		t.Errorf("error %v, want request_denied", b["error"])
	}

	// And the ticket is gone.
	if _, b := f.exchange(t, f.clientID, ticket, nil); b["error"] != "invalid_grant" {
		t.Errorf("after a refusal the ticket answered %v; presentation invalidates, "+
			"whatever the outcome", b["error"])
	}
}

// TestThePermissionEndpointRequiresAnAuthenticatedResourceServer.
func TestThePermissionEndpointRequiresAnAuthenticatedResourceServer(t *testing.T) {
	f := newCIBAFixture(t)

	if code, _ := f.permission(t, "", "", onePermission); code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated permission request answered %d; the endpoint "+
			"mints a credential a stranger presents back here", code)
	}
	if code, _ := f.permission(t, f.clientID, "wrong-secret", onePermission); code != http.StatusUnauthorized {
		t.Errorf("a wrong secret answered %d, want 401", code)
	}
}

// TestMalformedPermissionRequestsAreRefused.
func TestMalformedPermissionRequestsAreRefused(t *testing.T) {
	f := newCIBAFixture(t)

	for _, c := range []struct{ name, body string }{
		{"empty", ``},
		{"not JSON", `{`},
		{"empty array", `[]`},
		{"no resource_id", `{"resource_type":"document","resource_scopes":["read"]}`},
		{"no resource_type", `{"resource_id":"42","resource_scopes":["read"]}`},
		{"no scopes", `{"resource_type":"document","resource_id":"42"}`},
		{"an empty scope", `{"resource_type":"document","resource_id":"42","resource_scopes":[""]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code, b := f.permission(t, f.clientID, f.secret, c.body); code == http.StatusCreated {
				t.Fatalf("accepted: %v", b)
			}
		})
	}
}

// TestUnsupportedUMAParametersAreRefusedRatherThanIgnored.
//
// A client that pushes claims and receives a token concludes the claims were
// weighed. They were not: this server answers from policy alone.
func TestUnsupportedUMAParametersAreRefusedRatherThanIgnored(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")

	for _, param := range []string{"claim_token", "pct", "rpt"} {
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)

		code, b := f.exchange(t, f.clientID, ticket, url.Values{param: {"x"}})
		if code == http.StatusOK {
			t.Errorf("%s was accepted and ignored; the client believes it was "+
				"considered", param)
		}
		if b["error"] != "invalid_request" {
			t.Errorf("%s: error %v, want invalid_request", param, b["error"])
		}
	}
}

// TestATicketFromAnotherOrganisationIsRefused.
func TestATicketFromAnotherOrganisationIsRefused(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()

	var otherOrg string
	if err := f.pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://other-' || gen_random_uuid() || '.test', 'O') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text,1,8), 'Other' FROM i
		RETURNING id::text`).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.uma_permission_tickets WHERE org_id = $1::uuid`, otherOrg)
	})

	ticket, err := uma.NewTicket()
	if err != nil {
		t.Fatal(err)
	}
	// Minted against the OTHER organisation, but naming this fixture's client as
	// the resource server is impossible (foreign key), so use the same client id
	// only if it exists there -- it does not, so the ticket is created with the
	// fixture's client under the other org id via a direct insert.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.uma_permission_tickets
			(org_id, resource_server, ticket_hash, permissions, expires_at)
		VALUES ($1::uuid, $2, $3, $4::jsonb, now() + interval '2 minutes')`,
		otherOrg, f.clientID, store.HashToken(ticket),
		`[{"resource_type":"document","resource_id":"42","resource_scopes":["read"]}]`); err != nil {
		t.Fatalf("planting a cross-organisation ticket: %v", err)
	}

	code, b := f.exchange(t, f.clientID, ticket, nil)
	if code == http.StatusOK {
		t.Fatal("a ticket minted in another organisation produced an RPT")
	}
	if b["error"] != "invalid_grant" {
		t.Errorf("error %v, want invalid_grant", b["error"])
	}
}

// TestAnExpiredTicketIsRefused.
func TestAnExpiredTicketIsRefused(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)

	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.uma_permission_tickets SET expires_at = now() - interval '1 second'
		WHERE ticket_hash = $1`, store.HashToken(ticket)); err != nil {
		t.Fatal(err)
	}
	if _, b := f.exchange(t, f.clientID, ticket, nil); b["error"] != "invalid_grant" {
		t.Errorf("an expired ticket answered %v, want invalid_grant", b["error"])
	}
	_ = time.Now
}

func TestAPermissionTicketSurvivesConcurrentRedemption(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")

	const racers = 8
	for round := 0; round < 5; round++ {
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)
		if ticket == "" {
			t.Fatalf("round %d: no ticket in %v", round, body)
		}

		var wg sync.WaitGroup
		codes := make([]int, racers)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start // release them together
				codes[i], _ = f.exchange(t, f.clientID, ticket, nil)
			}(i)
		}
		close(start)
		wg.Wait()

		won := 0
		for _, c := range codes {
			if c == http.StatusOK {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d of %d concurrent presentations of one ticket "+
				"received an RPT; exactly one may. §3.3.1 makes single use a MUST "+
				"because a reusable ticket is a session fixation primitive",
				round, won, racers)
		}
	}
}
