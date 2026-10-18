package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/txntoken"
	"signari.dev/engine/internal/uma"
)

// The grants that issue a token for a person with no sign-in in front of it
// ask the access policy, as /authorize does before a code exists. Each was
// found by TestEveryIssuingPathAsksTheAccessPolicy issuing with no check, so
// an operator's deny rule on a client held at its sign-in page and nowhere a
// token could be had without one.
//
// Each case is refused under a rule denying the client and served once the
// rule is lifted, so the refusal is the policy's and nothing else's.

func refusedByPolicy(t *testing.T, status int, body map[string]any) {
	t.Helper()
	desc, _ := body["error_description"].(string)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" ||
		!strings.Contains(desc, "access policy") {
		t.Fatalf("under a rule denying the client: %d %v, want invalid_grant from the access policy",
			status, body)
	}
}

func TestAnExchangeIsRefusedWhenThePolicyDeniesTheClient(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	subject := f.subjectTokenWithDetails(t, "verifier-exchange-policy-aaaaaaaaaaaaaaaaaaa", nil)
	exchange := func() (int, map[string]any) {
		return f.post(t, url.Values{
			"grant_type":         {oauth.GrantTypeTokenExchange},
			"client_secret":      {f.exchangeSecret},
			"subject_token":      {subject},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"audience":           {exchangeAudience},
			"client_id":          {f.clientID},
		})
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	status, body := exchange()
	refusedByPolicy(t, status, body)

	removePolicy(t, f.srv, f.pool, f.orgID)
	if status, body := exchange(); status != http.StatusOK {
		t.Fatalf("with the rule lifted the exchange gave %d %v", status, body)
	}
}

func TestAJWTBearerGrantIsRefusedWhenThePolicyDeniesTheClient(t *testing.T) {
	f := newAssertionFixture(t)
	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	status, body := f.grant(t, f.assert(t, nil), nil)
	refusedByPolicy(t, status, body)

	removePolicy(t, f.srv, f.pool, f.orgID)
	if status, body := f.grant(t, f.assert(t, nil), nil); status != http.StatusOK {
		t.Fatalf("with the rule lifted the grant gave %d %v", status, body)
	}
}

// Who, not where, as for a refresh: a rule admitting the client only from an
// office network judges the person's browser at sign-in, and a grant comes
// from a server whose address says nothing about the person.
func TestANetworkRuleDoesNotJudgeTheServerMakingAGrant(t *testing.T) {
	f := newAssertionFixture(t)
	applyPolicy(t, f.srv, f.pool, f.orgID, fmt.Sprintf(`
version: 1
policies:
  - name: office-only
    when: {client: %q}
    require: {from_networks: ["10.9.9.0/24"]}
    message: "Only from the office."
tests:
  - name: office
    given: {client: %q, ip: "10.9.9.5"}
    expect: allow
  - name: elsewhere
    given: {client: %q, ip: "192.0.2.1"}
    expect: deny
`, f.clientID, f.clientID, f.clientID))
	if status, body := f.grant(t, f.assert(t, nil), nil); status != http.StatusOK {
		t.Fatalf("a network rule refused the grant by the calling server's address: %d %v",
			status, body)
	}
}

// A refusal does not spend the offer: lifting the rule lets the same code in.
func TestAPreAuthorizedCodeIsRefusedWhenThePolicyDeniesTheClient(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", 5*time.Minute)

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	status, body := f.post(t, preAuthForm(code, ""))
	refusedByPolicy(t, status, body)

	removePolicy(t, f.srv, f.pool, f.orgID)
	if status, body := f.post(t, preAuthForm(code, "")); status != http.StatusOK {
		t.Fatalf("with the rule lifted the same offer gave %d %v", status, body)
	}
}

// A person outside the client's organisation is refused before any policy is
// read, which is what stops a token audienced here from another tenant being
// exchanged into one issued under this tenant.
func TestAGrantNamingAPersonFromAnotherOrganisationIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	elsewhere := "00000000-0000-4000-8000-000000000001"
	if !f.srv.grantRefusedByPolicy(rec, r, elsewhere, f.clientID, f.userID, "", "", "test") {
		t.Fatal("a person from another organisation passed")
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("refusal = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if f.srv.grantRefusedByPolicy(rec, r, f.orgID, f.clientID, f.userID, "", "", "test") {
		t.Fatalf("the person's own organisation was refused: %s", rec.Body.String())
	}
}

// A transaction token names its subject to the asking workload, on the first
// hop and on every replacement, so the policy is asked about both. Neither was.
func TestATransactionTokenIsRefusedWhenThePolicyDeniesTheWorkload(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	subject := f.mintAccessTokenWithScope(t, []string{"read"})
	const accessToken = "urn:ietf:params:oauth:token-type:access_token"

	// A first hop before the rule, to replace once it is in force.
	status, body := f.txnToken(t, subject, accessToken, "read")
	if status != http.StatusOK {
		t.Fatalf("the first hop gave %d: %v", status, body)
	}
	first, _ := body["access_token"].(string)

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	status, body = f.txnToken(t, subject, accessToken, "read")
	refusedByPolicy(t, status, body)
	status, body = f.txnToken(t, first, txntoken.TokenType, "read")
	refusedByPolicy(t, status, body)

	removePolicy(t, f.srv, f.pool, f.orgID)
	if status, body := f.txnToken(t, subject, accessToken, "read"); status != http.StatusOK {
		t.Fatalf("with the rule lifted the first hop gave %d %v", status, body)
	}
}

// Once a person is identified the RPT names them, so the policy is asked about
// them; an unidentified request is the client asking for itself and is not.
func TestAnRPTForAPersonIsRefusedWhenThePolicyDeniesTheClient(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	idToken := f.idTokenFor(t, f.userID, f.clientID, time.Hour)
	ask := func() (int, map[string]any) {
		_, pb := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := pb["ticket"].(string)
		return f.exchange(t, f.clientID, ticket, url.Values{
			"claim_token": {idToken}, "claim_token_format": {uma.ClaimTokenFormatIDToken},
		})
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	status, body := ask()
	refusedByPolicy(t, status, body)

	removePolicy(t, f.srv, f.pool, f.orgID)
	if status, body := ask(); status != http.StatusOK {
		t.Fatalf("with the rule lifted the RPT request gave %d %v", status, body)
	}
}
