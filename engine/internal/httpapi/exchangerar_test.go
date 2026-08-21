package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/rar"
)

// RFC 8693 exchange must not launder away an RFC 9396 constraint.
//
// Scope was narrowed on exchange and authorization_details were dropped, which
// made exchange the widest hole in the product: a token constrained to "initiate
// this one payment" exchanged into one carrying `scope=payments` and no details
// at all. A resource server with no details left has only the scope to enforce,
// so a single-transaction grant became a standing capability -- and exchange
// exists precisely to hand that token to another party.
//
// The defect is the same class as the refresh ones: a property established at
// authorization, not carried across a derivation that happens later.

const exchangeAudience = "https://downstream.example/api"

func (f *tokenFixture) enableExchange(t *testing.T) {
	t.Helper()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients
		    SET may_exchange = true, exchange_audiences = $2,
		        client_type = 'confidential', client_secret_hash = $3
		  WHERE client_id = $1`,
		f.clientID, []string{exchangeAudience}, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret
}

// subjectTokenWithDetails runs a real authorization-code redemption so the
// subject token is one this server actually issued, details and all.
func (f *tokenFixture) subjectTokenWithDetails(t *testing.T, verifier string,
	details []rar.Detail) string {

	t.Helper()
	code := f.issueCodeWithDetails(t, verifier, details)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}
	// enableExchange makes the fixture confidential, because token exchange is
	// not available to a public client. That applies to THIS redemption too, so
	// the secret is presented whenever one exists — otherwise the order in which
	// a test calls enableExchange decides whether its subject token can be
	// obtained at all.
	if f.exchangeSecret != "" {
		form.Set("client_secret", f.exchangeSecret)
	}
	status, body := f.post(t, form)
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	return body["access_token"].(string)
}

func TestExchangeCarriesTheSubjectTokensAuthorizationDetails(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier", "locations"}, []string{"actions"})

	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-42",
	}}
	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-rar-aaaaaaaaaaaaaaaaaaaaaa", granted)

	status, body := f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("exchange gave %d: %v", status, body)
	}

	got := detailsInAccessToken(t, body["access_token"].(string))
	if len(got) != 1 || got[0].Identifier != "acct-42" {
		t.Fatalf("the exchanged token carries %+v; the constraint was dropped and "+
			"a single-transaction grant became whatever `scope` permits", got)
	}
}

// And the caller may ask for LESS, never more.
func TestExchangeRefusesDetailsWiderThanTheSubjectTokenCarried(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier", "locations"}, []string{"actions"})

	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-42",
	}}
	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-rar-bbbbbbbbbbbbbbbbbbbbbb", granted)

	// `cancel` was never granted to the subject token.
	status, body := f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
		"authorization_details": {`[{"type":"payment_initiation",` +
			`"actions":["initiate","cancel"],"identifier":"acct-42"}]`},
	})
	if status == http.StatusOK {
		t.Fatalf("the exchange granted an action the subject token never had: %v", body)
	}
	if body["error"] != rar.ErrorCode {
		t.Fatalf("refused with %v, want %s", body["error"], rar.ErrorCode)
	}
}

// Narrowing down is allowed -- that is what exchange is for.
func TestExchangeAllowsNarrowingTheDetails(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier", "locations"}, []string{"actions"})

	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate", "status"},
		Identifier: "acct-42",
	}}
	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-rar-cccccccccccccccccccccc", granted)

	status, body := f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
		"authorization_details": {`[{"type":"payment_initiation",` +
			`"actions":["status"],"identifier":"acct-42"}]`},
	})
	if status != http.StatusOK {
		t.Fatalf("narrowing was refused: %d %v", status, body)
	}
	got := detailsInAccessToken(t, body["access_token"].(string))
	if len(got) != 1 || len(got[0].Actions) != 1 || got[0].Actions[0] != "status" {
		t.Fatalf("the narrowed token carries %+v, want only the status action", got)
	}
}

// Exchange dropped the sender-constraint as well as the details.
//
// handleToken verifies the DPoP proof before dispatching the grant, so the
// caller's thumbprint was already on the context; this path just never read it.
// RFC 9449 §5 permits an AS to elect not to bind ("An authorization server MAY
// elect to issue access tokens that are not DPoP bound"), so the old behaviour
// was allowed rather than wrong — but it meant a client using DPoP everywhere
// else silently received an ordinary bearer token from the one endpoint whose
// entire purpose is handing a credential to another party.
func TestAnExchangedTokenIsBoundToTheCallersDPoPKey(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)

	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-dpop-aaaaaaaaaaaaaaaaaaaaa", nil)
	key := newProofKey(t)

	status, body := f.postDPoP(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	}, key.proof(t, "jti-exchange-0001"))
	if status != http.StatusOK {
		t.Fatalf("exchange under DPoP gave %d: %v", status, body)
	}

	bound := confirmationIn(t, body["access_token"].(string))
	if bound != key.thumbprint(t) {
		t.Fatalf("the exchanged token is bound to %q, want the caller's key %q: a "+
			"client that proved possession received an unconstrained bearer token "+
			"from the endpoint that hands credentials to someone else",
			bound, key.thumbprint(t))
	}
	if got := body["token_type"]; got != "DPoP" {
		t.Fatalf("token_type is %v while the token carries cnf.jkt; the client "+
			"will send no proof and every request will be refused", got)
	}
}

// A caller that presents no proof still gets a plain bearer token -- binding must
// not become mandatory as a side effect.
func TestAnExchangeWithoutAProofIsStillBearer(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-dpop-bbbbbbbbbbbbbbbbbbbbb", nil)

	status, body := f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("plain exchange gave %d: %v", status, body)
	}
	if got := body["token_type"]; got != "Bearer" {
		t.Fatalf("token_type is %v for a caller that sent no proof", got)
	}
	if bound := confirmationIn(t, body["access_token"].(string)); bound != "" {
		t.Fatalf("the token is bound to %q though nothing was proved", bound)
	}
}

// A sender-constrained subject token may only be exchanged by whoever holds its
// key.
//
// No specification demands this — RFC 8693 §1 puts proof-of-possession handling
// out of scope as "policy decisions made with respect to the specific needs of
// individual deployments" — so it is a choice, and these tests are what make the
// choice checkable.
//
// The reasoning: `cnf.jkt` means "holding this is not enough". userinfo and the
// credential endpoint both enforce that. The token endpoint did not, so a stolen
// bound token could be traded there for a working one by someone who never held
// the key — leaving exactly one door where possession alone suffices, and an
// attacker only ever needs the weakest door.
func TestABoundSubjectTokenCannotBeExchangedByAnotherKey(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)

	victim := newProofKey(t)
	thief := newProofKey(t)

	// A subject token genuinely bound to the victim's key.
	code := f.issueCodeWithDetailsAndScopes(t,
		"verifier-exchange-bound-aaaaaaaaaaaaaaaaaaaa", nil, []string{"openid"})
	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {"verifier-exchange-bound-aaaaaaaaaaaaaaaaaaaa"},
		// Confidential since enableExchange; see subjectTokenWithDetails.
		"client_secret": {f.exchangeSecret},
	}, victim.proof(t, "jti-bound-issue-1"))
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	subject := body["access_token"].(string)
	if confirmationIn(t, subject) != victim.thumbprint(t) {
		t.Fatal("the subject token is not bound, so the test proves nothing")
	}

	status, body = f.postDPoP(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	}, thief.proof(t, "jti-bound-thief-1"))

	if status == http.StatusOK {
		t.Fatalf("a bound subject token was exchanged by a party that cannot prove "+
			"its key: the token endpoint becomes the one place where possession "+
			"alone is sufficient: %v", body)
	}

	// And with no proof at all.
	status, body = f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	})
	if status == http.StatusOK {
		t.Fatal("dropping the proof entirely escaped the subject token's binding")
	}

	// The message must distinguish "send a proof" from "wrong key".
	//
	// Security does not rest on the separate branch: with no proof the presented
	// thumbprint is empty and a constant-time compare against a real one fails on
	// length alone, which mutation confirmed. The branch earns its place on
	// diagnostics -- a caller told its key is wrong will go looking for a
	// mismatch that does not exist. Asserted so the branch has a reason that can
	// fail, exactly as for the refresh binding in dpoprefresh_test.go.
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "present a proof") {
		t.Fatalf("the refusal says %q; a caller that sent no proof needs to be "+
			"told to send one, not that its key does not match", desc)
	}
}

// The holder still gets through -- a rule that refuses everyone is an outage.
func TestTheHolderOfABoundSubjectTokenCanStillExchangeIt(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	holder := newProofKey(t)

	code := f.issueCodeWithDetailsAndScopes(t,
		"verifier-exchange-bound-bbbbbbbbbbbbbbbbbbbb", nil, []string{"openid"})
	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {"verifier-exchange-bound-bbbbbbbbbbbbbbbbbbbb"},
		"client_secret": {f.exchangeSecret},
	}, holder.proof(t, "jti-bound-issue-2"))
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	subject := body["access_token"].(string)

	status, body = f.postDPoP(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	}, holder.proof(t, "jti-bound-holder-2"))

	if status != http.StatusOK {
		t.Fatalf("the key holder was refused its own subject token: %d %v", status, body)
	}
}

// An ordinary bearer subject token is unaffected: the check must not quietly
// make DPoP mandatory for everyone.
func TestAnUnboundSubjectTokenStillExchangesWithoutAProof(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-unbound-aaaaaaaaaaaaaaaaaa", nil)

	status, body := f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"client_secret":      {f.exchangeSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {exchangeAudience},
		"client_id":          {f.clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("an unbound subject token was refused: %d %v", status, body)
	}
}
