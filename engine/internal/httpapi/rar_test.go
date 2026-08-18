package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/rar"
	"signari.dev/engine/internal/store"
)

// RFC 9396 end to end: a rich permission survives from the authorization request
// to the token response.
//
// internal/rar proves the rules. What is untested until here is whether the
// granted details are the ones the RESOURCE OWNER approved rather than whatever
// the client resends — the property §7 is about, and the one a library test
// cannot reach.

func registerType(t *testing.T, f *tokenFixture, typ string, fields, required []string) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.authorization_detail_types (org_id, type, fields, required)
		VALUES ($1::uuid, $2, $3, $4)`, f.orgID, typ, fields, required); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.client_authorization_detail_types (client_id, org_id, type)
		VALUES ($1, $2::uuid, $3)`, f.clientID, f.orgID, typ); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(c, `DELETE FROM core.authorization_detail_types
			WHERE org_id = $1::uuid AND type = $2`, f.orgID, typ)
	})
}

// issueCodeWithDetails plants a code carrying granted details, the way the
// authorize endpoint would once the resource owner approved.
func (f *tokenFixture) issueCodeWithDetails(t *testing.T, verifier string,
	details []rar.Detail) string {

	t.Helper()
	ctx := context.Background()
	code, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := store.MarshalDetails(details)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grant := oauth.GrantRecord{
		ClientID: f.clientID, RedirectURI: "https://rp.test/cb",
		CodeChallenge: oauth.Challenge(verifier), CodeChallengeMethod: "S256",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.IssueCode(ctx, tx, f.orgID, f.clientID, f.sid, f.userID,
		grant, hash, nil, blob); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchSessionClient(ctx, tx, f.sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return code
}

// §7: "the AS MUST also return the authorization_details as granted by the
// resource owner and assigned to the respective access token."
func TestGrantedAuthorizationDetailsAreReturnedInTheTokenResponse(t *testing.T) {
	f := newTokenFixture(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier"}, []string{"actions"})

	verifier := "verifier-for-rar-test-0000000000000000000000000000"
	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate", "status"},
		Identifier: "acct-1",
	}}
	code := f.issueCodeWithDetails(t, verifier, granted)

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}

	raw, ok := body["authorization_details"]
	if !ok {
		t.Fatalf("the token response carries no authorization_details; §7 makes "+
			"returning them a MUST: %v", body)
	}
	blob, _ := json.Marshal(raw)
	var got []rar.Detail
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != "payment_initiation" ||
		got[0].Identifier != "acct-1" || len(got[0].Actions) != 2 {
		t.Fatalf("returned %+v, want what the resource owner granted", got)
	}
}

// And the converse: a grant with no rich permissions must not carry the field at
// all. A client that never asked should not have to tell "you got nothing" apart
// from "this server does not do that".
func TestAGrantWithoutDetailsOmitsTheField(t *testing.T) {
	f := newTokenFixture(t)
	verifier := "verifier-for-rar-test-1111111111111111111111111111"
	code := f.issueCodeWithDetails(t, verifier, nil)

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	if _, present := body["authorization_details"]; present {
		t.Errorf("a grant with no rich permissions returned the field anyway: %v", body)
	}
}

// §5 at the authorization endpoint, through the real handler: an unregistered
// type is refused, and refused with the error code the specification names.
func TestTheAuthorizeEndpointRefusesAnUnregisteredType(t *testing.T) {
	f := newTokenFixture(t)
	registerType(t, f, "payment_initiation", []string{"actions"}, []string{"actions"})

	q := url.Values{
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {oauth.Challenge("v")}, "code_challenge_method": {"S256"},
		"authorization_details": {`[{"type":"nuclear_launch","actions":["fire"]}]`},
	}
	req := mustGet(t, "/oauth2/authorize?"+q.Encode())
	rec := serve(t, f.srv, req)

	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || loc == "" {
		t.Fatalf("expected a redirected error, got %d %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("error"); got != rar.ErrorCode {
		t.Errorf("error = %q, want %q — §5 names this code specifically",
			got, rar.ErrorCode)
	}
}

// A type the deployment registered but THIS client was not, which §5 makes an
// unknown type from the client's point of view. Dropping it silently instead
// would mint a token weaker than the consent screen described.
func TestATypeThisClientMayNotRequestIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.authorization_detail_types (org_id, type, fields, required)
		VALUES ($1::uuid, 'other_client_only', ARRAY['actions'], ARRAY['actions'])`,
		f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(c, `DELETE FROM core.authorization_detail_types
			WHERE org_id = $1::uuid AND type = 'other_client_only'`, f.orgID)
	})

	q := url.Values{
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {oauth.Challenge("v")}, "code_challenge_method": {"S256"},
		"authorization_details": {`[{"type":"other_client_only","actions":["go"]}]`},
	}
	rec := serve(t, f.srv, mustGet(t, "/oauth2/authorize?"+q.Encode()))
	u, _ := url.Parse(rec.Header().Get("Location"))
	if u == nil || u.Query().Get("error") != rar.ErrorCode {
		t.Fatalf("a type this client may not request was not refused: %d %s",
			rec.Code, rec.Header().Get("Location"))
	}
}

func mustGet(t *testing.T, path string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func serve(t *testing.T, srv *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, r)
	return rec
}

// issueCodeWithDetailsAndScopes is issueCodeWithDetails plus a scope list, so a
// test can ask for `offline_access` and get a refresh token to rotate.
func (f *tokenFixture) issueCodeWithDetailsAndScopes(t *testing.T, verifier string,
	details []rar.Detail, scopes []string) string {

	t.Helper()
	ctx := context.Background()
	code, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := store.MarshalDetails(details)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grant := oauth.GrantRecord{
		ClientID: f.clientID, RedirectURI: "https://rp.test/cb",
		CodeChallenge: oauth.Challenge(verifier), CodeChallengeMethod: "S256",
		Scopes: scopes, ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.IssueCode(ctx, tx, f.orgID, f.clientID, f.sid, f.userID,
		grant, hash, nil, blob); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchSessionClient(ctx, tx, f.sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return code
}

// detailsInAccessToken decodes the RFC 9396 §9.1 claim from a signed token.
func detailsInAccessToken(t *testing.T, at string) []rar.Detail {
	t.Helper()
	parts := strings.Split(at, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWS: %q", at)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Details []rar.Detail `json:"authorization_details"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Details
}

// §9 (MUST): "In order to enable the RS to enforce the authorization details as
// approved in the authorization process, the AS MUST make this data available
// to the RS."
//
// §7's token-response field goes to the CLIENT. The client is the party being
// constrained; the resource server is the one that has to do the constraining,
// and it never sees the token response. Without the claim an RS has only `scope`
// -- exactly the coarse grant RAR exists to replace.
func TestTheAccessTokenCarriesTheGrantedDetailsForTheResourceServer(t *testing.T) {
	f := newTokenFixture(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier"}, []string{"actions"})

	verifier := "verifier-for-rar-rs-000000000000000000000000000000"
	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-9",
	}}
	code := f.issueCodeWithDetails(t, verifier, granted)

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}

	got := detailsInAccessToken(t, body["access_token"].(string))
	if len(got) != 1 || got[0].Identifier != "acct-9" {
		t.Fatalf("the access token carries %+v; a resource server cannot enforce "+
			"a permission it never receives", got)
	}
}

// The lifecycle bug, and the reason a per-endpoint review missed it.
//
// The authorization carried a constraint; the FIRST access token carried it too.
// The refreshed one did not -- mintFromGrant never read the details -- so a
// permission narrowed at authorization silently widened back to plain `scope` at
// the first rotation. Nothing failed and no error was logged, because a resource
// server seeing no details has no way to tell "unconstrained grant" from
// "constraint lost in transit".
//
// Migration 0080 had already added the column, with a comment saying the details
// "have to survive a refresh, or the second token silently carries different
// permissions from the first". No code ever wrote or read it. Only walking the
// full lifecycle finds this; every individual endpoint looked correct.
func TestDetailsSurviveARefreshInsteadOfWideningBackToScope(t *testing.T) {
	f := newTokenFixture(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier"}, []string{"actions"})

	verifier := "verifier-for-rar-refresh-00000000000000000000000000"
	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-7",
	}}
	code := f.issueCodeWithDetailsAndScopes(t, verifier, granted,
		[]string{"openid", "offline_access"})

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	refresh, ok := body["refresh_token"].(string)
	if !ok {
		t.Fatalf("no refresh token; the test cannot exercise rotation: %v", body)
	}
	if d := detailsInAccessToken(t, body["access_token"].(string)); len(d) != 1 {
		t.Fatalf("the first access token already lacks details: %+v", d)
	}

	status, body = f.post(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh gave %d: %v", status, body)
	}

	// The claim the resource server reads.
	got := detailsInAccessToken(t, body["access_token"].(string))
	if len(got) != 1 || got[0].Identifier != "acct-7" ||
		len(got[0].Actions) != 1 || got[0].Actions[0] != "initiate" {
		t.Fatalf("after one refresh the access token carries %+v; the constraint "+
			"was dropped and the token now grants whatever `scope` allows", got)
	}

	// And §7's field for the client, which must not vanish either.
	if _, ok := body["authorization_details"]; !ok {
		t.Fatalf("the refreshed token response omits authorization_details; §7 "+
			"requires them on the token response, not only the first one: %v", body)
	}
}

// §3.1 (MUST): "When gathering user consent, the AS MUST present the merged set
// of requirements represented by the authorization request."
//
// The consent screen listed scopes only. A user approving a payment of a
// specific amount to a specific account saw "openid profile" and nothing else --
// so the one thing RAR exists to make explicit was the one thing not shown.
func TestTheConsentScreenShowsTheAuthorizationDetails(t *testing.T) {
	f := newTokenFixture(t)
	c, err := f.srv.lookupClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	details := []rar.Detail{{
		Type:       "payment_initiation",
		Actions:    []string{"initiate"},
		Identifier: "DE02100100109307118603",
	}}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x", nil)
	f.srv.renderConsent(rec, req, c, store.ConsentDecision{Missing: []string{"profile"}},
		details, "client_id=x")

	page := rec.Body.String()
	for _, want := range []string{"payment_initiation", "initiate", "DE02100100109307118603"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the consent screen never shows %q, so the user is approving "+
				"a transaction they were not shown:\n%s", want, page)
		}
	}
}

// Details are never pre-approved by a stored consent or a first-party trust
// relationship.
//
// Consent is recorded per SCOPE. An authorization detail carries the particulars
// of one transaction, so a user who once approved the scope `payments` approved
// a capability and never a payment. If a stored grant could satisfy a detail,
// every later transfer -- any amount, any account -- would be auto-approved with
// no screen at all.
func TestAuthorizationDetailsAlwaysPromptEvenForAFirstPartyClient(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	c, lerr := f.srv.lookupClient(ctx, f.clientID)
	if lerr != nil {
		t.Fatal(lerr)
	}
	c.FirstParty = true

	// Prior consent for every scope in the request: without details this is
	// exactly the case that must NOT prompt.
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := f.pool.Begin(ctx2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordConsent(ctx2, tx, f.userID, f.clientID,
		[]string{"openid", "profile"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx2); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	base := oauth.AuthzRequest{ClientID: f.clientID, Scope: "openid profile"}

	if _, ask, err := f.srv.needsConsent(req, c, f.userID, base); err != nil {
		t.Fatal(err)
	} else if ask {
		t.Fatal("a first-party client with prior consent and no details was " +
			"prompted; the test cannot then show that details are what forces it")
	}

	withDetails := base
	withDetails.AuthorizationDetails = []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"},
	}}
	_, ask, err := f.srv.needsConsent(req, c, f.userID, withDetails)
	if err != nil {
		t.Fatal(err)
	}
	if !ask {
		t.Fatal("a request carrying authorization_details was auto-approved from " +
			"stored scope consent: every later payment would be granted silently")
	}
}

// §9.2 (MUST): "the information MUST be conveyed with authorization_details as
// a top-level member of the introspection response JSON object."
//
// Both halves are asserted -- that the details reach introspection at all, and
// that they arrive under that exact name at the top level. A resource server
// looks there and nowhere else, so details nested one level down, or spelled
// differently, are details it will never find.
func TestIntrospectionConveysDetailsAsATopLevelMember(t *testing.T) {
	f := newTokenFixture(t)
	registerType(t, f, "payment_initiation",
		[]string{"actions", "identifier"}, []string{"actions"})

	verifier := "verifier-for-rar-introspect-000000000000000000000"
	granted := []rar.Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-3",
	}}
	code := f.issueCodeWithDetails(t, verifier, granted)

	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}

	c, err := f.srv.lookupClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp := f.srv.introspectAccessToken(context.Background(), c,
		body["access_token"].(string))
	if resp == nil || !resp.Active {
		t.Fatalf("introspection reported the fresh token inactive: %+v", resp)
	}

	// Marshalled, not read off the struct: the MUST is about what the resource
	// server receives, and a wrong json tag is invisible from the Go side.
	blob, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(blob, &top); err != nil {
		t.Fatal(err)
	}
	raw, ok := top["authorization_details"]
	if !ok {
		t.Fatalf("the introspection response has no top-level "+
			"authorization_details member: %s", blob)
	}
	var got []rar.Detail
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("authorization_details is not the §2 structure: %v", err)
	}
	if len(got) != 1 || got[0].Identifier != "acct-3" {
		t.Fatalf("introspection reports %+v, not what was granted", got)
	}
}
