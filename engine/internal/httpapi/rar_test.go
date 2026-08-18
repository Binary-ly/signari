package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
