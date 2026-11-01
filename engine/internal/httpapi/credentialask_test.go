package httpapi

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/rar"
	"signari.dev/engine/internal/store"
)

// credentialFlow is a holder signed in with a wallet, and two configurations: one
// anybody may ask for, and one that takes an offer.
type credentialFlow struct {
	f  *signInFixture
	b  *testBrowser
	wa *wallet
}

func newCredentialFlow(t *testing.T) *credentialFlow {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	if err := store.RegisterDetailType(ctx, f.pool, f.orgID, store.DetailType{Type: rar.CredentialType,
		Fields: []string{rar.FieldLocations}, Required: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AllowClientDetailType(ctx, f.pool, f.clientID, rar.CredentialType); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.credential_configurations
			(org_id, config_id, vct, always_claims, selective_claims, lifetime, display_name, wallet_initiated)
		VALUES ($1::uuid, 'OpenCredential', 'https://signari.test/open', ARRAY['sub'], ARRAY['email'],
		        interval '30 days', 'Open', true),
		       ($1::uuid, 'ClosedCredential', 'https://signari.test/closed', ARRAY['sub'], ARRAY['email'],
		        interval '30 days', 'Closed', false)`, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(c, `DELETE FROM core.credential_configurations WHERE org_id = $1::uuid`, f.orgID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.authorization_detail_types WHERE org_id = $1::uuid`, f.orgID)
	})
	b := newTestBrowser(t, f.srv.Routes())
	b.post("/login", b.get("/login"), url.Values{"username": {f.email}, "password": {signInTestPassword}})
	if b.value(SessionCookieName) == "" {
		t.Fatal("the fixture did not sign in")
	}
	return &credentialFlow{f: f, b: b, wa: newWallet(t)}
}

func detailsFor(configs ...string) string {
	out := make([]map[string]string, 0, len(configs))
	for _, c := range configs {
		out = append(out, map[string]string{"type": rar.CredentialType, "credential_configuration_id": c})
	}
	blob, _ := json.Marshal(out)
	return string(blob)
}

func (c *credentialFlow) request(details, issuerState string) url.Values {
	q := url.Values{"client_id": {c.f.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"}, rar.Param: {details}}
	if issuerState != "" {
		q.Set("issuer_state", issuerState)
	}
	return q
}

func (c *credentialFlow) authorize(q url.Values) *httptest.ResponseRecorder {
	return c.b.get(oidc.PathAuthorize + "?" + q.Encode())
}

// approve answers the form the page carries, as a browser would: what it posts
// as authz is what the page rendered.
func (c *credentialFlow) approve(q url.Values, page *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	parked := consentAuthz.FindStringSubmatch(page.Body.String())
	if parked == nil {
		panic("no parked request on the consent page")
	}
	return c.b.post("/consent", page, url.Values{"decision": {"allow"}, "authz": {html.UnescapeString(parked[1])},
		"scope": strings.Fields(q.Get("scope"))})
}

var consentAuthz = regexp.MustCompile(`name="authz" value="([^"]*)"`)

func (c *credentialFlow) redeem(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	return c.f.redeemPlain(t, rec)
}

// credential asks with the body given, a proof added.
func (c *credentialFlow) credential(t *testing.T, token, naming string) (int, map[string]any) {
	t.Helper()
	post := func(path, body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		c.f.srv.Routes().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	_, nb := post("/oid4vci/nonce", "")
	nonce, _ := nb["c_nonce"].(string)
	return post("/oid4vci/credential", `{`+naming+`,"proofs":{"jwt":[`+
		mustJSONString(t, c.wa.proof(t, c.f.srv.cfg.Issuer, nonce))+`]}}`)
}

// The flow §3.3 opens with: the wallet asks, the holder signs in and approves what
// they are shown, the token response names an identifier, and the wallet asks with
// that. Nothing here was offered first.
func TestAWalletAsksForACredentialAndTheHolderApprovesIt(t *testing.T) {
	c := newCredentialFlow(t)
	q := c.request(detailsFor("OpenCredential"), "")

	page := c.authorize(q)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "OpenCredential") {
		t.Fatalf("the holder was not shown what is being issued (%d): %.300s", page.Code, page.Body.String())
	}
	body := c.redeem(t, c.approve(q, page))

	details, _ := body["authorization_details"].([]any)
	if len(details) != 1 {
		t.Fatalf("§6.2 requires authorization_details in the response: %v", body)
	}
	detail := details[0].(map[string]any)
	if detail["type"] != rar.CredentialType || detail["credential_configuration_id"] != "OpenCredential" {
		t.Errorf("the detail came back as %v", detail)
	}
	identifiers, _ := detail["credential_identifiers"].([]any)
	if len(identifiers) != 1 {
		t.Fatalf("§6.2: credential_identifiers is a non-empty array: %v", detail)
	}
	identifier := identifiers[0].(string)
	token := body["access_token"].(string)

	claims := claimsOfJWT(t, token)
	if aud, _ := claims["aud"].(string); aud != c.f.srv.credentialAudience() {
		if list, _ := claims["aud"].([]any); len(list) != 1 || list[0] != c.f.srv.credentialAudience() {
			t.Errorf("the token is audienced to %v, and it is good at the credential endpoint alone", claims["aud"])
		}
	}

	// §8.2: the configuration id "MUST NOT be used otherwise".
	if status, out := c.credential(t, token, `"credential_configuration_id":"OpenCredential"`); status != http.StatusBadRequest ||
		out["error"] != "invalid_credential_request" {
		t.Errorf("a token given identifiers took a configuration id: %d %v", status, out)
	}
	if status, out := c.credential(t, token, `"credential_identifier":"ClosedCredential"`); status != http.StatusBadRequest ||
		out["error"] != "unknown_credential_identifier" {
		t.Errorf("an identifier the token was not given: %d %v", status, out)
	}
	status, out := c.credential(t, token, `"credential_identifier":`+mustJSONString(t, identifier))
	if status != http.StatusOK {
		t.Fatalf("the identifier was refused: %d %v", status, out)
	}
	if issued, _ := out["credentials"].([]any); len(issued) != 1 {
		t.Errorf("no credential came back: %v", out)
	}
}

// §5.1.1's own example asks with authorization_details and no scope at all, and
// was refused as an invalid scope. Approved, it gets a token and no ID token.
func TestAWalletNeedNotAskForAScope(t *testing.T) {
	c := newCredentialFlow(t)
	q := c.request(detailsFor("OpenCredential"), "")
	q.Del("scope")
	page := c.authorize(q)
	if page.Code != http.StatusOK {
		t.Fatalf("a request of details alone answered %d %q", page.Code, page.Header().Get("Location"))
	}
	body := c.redeem(t, c.approve(q, page))
	if _, minted := body["id_token"]; minted {
		t.Errorf("nobody asked for openid, and an ID token came back")
	}
	if status, out := c.credential(t, body["access_token"].(string), `"credential_identifier":"OpenCredential"`); status != http.StatusOK {
		t.Errorf("the credential was refused: %d %v", status, out)
	}
}

// Pressing Allow on a screen of details has to end in a code. It went back to the
// authorization endpoint, which never takes a prior decision for details, and
// showed the screen again, so no rich request had ever finished in a browser; the
// tests above this one issued their codes directly.
func TestARichRequestEndsInACode(t *testing.T) {
	c := newCredentialFlow(t)
	ctx := context.Background()
	if err := store.RegisterDetailType(ctx, c.f.pool, c.f.orgID, store.DetailType{Type: "payment",
		Fields: []string{rar.FieldActions}, Required: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AllowClientDetailType(ctx, c.f.pool, c.f.clientID, "payment"); err != nil {
		t.Fatal(err)
	}
	q := c.request(`[{"type":"payment","actions":["pay"]}]`, "")
	page := c.authorize(q)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "payment") {
		t.Fatalf("the details were not shown: %d", page.Code)
	}
	body := c.redeem(t, c.approve(q, page))
	if details, _ := body["authorization_details"].([]any); len(details) != 1 {
		t.Errorf("§7 returns what was granted: %v", body)
	}

	// The approval was that one press. The same request comes back to a screen,
	// because details were never something a stored decision could stand for.
	if again := c.authorize(q); again.Code != http.StatusOK || !strings.Contains(again.Body.String(), "payment") {
		t.Errorf("a second request for the same details was not asked about: %d %q", again.Code,
			again.Header().Get("Location"))
	}

	// A mark on the request itself, which a client can write, is not a press.
	q.Set(detailsShownParam, "1")
	if rec := c.authorize(q); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "payment") {
		t.Errorf("the mark was taken for an approval: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// A pushed request parks its handle, so the consent form carries none of the
// details and the answer still has to know there were some.
func TestAPushedRichRequestEndsInACode(t *testing.T) {
	c := newCredentialFlow(t)
	q := c.request(detailsFor("OpenCredential"), "")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(q.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c.f.srv.Routes().ServeHTTP(rec, req)
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pushed); err != nil || pushed.RequestURI == "" {
		t.Fatalf("the push answered %d: %.300s", rec.Code, rec.Body.String())
	}
	handle := url.Values{"client_id": {c.f.clientID}, "request_uri": {pushed.RequestURI}}
	page := c.authorize(handle)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "OpenCredential") {
		t.Fatalf("the pushed details were not shown: %d %q", page.Code, page.Header().Get("Location"))
	}
	body := c.redeem(t, c.b.post("/consent", page, url.Values{"decision": {"allow"}, "scope": {"openid"},
		"authz": {withDetailsShown(handle.Encode())}}))
	if status, out := c.credential(t, body["access_token"].(string), `"credential_identifier":"OpenCredential"`); status != http.StatusOK {
		t.Errorf("the credential was refused: %d %v", status, out)
	}
}

// A person only has what is open to anybody, or what an offer names them for. A
// wallet can ask for anything in the metadata, and the claims being the person's
// own does not make holding the credential theirs to decide.
func TestAClosedCredentialNeedsAnOfferToThisPerson(t *testing.T) {
	c := newCredentialFlow(t)
	ctx := context.Background()
	q := c.request(detailsFor("ClosedCredential"), "")
	refused := func(rec *httptest.ResponseRecorder, what string) {
		t.Helper()
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=access_denied") {
			t.Errorf("%s: %d %q", what, rec.Code, loc)
		}
	}
	refused(c.authorize(q), "asked for with no offer")
	refused(c.authorize(c.request(detailsFor("ClosedCredential"), "something-a-page-injected")), "an unknown state")

	mint := func(user, clientID string, configs ...string) string {
		t.Helper()
		minted, err := store.MintCredentialOffer(ctx, c.f.pool, c.f.orgID, store.OfferSpec{UserID: user, ClientID: clientID,
			CredentialIssuer: c.f.srv.cfg.Issuer, ConfigIDs: configs, TTL: time.Minute, AuthorizationCode: true})
		if err != nil {
			t.Fatal(err)
		}
		if minted.Offer.Grants.PreAuthorized != nil || minted.Offer.Grants.AuthorizationCode == nil {
			t.Fatalf("the offer carries %+v", minted.Offer.Grants)
		}
		return minted.Offer.Grants.AuthorizationCode.IssuerState
	}

	// Somebody else's offer, injected into this person's request.
	var other string
	if err := c.f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, $2, sha256(gen_random_uuid()::text::bytea))
		RETURNING id::text`, c.f.orgID, "other-"+c.f.clientID+"@test.invalid").Scan(&other); err != nil {
		t.Fatal(err)
	}
	refused(c.authorize(c.request(detailsFor("ClosedCredential"), mint(other, c.f.clientID, "ClosedCredential"))),
		"another person's offer")

	// An offer of something else.
	refused(c.authorize(c.request(detailsFor("ClosedCredential"), mint(c.f.userID, c.f.clientID, "OpenCredential"))),
		"an offer of another credential")

	// An offer to this person, through another wallet.
	otherWallet := c.f.clientID + "-other"
	if _, err := c.f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash,
		                          grant_types, scopes, require_pkce)
		VALUES ($1, $2, 'W', 'public', '', ARRAY['authorization_code'], ARRAY['openid'], true)`,
		otherWallet, c.f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = c.f.pool.Exec(cleanup, `DELETE FROM core.clients WHERE client_id = $1`, otherWallet)
	})
	refused(c.authorize(c.request(detailsFor("ClosedCredential"), mint(c.f.userID, otherWallet, "ClosedCredential"))),
		"an offer through another client")

	// §4.1.1 gives this grant no transaction code, and one would be a promise.
	if _, err := store.MintCredentialOffer(ctx, c.f.pool, c.f.orgID, store.OfferSpec{UserID: c.f.userID,
		ClientID: c.f.clientID, CredentialIssuer: c.f.srv.cfg.Issuer, ConfigIDs: []string{"ClosedCredential"},
		TTL: time.Minute, AuthorizationCode: true, TxCode: true, TxLength: 6}); err == nil {
		t.Error("an offer for the authorization code grant took a transaction code")
	}

	state := mint(c.f.userID, c.f.clientID, "ClosedCredential")
	q = c.request(detailsFor("ClosedCredential"), state)
	page := c.authorize(q)
	if page.Code != http.StatusOK {
		t.Fatalf("the person the offer names was refused: %d %q", page.Code, page.Header().Get("Location"))
	}
	// Looking at the consent screen twice spends nothing.
	if again := c.authorize(q); again.Code != http.StatusOK {
		t.Fatalf("a second look spent the offer: %d", again.Code)
	}
	body := c.redeem(t, c.approve(q, page))
	if status, out := c.credential(t, body["access_token"].(string), `"credential_identifier":"ClosedCredential"`); status != http.StatusOK {
		t.Fatalf("the offered credential was refused: %d %v", status, out)
	}

	// One offer, one authorization.
	refused(c.authorize(q), "an offer already taken up")
}

// A state and a pre-authorized code share a column. A code is a bearer secret and a
// state is not: the holder of one that worked as the other would have a token with
// nobody having signed in, from a value that travels in a browser's address bar.
func TestAnIssuerStateIsNeverAPreAuthorizedCode(t *testing.T) {
	c := newCredentialFlow(t)
	ctx := context.Background()
	minted, err := store.MintCredentialOffer(ctx, c.f.pool, c.f.orgID, store.OfferSpec{UserID: c.f.userID,
		ClientID: c.f.clientID, CredentialIssuer: c.f.srv.cfg.Issuer, ConfigIDs: []string{"ClosedCredential"},
		TTL: time.Minute, AuthorizationCode: true})
	if err != nil {
		t.Fatal(err)
	}
	state := minted.Offer.Grants.AuthorizationCode.IssuerState
	if _, err := store.LookupPreAuthorizedCode(ctx, c.f.pool, store.HashToken(state)); err != store.ErrPreAuthUnknown {
		t.Errorf("a state was found as a pre-authorized code: %v", err)
	}
}

// §5.1.1, and the things only this type can get wrong. Every one comes back at the
// redirect as RFC 9396 §5's error, before anybody is asked to sign in or approve.
func TestARequestForACredentialIsCheckedAsADetail(t *testing.T) {
	c := newCredentialFlow(t)
	ctx := context.Background()
	if err := store.RegisterDetailType(ctx, c.f.pool, c.f.orgID, store.DetailType{Type: "payment",
		Fields: []string{rar.FieldActions}, Required: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AllowClientDetailType(ctx, c.f.pool, c.f.clientID, "payment"); err != nil {
		t.Fatal(err)
	}
	for name, details := range map[string]string{
		"no configuration":   `[{"type":"openid_credential"}]`,
		"not a string":       `[{"type":"openid_credential","credential_configuration_id":["OpenCredential"]}]`,
		"unknown":            `[{"type":"openid_credential","credential_configuration_id":"NoSuchCredential"}]`,
		"another issuer":     `[{"type":"openid_credential","credential_configuration_id":"OpenCredential","locations":["https://elsewhere.test"]}]`,
		"locations not list": `[{"type":"openid_credential","credential_configuration_id":"OpenCredential","locations":"x"}]`,
		"beside another":     `[{"type":"openid_credential","credential_configuration_id":"OpenCredential"},{"type":"payment","actions":["pay"]}]`,
	} {
		rec := c.authorize(c.request(details, ""))
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "error="+rar.ErrorCode) {
			t.Errorf("%s: %d %q", name, rec.Code, loc)
		}
		// Said as what it is, or it reads as a configuration nobody asked for.
		if name == "beside another" && !strings.Contains(loc, "alone") {
			t.Errorf("%s was refused for the wrong reason: %q", name, loc)
		}
	}

	// "never considered invalid due to unknown fields", and a location naming this
	// issuer is what §5.1.1 asks for where one is asked for.
	fine := `[{"type":"openid_credential","credential_configuration_id":"OpenCredential","claims":[{"path":["email"]}],` +
		`"locations":["` + c.f.srv.credentialIssuerID() + `"],"vendor_extension":true}]`
	q := c.request(fine, "")
	page := c.authorize(q)
	if page.Code != http.StatusOK {
		t.Fatalf("a request with an extra field was refused: %d %q", page.Code, page.Header().Get("Location"))
	}
	body := c.redeem(t, c.approve(q, page))

	// The endpoint reads this claim, so the audience filter must not have taken it.
	if status, out := c.credential(t, body["access_token"].(string), `"credential_identifier":"OpenCredential"`); status != http.StatusOK {
		t.Fatalf("a detail with locations lost its claim: %d %v", status, out)
	}
	// What was granted comes back, and an extra field was not granted.
	detail := body["authorization_details"].([]any)[0].(map[string]any)
	if _, echoed := detail["vendor_extension"]; echoed {
		t.Errorf("a field nothing read was answered as granted: %v", detail)
	}
}

// A refresh of this grant is good for what the grant was, and nothing wider. Minted
// with an ordinary audience it would be a token carrying details no resource server
// was meant to see, and the wallet would lose the credential endpoint as well.
func TestARefreshOfACredentialGrantStaysAtTheCredentialEndpoint(t *testing.T) {
	c := newCredentialFlow(t)
	ctx := context.Background()
	if _, err := c.f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = ARRAY['authorization_code','refresh_token'],
		scopes = ARRAY['openid','offline_access'] WHERE client_id = $1`, c.f.clientID); err != nil {
		t.Fatal(err)
	}
	q := c.request(detailsFor("OpenCredential"), "")
	q.Set("scope", "openid offline_access")
	body := c.redeem(t, c.approve(q, c.authorize(q)))
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", body)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {c.f.clientID}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c.f.srv.Routes().ServeHTTP(rec, req)
	var refreshed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &refreshed); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("the refresh answered %d: %.300s", rec.Code, rec.Body.String())
	}
	if status, out := c.credential(t, refreshed["access_token"].(string), `"credential_identifier":"OpenCredential"`); status != http.StatusOK {
		t.Errorf("the refreshed token was refused: %d %v", status, out)
	}
	if !slices.ContainsFunc(refreshed["authorization_details"].([]any), func(d any) bool {
		return len(d.(map[string]any)["credential_identifiers"].([]any)) == 1
	}) {
		t.Errorf("a refresh must return the details too: %v", refreshed)
	}
}

// §8.2's other half: an identifier from a token that was given none is one this
// issuer never handed out.
func TestAnOfferTokenStillAsksByConfiguration(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)
	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, out := f.postJSON(t, "/oid4vci/credential", token, `{"credential_identifier":"IdentityCredential",`+
		`"proofs":{"jwt":[`+mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce))+`]}}`)
	if status != http.StatusBadRequest || out["error"] != "invalid_credential_request" {
		t.Errorf("an identifier from a token given none: %d %v", status, out)
	}
}
