package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Signed authorization responses (JARM), through the authorization endpoint. A
// response here is read the way §2.4 tells a client to read one: the signature against
// the published keys, then iss, aud and exp, and only then what it says.

// newResponseClient is a client a session gets a code from with no consent page, with
// algorithm as its authorization_signed_response_alg. The fixture holds ES256 alone.
func newResponseClient(t *testing.T, algorithm string) *signInFixture {
	t.Helper()
	f := newSignInFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET first_party = true,
		authorization_signed_response_alg = NULLIF($2, ''),
		allow_hybrid = true, response_types = ARRAY['code', 'code id_token'] WHERE client_id = $1`,
		f.clientID, algorithm); err != nil {
		t.Fatal(err)
	}
	return f
}

// carried is how a response reached the client, and the parameters that reached it.
func carried(t *testing.T, rec *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	if rec.Code == http.StatusOK {
		page := rec.Body.String()
		if !strings.Contains(page, `action="https://rp.test/cb"`) {
			t.Fatalf("a page that does not post to the client: %.300s", page)
		}
		fields := url.Values{}
		for _, m := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(page, -1) {
			fields.Set(m[1], html.UnescapeString(m[2]))
		}
		return "form_post", fields
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc.String(), "https://rp.test/cb") {
		t.Fatalf("not sent back to the client (%d, %q): %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if loc.Fragment == "" {
		return "query", loc.Query()
	}
	if len(loc.Query()) != 0 {
		t.Errorf("a response in two places: %q", loc)
	}
	values, err := url.ParseQuery(loc.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	return "fragment", values
}

// opened is §2.4, for a response expected from issuer.
func (f *signInFixture) opened(t *testing.T, raw, issuer string) map[string]any {
	t.Helper()
	claims := f.verified(t, raw, issuer)
	exp, _ := claims["exp"].(float64)
	// §2.1: "A maximum JWT lifetime of 10 minutes is RECOMMENDED."
	if left := time.Until(time.Unix(int64(exp), 0)); left <= 0 || left > 10*time.Minute {
		t.Errorf("exp is %v from now", left)
	}
	return claims
}

// verified checks a JWT from this server to this client: who signed it, and for whom.
func (f *signInFixture) verified(t *testing.T, raw, issuer string) map[string]any {
	t.Helper()
	token, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatalf("no signed response in %q: %v", raw, err)
	}
	key, published := f.srv.cfg.Keys.ByKID(token.Signatures[0].Header.KeyID)
	if !published {
		t.Fatalf("signed by %q, which nobody published", token.Signatures[0].Header.KeyID)
	}
	payload, err := token.Verify(key.Signer().Public())
	if err != nil {
		t.Fatalf("the signature did not verify: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != issuer {
		t.Errorf("iss is %v, want %s", claims["iss"], issuer)
	}
	if claims["aud"] != f.clientID {
		t.Errorf("aud is %v, want the client", claims["aud"])
	}
	return claims
}

var signedModes = []struct{ mode, encoding string }{
	{"query.jwt", "query"}, {"fragment.jwt", "fragment"}, {"form_post.jwt", "form_post"},
	{"jwt", "query"},
}

// The state and the issuer travel inside: the client must not read anything before it
// has checked the signature, and §2.3 gives it one parameter to check.
func TestASignedResponseCarriesNothingButTheJWT(t *testing.T) {
	f := newResponseClient(t, "ES256")
	cookie := f.signInAndReturnCookie(t)
	for _, tc := range signedModes {
		t.Run(tc.mode, func(t *testing.T) {
			encoding, outer := carried(t, f.authorizeWith(t, cookie, url.Values{"response_mode": {tc.mode}}))
			if encoding != tc.encoding {
				t.Errorf("it came by %s, want %s", encoding, tc.encoding)
			}
			if len(outer) != 1 || outer.Get("response") == "" {
				t.Fatalf("the response carried %v, want `response` alone", outer)
			}
			claims := f.opened(t, outer.Get("response"), f.srv.cfg.Issuer)
			if claims["state"] != "s" {
				t.Errorf("state is %v", claims["state"])
			}
			code, _ := claims["code"].(string)
			if tokens := f.redeemCode(t, code); tokens["id_token"] == nil {
				t.Errorf("the code in the response did not redeem: %v", tokens)
			}
		})
	}
}

// §2.1: the parameters are in the JWT "even in case of an error response".
func TestARefusalIsSignedAsACodeWouldHaveBeen(t *testing.T) {
	f := newResponseClient(t, "ES256")
	for _, tc := range signedModes {
		t.Run(tc.mode, func(t *testing.T) {
			encoding, outer := carried(t, f.authorizeWith(t, "", url.Values{
				"response_mode": {tc.mode}, "prompt": {"none"}}))
			if encoding != tc.encoding || len(outer) != 1 {
				t.Fatalf("it came by %s carrying %v, want %s and `response` alone", encoding, outer, tc.encoding)
			}
			claims := f.opened(t, outer.Get("response"), f.srv.cfg.Issuer)
			if claims["error"] != "login_required" || claims["state"] != "s" {
				t.Errorf("the refusal says %v", claims)
			}
		})
	}
}

// An error goes the way a code would have. It went in the query whatever was asked:
// past form_post, which is there to keep the response out of URLs, and past OIDC Core
// §3.3.2.6, which says a hybrid error "MUST" go in the fragment "unless a different
// Response Mode was specified". A client listening at a fragment saw nothing.
func TestARefusalGoesTheWayTheResponseWouldHave(t *testing.T) {
	f := newResponseClient(t, "")
	hybrid := url.Values{"response_type": {"code id_token"}, "nonce": {"n-0S6_WzA2Mj"}}
	for _, tc := range []struct {
		name     string
		extra    url.Values
		encoding string
	}{
		{"a code by default", nil, "query"},
		{"query", url.Values{"response_mode": {"query"}}, "query"},
		{"fragment", url.Values{"response_mode": {"fragment"}}, "fragment"},
		{"form_post", url.Values{"response_mode": {"form_post"}}, "form_post"},
		{"hybrid by default", hybrid, "fragment"},
		{"hybrid form_post", url.Values{"response_type": hybrid["response_type"], "nonce": hybrid["nonce"],
			"response_mode": {"form_post"}}, "form_post"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := url.Values{"prompt": {"none"}}
			for name, values := range tc.extra {
				extra[name] = values
			}
			encoding, outer := carried(t, f.authorizeWith(t, "", extra))
			if encoding != tc.encoding {
				t.Errorf("it came by %s, want %s", encoding, tc.encoding)
			}
			if outer.Get("error") != "login_required" || outer.Get("state") != "s" ||
				outer.Get("iss") != f.srv.cfg.Issuer {
				t.Errorf("it carried %v", outer)
			}
		})
	}
}

// A signature does not make a query string a place for an assertion, and `jwt` picks
// the fragment for one (§2.3.4).
func TestASignedHybridResponseStaysOutOfTheQuery(t *testing.T) {
	f := newResponseClient(t, "ES256")
	cookie := f.signInAndReturnCookie(t)
	extra := url.Values{"response_type": {"code id_token"}, "nonce": {"n-0S6_WzA2Mj"}, "response_mode": {"jwt"}}

	encoding, outer := carried(t, f.authorizeWith(t, cookie, extra))
	if encoding != "fragment" {
		t.Errorf("a hybrid response by `jwt` came by %s", encoding)
	}
	claims := f.opened(t, outer.Get("response"), f.srv.cfg.Issuer)
	if claims["code"] == nil || claims["id_token"] == nil {
		t.Errorf("the response carried %v", claims)
	}

	extra.Set("response_mode", "query.jwt")
	_, outer = carried(t, f.authorizeWith(t, cookie, extra))
	claims = f.opened(t, outer.Get("response"), f.srv.cfg.Issuer)
	if claims["error"] != "invalid_request" || claims["id_token"] != nil {
		t.Errorf("query.jwt with an id_token answered %v", claims)
	}
}

// With an algorithm set a client gets nothing unsigned, the refusal of a plain mode
// included: a client that only reads signed responses cannot read any other.
func TestAClientHeldToSigningGetsNothingUnsigned(t *testing.T) {
	f := newResponseClient(t, "ES256")
	cookie := f.signInAndReturnCookie(t)
	for _, tc := range []struct {
		mode, encoding string
	}{{"", "query"}, {"query", "query"}, {"fragment", "fragment"}, {"form_post", "form_post"}} {
		t.Run("mode "+tc.mode, func(t *testing.T) {
			extra := url.Values{}
			if tc.mode != "" {
				extra.Set("response_mode", tc.mode)
			}
			encoding, outer := carried(t, f.authorizeWith(t, cookie, extra))
			if encoding != tc.encoding || len(outer) != 1 {
				t.Fatalf("it came by %s carrying %v, want %s and `response` alone", encoding, outer, tc.encoding)
			}
			claims := f.opened(t, outer.Get("response"), f.srv.cfg.Issuer)
			if claims["error"] != "invalid_request" || claims["code"] != nil {
				t.Errorf("a plain mode for a client held to signing answered %v", claims)
			}
		})
	}
}

// A client asked for a signature so as to refuse a response without one. With no key
// to sign with it gets nothing, not the same thing in the clear.
func TestAResponseThatCannotBeSignedIsNotSent(t *testing.T) {
	// An unset algorithm is RS256, and this fixture holds ES256 alone.
	f := newResponseClient(t, "")
	cookie := f.signInAndReturnCookie(t)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"a code":     f.authorizeWith(t, cookie, url.Values{"response_mode": {"jwt"}}),
		"a form":     f.authorizeWith(t, cookie, url.Values{"response_mode": {"form_post.jwt"}}),
		"a refusal":  f.authorizeWith(t, "", url.Values{"response_mode": {"jwt"}, "prompt": {"none"}}),
		"a fragment": f.authorizeWith(t, "", url.Values{"response_mode": {"fragment.jwt"}, "prompt": {"none"}}),
	} {
		if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" ||
			strings.Contains(rec.Body.String(), "rp.test") {
			t.Errorf("%s with no key to sign it answered %d %q: %.200s", name, rec.Code,
				rec.Header().Get("Location"), rec.Body.String())
		}
	}
}

// §3: "If unspecified, the default algorithm to use for signing authorization responses
// is RS256", and what a client set otherwise.
func TestAResponseIsSignedWithTheClientsAlgorithm(t *testing.T) {
	f := newResponseClient(t, "")
	cookie := f.signInAndReturnCookie(t)
	generated, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(generated, keys.StateActive)
	next, err := keys.NewSet(append(f.srv.cfg.Keys.Keys(), active)...)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Keys = next

	algorithm := func() string {
		t.Helper()
		_, outer := carried(t, f.authorizeWith(t, cookie, url.Values{"response_mode": {"jwt"}}))
		f.opened(t, outer.Get("response"), f.srv.cfg.Issuer)
		alg, _ := tokenHeader(t, outer.Get("response"))
		return alg
	}
	if alg := algorithm(); alg != "RS256" {
		t.Errorf("with nothing set a response is signed %s", alg)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET authorization_signed_response_alg = 'ES256'
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if alg := algorithm(); alg != "ES256" {
		t.Errorf("set to ES256 a response is signed %s", alg)
	}
}

// RFC 9207's iss is the issuer as the client knows it, and a refusal named the
// deployment's own to a client pinned to an alias, which took it for a mix-up.
func TestARefusalNamesTheIssuerTheClientKnows(t *testing.T) {
	f := newResponseClient(t, "")
	ctx := context.Background()
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	alias := fmt.Sprintf("https://legacy-%d.test", time.Now().UnixNano())
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `UPDATE core.clients SET issuer_alias = NULL WHERE client_id = $1`, f.clientID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.instance_issuer_aliases WHERE issuer = $1`, alias)
	})
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.AddIssuerAlias(ctx, tx, instanceID, alias, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE core.clients SET issuer_alias = $2, authorization_signed_response_alg = NULL
		WHERE client_id = $1`, f.clientID, alias); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	_, outer := carried(t, f.authorizeWith(t, "", url.Values{"prompt": {"none"}}))
	if outer.Get("iss") != alias {
		t.Errorf("a refusal told a pinned client its issuer is %q, want %q", outer.Get("iss"), alias)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET authorization_signed_response_alg = 'ES256'
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	_, outer = carried(t, f.authorizeWith(t, "", url.Values{"prompt": {"none"}, "response_mode": {"jwt"}}))
	f.opened(t, outer.Get("response"), alias)
}

// The mode has to survive the pages of a sign-in, pushed or not, or the person arrives
// at the client unsigned after doing everything right.
func TestASignedResponseSurvivesThePagesOfASignIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		page func(t *testing.T, f *signInFixture) *httptest.ResponseRecorder
	}{
		{"in the URL", func(t *testing.T, f *signInFixture) *httptest.ResponseRecorder {
			return f.authorizeWith(t, "", url.Values{"response_mode": {"form_post.jwt"}})
		}},
		{"pushed", func(t *testing.T, f *signInFixture) *httptest.ResponseRecorder {
			return f.byHandle(t, "", f.push(t, url.Values{"response_mode": {"form_post.jwt"}}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newResponseClient(t, "ES256")
			clearSignInBucket(t, f.pool)
			arrived, _ := f.signInThrough(t, tc.page(t, f))
			encoding, outer := carried(t, arrived)
			if encoding != "form_post" {
				t.Errorf("it came by %s", encoding)
			}
			if claims := f.opened(t, outer.Get("response"), f.srv.cfg.Issuer); claims["code"] == nil {
				t.Errorf("signing in arrived with %v", claims)
			}
		})
	}
}

// The disposition is load-bearing: an error sent to a redirect URI nothing vouches for
// sends a person wherever the request said.
func TestARefusalGoesToARedirectOnlyWithAClientBehindIt(t *testing.T) {
	f := newResponseClient(t, "")
	c, err := f.srv.lookupClientAnyState(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		client      *clients.Client
		disposition oauth.Disposition
	}{
		"a redirect error and no client":   {nil, oauth.DispositionRedirect},
		"a direct error and a client":      {c, oauth.DispositionDirect},
		"a direct error and nobody at all": {nil, oauth.DispositionDirect},
	} {
		rec := httptest.NewRecorder()
		f.srv.writeAuthzError(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil),
			oauth.AuthzRequest{RedirectURI: "https://evil.test/cb"}, tc.client,
			&oauth.AuthzError{Code: "invalid_request", Disposition: tc.disposition})
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" ||
			strings.Contains(rec.Body.String(), "evil.test") {
			t.Errorf("%s answered %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// A push is checked by the rules the authorization endpoint applies, which is the point
// of checking it: a caller that can act on the answer gets it. It was checked against
// a copy of nine parameters, so what it left out reached a person's browser instead,
// and a client held to signing could not push at all.
func TestAPushIsCheckedAsTheRequestItStandsFor(t *testing.T) {
	f := newResponseClient(t, "")
	for name, extra := range map[string]url.Values{
		"a mode nobody knows": {"response_mode": {"carrier-pigeon"}},
		"an impossible mix":   {"response_type": {"code id_token"}, "nonce": {"n"}, "response_mode": {"query.jwt"}},
	} {
		form, err := url.ParseQuery(f.plainAuthz())
		if err != nil {
			t.Fatal(err)
		}
		for key, values := range extra {
			form[key] = values
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
			t.Errorf("%s was pushed: %d %.200s", name, rec.Code, rec.Body.String())
		}
	}
}

// A refusal on the consent page takes the other road to the client, and the same mode.
func TestAConsentRefusalIsSignedToo(t *testing.T) {
	f := newResponseClient(t, "ES256")
	clearSignInBucket(t, f.pool)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET first_party = false WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	b := newTestBrowser(t, f.srv.Routes())
	b.post("/login", b.get("/login"), url.Values{"username": {f.email}, "password": {signInTestPassword}})
	authz, err := url.ParseQuery(f.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	authz.Set("response_mode", "jwt")
	refused := b.post("/consent", b.get("/login"), url.Values{"decision": {"deny"}, "authz": {authz.Encode()}})
	_, outer := carried(t, refused)
	if claims := f.opened(t, outer.Get("response"), f.srv.cfg.Issuer); claims["error"] != "access_denied" {
		t.Errorf("a refusal on the consent page said %v", claims)
	}
}

// The algorithm takes the rules every other one takes, by each road that can set it: a
// response nobody can sign is a client locked out at its next sign-in.
func TestAResponseAlgorithmIsHeldToWhatAnInstanceCanSign(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	set := func(alg string) error {
		t.Helper()
		return setClientSettings(t, f, store.ClientSettings{AuthorizationResponseAlg: &alg})
	}
	for _, alg := range []string{"HS256", "none", "EdDSA"} {
		if err := set(alg); !errors.Is(err, store.ErrInvalidClientSetting) {
			t.Errorf("%s with no such active key answered %v", alg, err)
		}
	}

	generated, err := keys.Generate(keys.NewKID(), keys.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(generated, keys.StateActive)
	root, err := keys.NewRootKey("jarm-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := keys.Save(ctx, tx, instanceID, active, root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE kid = $1`, active.KID())
	})

	if err := set("EdDSA"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ClientSettingsOf(ctx, f.pool, f.clientID); err != nil || got.AuthorizationResponseAlg != "EdDSA" {
		t.Errorf("stored %q (%v)", got.AuthorizationResponseAlg, err)
	}
	if err := set(""); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ClientSettingsOf(ctx, f.pool, f.clientID); err != nil || got.AuthorizationResponseAlg != "" {
		t.Errorf("clearing it left %q (%v)", got.AuthorizationResponseAlg, err)
	}

	register := func(alg string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(
			`{"redirect_uris":["https://rp.test/cb"],"authorization_signed_response_alg":"`+alg+`"}`))
		req.RemoteAddr = freshAddress() + ":443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+registrationToken(t, f))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, out := register("EdDSA")
	id, _ := out["client_id"].(string)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if code != http.StatusCreated || out["authorization_signed_response_alg"] != "EdDSA" {
		t.Errorf("registering an algorithm answered %d %v", code, out)
	}
	if code, out := register("HS256"); code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Errorf("HS256 registered: %d %v", code, out)
	}
}
