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

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// UMA 2.0 claims gathering, end to end.
//
// The interesting cases are all refusals, and they divide into two kinds:
//
//   - things a hostile client can try: an unregistered claims redirect, a
//     pushed ID token belonging to somebody else, presenting another client's
//     gathered ticket;
//   - things a hostile PAGE can try, which is what §5.1 is about: a GET that
//     spends a ticket without the person's involvement.

// browserSession gives a user a live session and returns the cookie value.
//
// The cookie_hash is SHA-256 of the cookie, because that is what
// ResolveSessionCookie computes. A fixture that stored anything else would
// produce a session the server never resolves, and every test needing one would
// silently take the not-signed-in branch.
func (f *cibaFixture) browserSession(t *testing.T, userID string) string {
	t.Helper()
	cookie, err := newSID()
	if err != nil {
		t.Fatal(err)
	}
	sid := "uma-sid-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr,
		                           auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '1', ARRAY['pwd'],
		        now(), now() + interval '1 hour')`,
		sid, store.HashToken(cookie), f.orgID, userID); err != nil {
		t.Fatalf("creating a browser session: %v", err)
	}
	// Proof the session actually resolves. Without this the whole file could
	// pass by taking the unauthenticated path everywhere, which looks like
	// working refusals.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	if _, got, _, ok := f.srv.currentSession(req); !ok || got != userID {
		t.Fatalf("the fixture session does not resolve (ok=%v user=%q want %q); "+
			"every test here would take the signed-out branch", ok, got, userID)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.sessions WHERE sid = $1`, sid)
	})
	return cookie
}

// registerClaimsRedirect points a client's claims redirection at these URIs.
func (f *cibaFixture) registerClaimsRedirect(t *testing.T, clientID string, uris ...string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET claims_redirect_uris = $2 WHERE client_id = $1`,
		clientID, uris); err != nil {
		t.Fatalf("registering claims redirect URIs: %v", err)
	}
}

// claimsGet asks the claims interaction endpoint for a confirmation page.
func (f *cibaFixture) claimsGet(t *testing.T, cookie string, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, claimsInteractionPath+"?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	f.srv.handleUMAClaims(rec, req)
	return rec
}

// handleFrom pulls the confirmation handle out of a rendered page.
func handleFrom(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="handle" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no handle in the confirmation page:\n%s", body)
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("unterminated handle")
	}
	return rest[:j]
}

// claimsPost submits the confirmation.
func (f *cibaFixture) claimsPost(t *testing.T, cookie, csrf, handle string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"handle": {handle}}
	if csrf != "" {
		form.Set(csrfFormField, csrf)
	}
	req := httptest.NewRequest(http.MethodPost, claimsInteractionPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrf})
	}
	rec := httptest.NewRecorder()
	f.srv.handleUMAClaims(rec, req)
	return rec
}

// csrfFrom reads the token the page was rendered with.
func csrfFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			return c.Value
		}
	}
	const marker = `name="` + csrfFormField + `" value="`
	body := rec.Body.String()
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no CSRF token on the confirmation page")
	}
	rest := body[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}

const claimsReturn = "https://rp.test/uma/return"

// The whole journey: refused, claims gathered, granted.
//
// Every other test here spoils one step of this one.
func TestClaimsGatheringTurnsARefusalIntoAGrant(t *testing.T) {
	f := newCIBAFixture(t)
	// Policy grants `read` on document:42 to the USER, not the client. So the
	// first attempt -- where the requesting party is the client -- must fail, and
	// the same ticket must succeed once the person has been identified. That
	// difference is the entire feature.
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)

	code, body := f.exchange(t, f.clientID, ticket, nil)
	if code != http.StatusForbidden {
		t.Fatalf("an unidentified request got %d, want 403", code)
	}
	if body["error"] != "need_info" {
		t.Fatalf("error = %v, want need_info: policy here is written about a "+
			"person, so refusing outright would be wrong -- gathering claims "+
			"changes the answer", body["error"])
	}
	// §3.3.6 makes both hints valid and this server sends both, because it
	// cannot tell whether the client has an end-user in front of it.
	if body["redirect_user"] == nil {
		t.Error("no redirect_user hint")
	}
	if body["required_claims"] == nil {
		t.Error("no required_claims hint; a headless client has nothing to act on")
	}
	next, _ := body["ticket"].(string)
	if next == "" {
		t.Fatal("need_info carried no ticket, which §3.3.6 makes REQUIRED")
	}
	if next == ticket {
		t.Fatal("the need_info ticket is the same value the client presented; " +
			"§3.3.6 says it MUST NOT be")
	}

	// The person arrives at the claims interaction endpoint.
	cookie := f.browserSession(t, f.userID)
	rec := f.claimsGet(t, cookie, url.Values{
		"client_id": {f.clientID}, "ticket": {next},
		"claims_redirect_uri": {claimsReturn}, "state": {"abc"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("the confirmation page returned %d: %s", rec.Code, rec.Body)
	}
	// What is being asked, in the person's terms. A confirmation that does not
	// say what it is confirming is the reason consent screens get clicked
	// through.
	if !strings.Contains(rec.Body.String(), "document 42") {
		t.Errorf("the confirmation page does not name the resource:\n%s", rec.Body)
	}

	rec2 := f.claimsPost(t, cookie, csrfFrom(t, rec), handleFrom(t, rec.Body.String()))
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("the confirmation returned %d: %s", rec2.Code, rec2.Body)
	}
	loc, err := url.Parse(rec2.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != claimsReturn {
		t.Fatalf("redirected to %q, want %q", loc, claimsReturn)
	}
	gathered := loc.Query().Get("ticket")
	if gathered == "" || gathered == next {
		t.Fatalf("the returned ticket is %q; §3.3.3 requires a value that is not "+
			"the one the client used", gathered)
	}
	if loc.Query().Get("state") != "abc" {
		t.Errorf("state = %q, want abc", loc.Query().Get("state"))
	}

	// And now the same request succeeds, because the requesting party is known.
	code, body = f.exchange(t, f.clientID, gathered, nil)
	if code != http.StatusOK {
		t.Fatalf("the gathered ticket got %d: %v", code, body)
	}
	rpt, _ := body["access_token"].(string)
	if rpt == "" {
		t.Fatal("no RPT")
	}
	// §1.2: an RPT is "unique to a requesting party, client, authorization
	// server, resource server, and resource owner". A resource server
	// introspecting one has to be able to tell who it is about, and leaving the
	// client id here after establishing that the client was NOT the requesting
	// party would say the application asked for itself.
	claims, err := tokens.VerifyAccessToken(f.srv.cfg.Keys, f.srv.cfg.Issuer, rpt)
	if err != nil {
		t.Fatalf("the RPT does not verify: %v", err)
	}
	if claims.Subject != f.userID {
		t.Errorf("the RPT's sub is %q, want the requesting party %q",
			claims.Subject, f.userID)
	}
}

// allowUserOn grants a relation to a PERSON rather than to a client.
func (f *cibaFixture) allowUserOn(t *testing.T, resourceType, resourceID, relation, who string) {
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
    subject: user:x
    action: read
    resource: ` + resourceType + `:1
    relations: [viewer]
    allow: true
`
	m, err := authzen.ParseModel([]byte(model))
	if err != nil {
		t.Fatalf("the fixture's own authorization model does not parse: %v", err)
	}
	if err := store.SaveModel(context.Background(), f.pool, f.orgID, model, m, ""); err != nil {
		t.Fatalf("installing the authorization model: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'user', $2, $3, $4, $5)`,
		f.orgID, who, relation, resourceType, resourceID); err != nil {
		t.Fatalf("granting the relation: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.relations WHERE org_id = $1::uuid`, f.orgID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.authorization_models WHERE org_id = $1::uuid`, f.orgID)
	})
}

// §5.1's requirement that the GET cannot spend anything.
//
// This is the attack the section is written against: a page the requesting party
// never chose to visit causes their browser to issue the GET. If that redeemed
// the ticket and redirected, the identity is spent with no awareness and no
// involvement, and the victim's evidence is a broken image.
func TestTheClaimsGetSpendsNothing(t *testing.T) {
	f := newCIBAFixture(t)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)

	rec := f.claimsGet(t, cookie, url.Values{
		"client_id": {f.clientID}, "ticket": {ticket},
		"claims_redirect_uri": {claimsReturn},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("the confirmation page returned %d", rec.Code)
	}
	// A GET must not redirect. If it does, a browser follows it.
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("the GET redirected to %q, so an <img> tag completes the whole "+
			"interaction on the requesting party's behalf (§5.1)", loc)
	}
	// And the ticket must still be spendable, which is the observable form of
	// "nothing was consumed".
	if _, err := store.InspectPermissionTicket(context.Background(), f.pool,
		store.HashToken(ticket)); err != nil {
		t.Fatalf("the GET consumed the permission ticket: %v", err)
	}

	// Two GETs in a row must both work: a page reload, or a browser prefetching
	// the link, must not destroy the request.
	if rec2 := f.claimsGet(t, cookie, url.Values{
		"client_id": {f.clientID}, "ticket": {ticket},
		"claims_redirect_uri": {claimsReturn},
	}); rec2.Code != http.StatusOK {
		t.Errorf("a second GET returned %d; a reload must not destroy the request",
			rec2.Code)
	}
}

// §5.1's other half.
func TestTheClaimsConfirmationNeedsItsCSRFToken(t *testing.T) {
	f := newCIBAFixture(t)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)
	rec := f.claimsGet(t, cookie, url.Values{
		"client_id": {f.clientID}, "ticket": {ticket},
		"claims_redirect_uri": {claimsReturn},
	})
	handle := handleFrom(t, rec.Body.String())

	if got := f.claimsPost(t, cookie, "", handle); got.Code == http.StatusSeeOther {
		t.Fatal("a confirmation with no CSRF token completed the interaction")
	}
	// A token that is well-formed but not the one this browser holds.
	other, err := newSID()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, claimsInteractionPath,
		strings.NewReader(url.Values{"handle": {handle}, csrfFormField: {other}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfFrom(t, rec)})
	got := httptest.NewRecorder()
	f.srv.handleUMAClaims(got, req)
	if got.Code == http.StatusSeeOther {
		t.Fatal("a confirmation carrying a mismatched CSRF token completed")
	}

	// The real one still works, so the refusals above are about the token and
	// not about the form being broken in some other way.
	if ok := f.claimsPost(t, cookie, csrfFrom(t, rec), handle); ok.Code != http.StatusSeeOther {
		t.Fatalf("the correct token was refused too (%d), so this test proves "+
			"nothing: %s", ok.Code, ok.Body)
	}
}

// §3.3.2 and §3.3.3: the redirect target, and never redirecting to a bad one.
func TestTheClaimsRedirectURIMustBeRegistered(t *testing.T) {
	f := newCIBAFixture(t)
	cookie := f.browserSession(t, f.userID)
	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)

	ask := func(uri string) *httptest.ResponseRecorder {
		q := url.Values{"client_id": {f.clientID}, "ticket": {ticket}}
		if uri != "" {
			q.Set("claims_redirect_uri", uri)
		}
		return f.claimsGet(t, cookie, q)
	}

	t.Run("a client with none registered cannot gather claims", func(t *testing.T) {
		// §3.3.2 makes pre-registration a SHOULD for every client and a MUST for
		// public ones. This server takes the SHOULD, because a server that accepts
		// an unregistered URI has an open redirect whose payload is a permission
		// ticket bound to whoever just signed in.
		rec := ask(claimsReturn)
		if rec.Code == http.StatusSeeOther {
			t.Fatal("redirected to an unregistered URI")
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", rec.Code)
		}
	})

	f.registerClaimsRedirect(t, f.clientID, claimsReturn)

	t.Run("an unregistered URI renders an error and never redirects", func(t *testing.T) {
		rec := ask("https://evil.test/steal")
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("redirected to %q; §3.3.3 says the server MUST NOT "+
				"automatically redirect to an invalid redirection URI", loc)
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", rec.Code)
		}
	})

	t.Run("a single registered URI may be omitted", func(t *testing.T) {
		if rec := ask(""); rec.Code != http.StatusOK {
			t.Errorf("code = %d; §3.3.2 makes the parameter OPTIONAL when exactly "+
				"one is registered", rec.Code)
		}
	})

	t.Run("with two registered it may not", func(t *testing.T) {
		f.registerClaimsRedirect(t, f.clientID, claimsReturn, "https://rp.test/other")
		if rec := ask(""); rec.Code == http.StatusOK {
			t.Error("the parameter was omitted with two URIs registered; §3.3.2 " +
				"makes it REQUIRED then, and guessing which one is meant is how a " +
				"requesting party ends up at the wrong endpoint")
		}
	})
}

// §3.3.3: state "MUST be present if and only if the client provided it".
func TestStateIsReturnedIfAndOnlyIfItWasSent(t *testing.T) {
	f := newCIBAFixture(t)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)

	gather := func(t *testing.T, q url.Values) url.Values {
		t.Helper()
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)
		q.Set("client_id", f.clientID)
		q.Set("ticket", ticket)
		q.Set("claims_redirect_uri", claimsReturn)
		rec := f.claimsGet(t, cookie, q)
		if rec.Code != http.StatusOK {
			t.Fatalf("confirmation page: %d %s", rec.Code, rec.Body)
		}
		out := f.claimsPost(t, cookie, csrfFrom(t, rec), handleFrom(t, rec.Body.String()))
		if out.Code != http.StatusSeeOther {
			t.Fatalf("confirmation: %d %s", out.Code, out.Body)
		}
		loc, err := url.Parse(out.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return loc.Query()
	}

	t.Run("absent stays absent", func(t *testing.T) {
		if got := gather(t, url.Values{}); got.Has("state") {
			t.Errorf("state=%q came back for a client that sent none; it has "+
				"nothing to match it against", got.Get("state"))
		}
	})
	t.Run("empty comes back empty", func(t *testing.T) {
		// The case that separates "record the value" from "record whether there
		// was one". A client that sent `state=` and gets nothing back cannot tell
		// this response from one to a different request.
		got := gather(t, url.Values{"state": {""}})
		if !got.Has("state") {
			t.Error("a client that sent an empty state got no state back")
		}
		if got.Get("state") != "" {
			t.Errorf("state = %q, want empty", got.Get("state"))
		}
	})
	t.Run("a value comes back verbatim", func(t *testing.T) {
		if got := gather(t, url.Values{"state": {"x y&z=1"}}); got.Get("state") != "x y&z=1" {
			t.Errorf("state = %q", got.Get("state"))
		}
	})
}

// A gathered ticket belongs to the client that gathered it.
func TestAGatheredTicketCannotBePresentedByAnotherClient(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)
	rec := f.claimsGet(t, cookie, url.Values{
		"client_id": {f.clientID}, "ticket": {ticket},
		"claims_redirect_uri": {claimsReturn},
	})
	out := f.claimsPost(t, cookie, csrfFrom(t, rec), handleFrom(t, rec.Body.String()))
	loc, _ := url.Parse(out.Header().Get("Location"))
	gathered := loc.Query().Get("ticket")

	code, body := f.exchange(t, f.otherClient, gathered, nil)
	if code == http.StatusOK {
		t.Fatal("a second client presented a ticket carrying somebody else's " +
			"proven identity and was given a token for it")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

// §3.3.1's pushed claims.
func TestPushedClaimTokens(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)

	// An ID token this server issued to this client, which is the only thing it
	// accepts -- see the audience test below for why.
	idToken := f.idTokenFor(t, f.userID, f.clientID, time.Hour)

	push := func(token, format string) (int, map[string]any) {
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)
		return f.exchange(t, f.clientID, ticket, url.Values{
			"claim_token": {token}, "claim_token_format": {format},
		})
	}

	t.Run("an ID token identifies the requesting party", func(t *testing.T) {
		code, body := push(idToken, uma.ClaimTokenFormatIDToken)
		if code != http.StatusOK {
			t.Fatalf("code = %d: %v", code, body)
		}
		rpt, _ := body["access_token"].(string)
		claims, err := tokens.VerifyAccessToken(f.srv.cfg.Keys, f.srv.cfg.Issuer, rpt)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != f.userID {
			t.Errorf("sub = %q, want the pushed subject %q", claims.Subject, f.userID)
		}
	})

	t.Run("base64url-wrapped is accepted too", func(t *testing.T) {
		// §3.3.1: "It MUST be base64url encoded unless specified otherwise by the
		// claim token format." Clients send both spellings, and no input is
		// validly both -- a compact JWS has dots and base64url has none.
		wrapped := base64.RawURLEncoding.EncodeToString([]byte(idToken))
		if strings.Contains(wrapped, ".") {
			t.Fatal("the wrapped value contains a dot, so this test does not " +
				"distinguish the two encodings")
		}
		if code, body := push(wrapped, uma.ClaimTokenFormatIDToken); code != http.StatusOK {
			t.Errorf("code = %d: %v", code, body)
		}
	})

	t.Run("a token issued to another client is refused, and not invited to retry", func(t *testing.T) {
		// The audience restriction §3.3.1 asks for, made concrete. Without it a
		// client could push an ID token picked up from a log, a referrer header,
		// or another application it also operates, and be treated as acting for
		// that person.
		other := f.idTokenFor(t, f.userID, f.otherClient, time.Hour)
		code, body := push(other, uma.ClaimTokenFormatIDToken)
		if code == http.StatusOK {
			t.Fatal("an ID token issued to a different client was accepted as " +
				"proof of who this client is acting for")
		}
		// invalid_grant, NOT need_info. This is not "we need more information":
		// it is a client presenting a credential it should not have, and a
		// need_info dresses that up as a recoverable mistake with a fresh ticket
		// attached.
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", body["error"])
		}
		if body["ticket"] != nil {
			t.Error("a token belonging to another client was answered with a " +
				"ticket, which invites the client to try again")
		}
	})

	// §3.3.6 defines need_info as covering exactly this: "a provided claim token
	// was invalid or expired, or had an incorrect format". So a recoverable
	// claim-token fault is answered with a fresh ticket and a hint, not with
	// invalid_grant -- which would tell the client its TICKET was bad when the
	// ticket was fine.
	t.Run("an expired token asks for a better one", func(t *testing.T) {
		// Expiry is enforced here even though VerifyIDTokenAudience deliberately
		// does not: that function exists for id_token_hint at logout, where an
		// expired token is the normal case. This grant is about who is asking NOW.
		stale := f.idTokenFor(t, f.userID, f.clientID, -time.Hour)
		code, body := push(stale, uma.ClaimTokenFormatIDToken)
		if code == http.StatusOK {
			t.Fatal("an expired ID token proved the requesting party's identity")
		}
		if body["error"] != "need_info" {
			t.Fatalf("error = %v, want need_info (§3.3.6 names an expired claim "+
				"token as exactly this case)", body["error"])
		}
		if body["ticket"] == nil {
			t.Error("need_info carried no ticket, so the client cannot act on it")
		}
		if body["required_claims"] == nil {
			t.Error("no required_claims, so the client is not told what would work")
		}
	})

	t.Run("an unsupported format asks for a better one, by name", func(t *testing.T) {
		code, body := push(idToken, "urn:ietf:params:oauth:token-type:saml2")
		if code == http.StatusOK {
			t.Fatal("an unrecognised claim_token_format was accepted")
		}
		if body["error"] != "need_info" {
			t.Errorf("error = %v, want need_info", body["error"])
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, uma.ClaimTokenFormatIDToken) {
			t.Errorf("the refusal does not name the format that would work: %q", desc)
		}
	})

	// §3.3.1: "If this parameter is used, it MUST appear together with the
	// claim_token_format parameter", and the converse.
	//
	// Both directions, and the assertions are on the MESSAGE, because the two
	// halves fail differently without the guard and only one of them fails at
	// all. A token with no format falls through to the format allow-list and is
	// refused with an empty format name -- same error code, useless text. A
	// format with no token falls through to "nothing was pushed" and the request
	// is treated as UNIDENTIFIED, so a client that believes it proved who it is
	// acting for gets need_info instead of an answer.
	t.Run("claim_token without a format is refused as a pair error", func(t *testing.T) {
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)
		code, out := f.exchange(t, f.clientID, ticket,
			url.Values{"claim_token": {idToken}})
		if code == http.StatusOK {
			t.Fatal("claim_token was accepted with no claim_token_format")
		}
		if out["error"] != "invalid_request" {
			t.Errorf("error = %v", out["error"])
		}
		desc, _ := out["error_description"].(string)
		if !strings.Contains(desc, "together") {
			t.Errorf("the refusal should say the two parameters must appear "+
				"together, not complain about an empty format; got %q", desc)
		}
	})

	t.Run("a format without a claim_token is not silently unidentified", func(t *testing.T) {
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)
		_, out := f.exchange(t, f.clientID, ticket,
			url.Values{"claim_token_format": {uma.ClaimTokenFormatIDToken}})
		if out["error"] == "need_info" {
			t.Fatal("a request naming a claim_token_format with no token was " +
				"treated as carrying no claims at all; the client believes it " +
				"pushed something")
		}
		if out["error"] != "invalid_request" {
			t.Errorf("error = %v, want invalid_request", out["error"])
		}
	})
}

// idTokenFor mints an ID token for a subject and audience.
func (f *cibaFixture) idTokenFor(t *testing.T, sub, aud string, life time.Duration) string {
	t.Helper()
	key, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := tokens.NewSigner(key).SignIDToken(tokens.IDTokenClaims{
		Issuer: f.srv.cfg.Issuer, Subject: sub, Audience: aud,
		IssuedAt: now.Add(-time.Minute).Unix(), Expiry: now.Add(life).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Two identities for one request is refused rather than resolved by precedence.
func TestAGatheredTicketPlusAPushedTokenIsRefused(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)

	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)
	rec := f.claimsGet(t, cookie, url.Values{
		"client_id": {f.clientID}, "ticket": {ticket},
		"claims_redirect_uri": {claimsReturn},
	})
	out := f.claimsPost(t, cookie, csrfFrom(t, rec), handleFrom(t, rec.Body.String()))
	loc, _ := url.Parse(out.Header().Get("Location"))
	gathered := loc.Query().Get("ticket")

	code, body := f.exchange(t, f.clientID, gathered, url.Values{
		"claim_token":        {f.idTokenFor(t, f.otherUserID, f.clientID, time.Hour)},
		"claim_token_format": {uma.ClaimTokenFormatIDToken},
	})
	if code == http.StatusOK {
		t.Fatal("a request asserting two different requesting parties was granted; " +
			"whichever one was used, the other was presented and silently discarded")
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
}

// §3.3.6's three refusals, and the rule that chooses between them.
func TestTheRefusalDependsOnWhetherAnybodyIsIdentified(t *testing.T) {
	f := newCIBAFixture(t)
	// A model in which NOBODY holds the relation, so every request is refused
	// and only the SHAPE of the refusal varies.
	f.allowUserOn(t, "document", "42", "viewer", "nobody@example.test")

	ask := func(extra url.Values) (int, map[string]any) {
		_, body := f.permission(t, f.clientID, f.secret, onePermission)
		ticket, _ := body["ticket"].(string)
		return f.exchange(t, f.clientID, ticket, extra)
	}
	identified := url.Values{
		"claim_token":        {f.idTokenFor(t, f.userID, f.clientID, time.Hour)},
		"claim_token_format": {uma.ClaimTokenFormatIDToken},
	}

	// The machine-to-machine case, which is what this grant did for everybody
	// before claims gathering existed. This client has no claims redirection
	// URIs, so nobody has said it acts for people -- and §3.3.6 itself notes
	// that a redirect_user hint is useless when "the requesting party is not an
	// end-user".
	t.Run("unidentified, and unable to identify, is request_denied", func(t *testing.T) {
		_, body := ask(nil)
		if body["error"] != "request_denied" {
			t.Fatalf("error = %v, want request_denied: this client cannot gather "+
				"claims, so a need_info would invite it to redirect a user that "+
				"does not exist", body["error"])
		}
	})

	t.Run("unidentified, but able to identify, is need_info", func(t *testing.T) {
		f.registerClaimsRedirect(t, f.clientID, claimsReturn)
		t.Cleanup(func() { f.registerClaimsRedirect(t, f.clientID) })
		_, body := ask(nil)
		if body["error"] != "need_info" {
			t.Fatalf("error = %v, want need_info: this client is registered to "+
				"gather claims, so identifying the requesting party could change "+
				"the answer", body["error"])
		}
	})

	t.Run("identified with no intervention is request_denied", func(t *testing.T) {
		_, body := ask(identified)
		if body["error"] != "request_denied" {
			t.Fatalf("error = %v, want request_denied", body["error"])
		}
		// FINAL, so no ticket: handing one back invites a retry that cannot
		// possibly produce a different answer.
		if body["ticket"] != nil {
			t.Error("request_denied carried a ticket, which invites a pointless retry")
		}
	})

	t.Run("identified with intervention is request_submitted", func(t *testing.T) {
		if err := store.SetUMASettings(context.Background(), f.pool, f.orgID,
			store.UMASettings{OwnerIntervention: true, PollInterval: 30 * time.Second}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(),
				`DELETE FROM core.uma_settings WHERE org_id = $1::uuid`, f.orgID)
			_, _ = f.pool.Exec(context.Background(),
				`DELETE FROM core.uma_pending_requests WHERE org_id = $1::uuid`, f.orgID)
		})

		code, body := ask(identified)
		if code != http.StatusForbidden || body["error"] != "request_submitted" {
			t.Fatalf("code=%d error=%v, want 403 request_submitted", code, body["error"])
		}
		if body["ticket"] == nil {
			t.Error("request_submitted carried no ticket, which §3.3.6 makes REQUIRED")
		}
		if body["interval"] == nil {
			t.Error("no interval; the client has nothing to pace its polling by")
		}

		// And somebody can actually see it. A submitted request nobody can find
		// is the same as a denial that lied about being reconsiderable.
		pending, err := store.ListPendingRequests(context.Background(), f.pool, f.orgID)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) != 1 {
			t.Fatalf("%d pending requests recorded, want 1", len(pending))
		}
		if pending[0].RequestingPartyEmail != f.email {
			t.Errorf("the pending request names %q, want %q",
				pending[0].RequestingPartyEmail, f.email)
		}

		// Polling again must find the SAME decision rather than enqueue another.
		if _, body := ask(identified); body["error"] != "request_submitted" {
			t.Fatalf("the second poll got %v", body["error"])
		}
		again, err := store.ListPendingRequests(context.Background(), f.pool, f.orgID)
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != 1 {
			t.Errorf("polling enqueued %d requests; a client polling every thirty "+
				"seconds would bury the resource owner", len(again))
		}
	})
}

// The encoding discrimination, unit-tested because it is the one place a
// permissive parser would be a real hazard.
func TestClaimTokenEncodingIsDiscriminatedNotGuessed(t *testing.T) {
	const jwt = "aaa.bbb.ccc"
	if got, err := uma.DecodeClaimToken(jwt); err != nil || got != jwt {
		t.Errorf("a compact JWT was not passed through: %q %v", got, err)
	}
	wrapped := base64.RawURLEncoding.EncodeToString([]byte(jwt))
	if got, err := uma.DecodeClaimToken(wrapped); err != nil || got != jwt {
		t.Errorf("a base64url-wrapped JWT did not decode: %q %v", got, err)
	}
	for _, bad := range []string{"", "   ", "notbase64!!", "YWJj"} {
		if _, err := uma.DecodeClaimToken(bad); err == nil {
			t.Errorf("%q was accepted as a claim token", bad)
		}
	}
}

// The discovery document §2 requires, at the path §2 requires.
func TestUMADiscoveryDeclaresTheClaimsInteractionEndpoint(t *testing.T) {
	f := newCIBAFixture(t)
	rec := httptest.NewRecorder()
	f.srv.handleUMAMetadata(rec,
		httptest.NewRequest(http.MethodGet, "/.well-known/uma2-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got, _ := doc["claims_interaction_endpoint"].(string)
	want := strings.TrimRight(f.srv.cfg.Issuer, "/") + claimsInteractionPath
	if got != want {
		t.Errorf("claims_interaction_endpoint = %q, want %q", got, want)
	}
	// §2 says the document conforms to RFC 8414, so the ordinary metadata has to
	// be there too -- a document carrying only UMA's additions is not one.
	if doc["issuer"] != f.srv.cfg.Issuer {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["token_endpoint"] == nil {
		t.Error("no token_endpoint; this is not an RFC 8414 document")
	}
	if doc["permission_endpoint"] == nil {
		t.Error("no permission_endpoint")
	}
}
