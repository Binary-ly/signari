package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// gather takes a person through the claims interaction and answers the successor
// ticket, with the box ticked or not.
func (f *cibaFixture) gather(t *testing.T, cookie string, remember bool) string {
	t.Helper()
	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)
	page := f.claimsGet(t, cookie, url.Values{"client_id": {f.clientID}, "ticket": {ticket},
		"claims_redirect_uri": {claimsReturn}})
	form := url.Values{"handle": {handleFrom(t, page.Body.String())}, csrfFormField: {csrfFrom(t, page)}}
	if remember {
		form.Set("remember", "1")
	}
	req := httptest.NewRequest(http.MethodPost, "/uma2/claims", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfFrom(t, page)})
	rec := httptest.NewRecorder()
	f.srv.handleUMAClaims(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("ticket") == "" {
		t.Fatalf("no ticket came back (%d): %q", rec.Code, rec.Header().Get("Location"))
	}
	return loc.Query().Get("ticket")
}

func (f *cibaFixture) rawTicket(t *testing.T) string {
	t.Helper()
	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)
	return ticket
}

// The whole of it: a person asked once, who ticks the box, and a client that then
// has a token standing for them. Without the tick there is none, which is §6.2's
// recommendation and the difference between remembering somebody and keeping them.
func TestAPersonIsRememberedOnlyIfTheySaidSo(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)

	code, body := f.exchange(t, f.clientID, f.gather(t, cookie, false), nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	if body["pct"] != nil {
		t.Errorf("a PCT was issued to somebody who did not ask for one: %v", body)
	}

	code, body = f.exchange(t, f.clientID, f.gather(t, cookie, true), nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	pct, _ := body["pct"].(string)
	if pct == "" {
		t.Fatalf("no PCT for somebody who asked for one: %v", body)
	}
	var stored []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT token_hash FROM core.uma_persisted_claims
		WHERE user_id = $1::uuid`, f.userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == pct {
		t.Error("§5.2: the token is kept in the clear")
	}

	// A fresh ticket, nobody signed in: the PCT is who is asking.
	code, body = f.exchange(t, f.clientID, f.rawTicket(t), url.Values{"pct": {pct}})
	if code != http.StatusOK {
		t.Fatalf("the PCT was refused: %d %v", code, body)
	}
	if sub := claimsOfJWT(t, body["access_token"].(string))["sub"]; sub != f.userID {
		t.Errorf("the RPT is about %v", sub)
	}
	if body["pct"] != nil {
		t.Errorf("a PCT presented was answered with another: %v", body)
	}
}

// A person remembered by an application can see it on their connected applications
// page, with how long it goes on acting for them, and removing it there ends the
// token: they had no way to before but signing out everywhere (11.12).
func TestAPersonSeesAndEndsWhatRemembersThem(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)
	_, body := f.exchange(t, f.clientID, f.gather(t, cookie, true), nil)
	pct, _ := body["pct"].(string)
	if pct == "" {
		t.Fatalf("no PCT: %v", body)
	}

	get := httptest.NewRequest(http.MethodGet, "/account/connected", nil)
	get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	page := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(page, get)
	html := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(html, `value="`+f.clientID+`"`) ||
		!strings.Contains(html, "while you are signed out") {
		t.Fatalf("the page (%d) does not show the application that remembers them:\n%s", page.Code, html)
	}

	form := url.Values{"client_id": {f.clientID}, csrfFormField: {csrfFrom(t, page)}}
	post := httptest.NewRequest(http.MethodPost, "/account/connected/revoke", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	post.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfFrom(t, page)})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, post)
	if rec.Code >= 400 {
		t.Fatalf("removing it answered %d: %s", rec.Code, rec.Body.String())
	}
	code, body := f.exchange(t, f.clientID, f.rawTicket(t), url.Values{"pct": {pct}})
	if code == http.StatusOK || body["error"] != "invalid_grant" {
		t.Errorf("the PCT of an application they removed still worked: %d %v", code, body)
	}
	apps, err := store.ConnectedApps(context.Background(), f.pool, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.ClientID == f.clientID {
			t.Errorf("it is still listed: %+v", a)
		}
	}
}

// §5.2: "The authorization server MUST maintain the binding between the PCT and the
// client to which it was issued." And what it stands for is read when it is used,
// because a token is no reason to take somebody's word about a closed account.
func TestAPersistedClaimsTokenHoldsOnlyWhileItShould(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	f.registerClaimsRedirect(t, f.clientID, claimsReturn)
	cookie := f.browserSession(t, f.userID)
	ctx := context.Background()
	mint := func() string {
		t.Helper()
		_, body := f.exchange(t, f.clientID, f.gather(t, cookie, true), nil)
		pct, _ := body["pct"].(string)
		if pct == "" {
			t.Fatalf("no PCT: %v", body)
		}
		return pct
	}
	refused := func(what, pct string) {
		t.Helper()
		code, body := f.exchange(t, f.clientID, f.rawTicket(t), url.Values{"pct": {pct}})
		if code == http.StatusOK || body["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", what, code, body)
		}
	}

	refused("nothing like one", "not-a-token")

	pct := mint()
	if _, err := store.PersonOfPersistedClaims(ctx, f.pool, pct, f.otherClient); err == nil {
		t.Error("another client's PCT was taken")
	}

	// Past its month.
	if _, err := f.pool.Exec(ctx, `UPDATE core.uma_persisted_claims SET expires_at = now() - interval '1 second'
		WHERE token_hash = $1`, store.HashToken(pct)); err != nil {
		t.Fatal(err)
	}
	refused("expired", pct)

	// Its person deactivated, the token untouched.
	pct = mint()
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	refused("a closed account", pct)
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}

	// Disagreeing with who else this request says is asking: gathered as one person
	// and remembered as another is two identities and this server will not pick.
	ticket := f.gather(t, f.browserSession(t, f.otherUserID), false)
	code, body := f.exchange(t, f.clientID, ticket, url.Values{"pct": {pct}})
	if code == http.StatusOK || body["error"] != "invalid_grant" {
		t.Errorf("a PCT about somebody else: %d %v", code, body)
	}

	// §3.7: the client can end one at the revocation endpoint.
	form := url.Values{"token": {pct}, "token_type_hint": {"pct"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.otherClient, f.otherSecret)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if _, err := store.PersonOfPersistedClaims(ctx, f.pool, pct, f.clientID); err != nil {
		t.Errorf("another client revoked it: %d %v", rec.Code, err)
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.clientID, f.secret)
	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revocation answered %d: %s", rec.Code, rec.Body.String())
	}
	refused("revoked", pct)

	// Signed out everywhere ends what speaks for them with no session behind it.
	pct = mint()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TerminateSessions(ctx, tx, "", f.userID, store.ReasonAdminRevoke); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	refused("signed out everywhere", pct)
}
