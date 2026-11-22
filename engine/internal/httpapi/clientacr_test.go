package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// A client's floor, through the writer every surface uses, at every place a
// person's session gives the client tokens. A relying party could ask for
// multi-factor; nothing let an operator require it of one that does not ask.

func setClientFloor(t *testing.T, pool *pgxpool.Pool, clientID, floor string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetClientSettings(ctx, tx, clientID, store.ClientSettings{MinimumACR: &floor}); err != nil {
		t.Fatalf("setting the floor to %s: %v", floor, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// authorizePlain asks for a code with no acr_values at all.
func (f *signInFixture) authorizePlain(t *testing.T, sessionCookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+f.plainAuthz(), nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionCookie})
	rec := httptest.NewRecorder()
	f.srv.handleAuthorize(rec, req)
	return rec
}

func (f *signInFixture) plainAuthz() string {
	return url.Values{
		"client_id": {f.clientID}, "scope": {"openid"}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()
}

func TestAClientFloorHoldsASessionToMultiFactor(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	// First-party, so a sufficient session is answered with a code rather
	// than the consent screen.
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET first_party = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	cookie := f.signInAndReturnCookie(t)
	coded := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusSeeOther &&
			strings.HasPrefix(rec.Header().Get("Location"), "https://rp.test/cb?code=")
	}

	if rec := f.authorizePlain(t, cookie); !coded(rec) {
		t.Fatalf("with no floor a password session got %d %q, want a code", rec.Code, rec.Header().Get("Location"))
	}

	// Nothing enrolled: the floor cannot be reached, said to the client.
	setClientFloor(t, f.pool, f.clientID, "2")
	rec := f.authorizePlain(t, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "error=unmet_authentication_requirements") {
		t.Fatalf("a floor nobody can reach answered %d %q, want unmet_authentication_requirements",
			rec.Code, rec.Header().Get("Location"))
	}

	// A factor enrolled: the person is asked to sign in again, not given a code.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	rec = f.authorizePlain(t, cookie)
	if coded(rec) || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("a password session for a floor-2 client got %d %q, want the sign-in form",
			rec.Code, rec.Header().Get("Location"))
	}

	// A multi-factor session meets it.
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['pwd','otp','mfa']
		WHERE cookie_hash = $1`, store.HashToken(cookie)); err != nil {
		t.Fatal(err)
	}
	if rec := f.authorizePlain(t, cookie); !coded(rec) {
		t.Errorf("a multi-factor session for a floor-2 client got %d %q, want a code",
			rec.Code, rec.Header().Get("Location"))
	}

	// The floor is a floor: a request asking for less does not lower it.
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['pwd']
		WHERE cookie_hash = $1`, store.HashToken(cookie)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+f.plainAuthz()+"&acr_values=1", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	asked := httptest.NewRecorder()
	f.srv.handleAuthorize(asked, req)
	if coded(asked) {
		t.Error("acr_values=1 lowered the client's floor of 2")
	}
}

// Under a flow that demands a factor only when the client requires one, the
// floor is what it reads: the password is not enough for that client and is
// for others.
func TestAClientFloorIsWhatClientRequiresMFAReads(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	cred := j.register(t, session)
	j.applyFlow(t, `
version: 1
flows:
  - name: on-request
    on: authentication
    stages:
      - password
      - {stage: mfa, when: client_requires_mfa}
      - session
    tests:
      - name: not asked
        given: {}
        expect: [password, session]
      - name: asked
        given: {client_requires_mfa: true}
        expect: [password, mfa, session]
`)

	if step := j.passwordStep(t, j.plainAuthz()); step.pending != nil ||
		cookieFrom(step.page, SessionCookieName) == nil {
		t.Fatalf("with no floor the flow asked for a factor: %d", step.page.Code)
	}

	setClientFloor(t, j.pool, j.clientID, "2")
	step := j.passwordStep(t, j.plainAuthz())
	if step.pending == nil || cookieFrom(step.page, SessionCookieName) != nil {
		t.Fatalf("for a floor-2 client the flow did not ask for a factor: %d", step.page.Code)
	}
	rec := step.withKey(t, cred)
	if _, acr, ok := j.sessionFor(t, rec); !ok || acr != oauth.ACRMultiFactor {
		t.Errorf("the key after the password gave session %v acr %q", ok, acr)
	}
}

func TestAClientFloorReachesRefreshTokensAlreadyIssued(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	mint := func() string {
		raw, hash, err := store.NewCode()
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		family, err := store.NewRefreshFamily(ctx, tx, f.orgID, f.clientID, f.userID, f.sid, nil, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.IssueRefreshToken(ctx, tx, family, hash, []string{"openid", "offline_access"},
			nil, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	refresh := func(raw string) (int, map[string]any) {
		return f.post(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw},
			"client_id": {f.clientID}})
	}

	if status, body := refresh(mint()); status != http.StatusOK {
		t.Fatalf("with no floor a refresh failed: %d %v", status, body["error_description"])
	}

	setClientFloor(t, f.pool, f.clientID, "2")
	raw := mint()
	status, body := refresh(raw)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("a refresh token from a password session refreshed under a floor of 2: %d", status)
	}
	// Refused, not spent: once the session meets the floor the same token works.
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['pwd','otp','mfa'] WHERE sid = $1`,
		f.sid); err != nil {
		t.Fatal(err)
	}
	if status, body := refresh(raw); status != http.StatusOK {
		t.Errorf("the refused token did not refresh once the session met the floor: %d %v",
			status, body["error_description"])
	}

	// A floor above multi-factor (4.15) reaches refresh tokens too: this
	// check once ran only for a floor of exactly 2.
	setClientFloor(t, f.pool, f.clientID, "3")
	if status, _ := refresh(mint()); status != http.StatusBadRequest {
		t.Errorf("a refresh token from a password-and-app session refreshed under a floor of 3: %d", status)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['user','swk','mfa'] WHERE sid = $1`,
		f.sid); err != nil {
		t.Fatal(err)
	}
	if status, body := refresh(mint()); status != http.StatusOK {
		t.Errorf("a passkey session did not refresh under a floor of 3: %d %v", status, body["error_description"])
	}
}

func TestAClientFloorHoldsDeviceAndBackchannelApprovals(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	ctx := context.Background()
	setClientFloor(t, f.pool, f.clientID, "2")

	userCode, err := oauth.NewUserCode()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.CreateDeviceAuthorization(ctx, f.pool, f.orgID, f.clientID, "openid", nil,
		store.HashToken("dc-"+userCode+fmt.Sprint(time.Now().UnixNano())), store.HashToken(userCode),
		5, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rec := f.formPost(t, cookie, "/device", "/device",
		url.Values{"user_code": {userCode}, "decision": {"approve"}})
	if s := f.requestStatus(t, device); s != "pending" {
		t.Errorf("a password session approved a device for a floor-2 client: the request is %q", s)
	}
	if !strings.Contains(rec.Body.String(), "requires a second factor") {
		t.Error("the person approving the device was not told a second factor is needed")
	}

	backchannel, err := store.CreateBackchannelAuthentication(ctx, f.pool, f.orgID, f.clientID, f.userID,
		"openid", "", nil, store.HashToken(fmt.Sprint("ar-", time.Now().UnixNano())), 5, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rec = f.formPost(t, cookie, "/account/requests", "/account/requests",
		url.Values{"id": {backchannel}, "decision": {"approve"}})
	if s := f.requestStatus(t, backchannel); s != "pending" {
		t.Errorf("a password session approved a backchannel request for a floor-2 client: %q", s)
	}
	if !strings.Contains(rec.Body.String(), "requires a second factor") {
		t.Error("the person approving the backchannel request was not told a second factor is needed")
	}

	// Both go through once the session is multi-factor.
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['pwd','otp','mfa']
		WHERE cookie_hash = $1`, store.HashToken(cookie)); err != nil {
		t.Fatal(err)
	}
	f.formPost(t, cookie, "/device", "/device", url.Values{"user_code": {userCode}, "decision": {"approve"}})
	if s := f.requestStatus(t, device); s != "approved" {
		t.Errorf("a multi-factor session left the device request %q", s)
	}
	f.formPost(t, cookie, "/account/requests", "/account/requests",
		url.Values{"id": {backchannel}, "decision": {"approve"}})
	if s := f.requestStatus(t, backchannel); s != "approved" {
		t.Errorf("a multi-factor session left the backchannel request %q", s)
	}
}

func TestAClientFloorOutsideTheLadderIsRefused(t *testing.T) {
	for _, bad := range []string{"0", "5", "", "urn:mace:incommon:iap:silver"} {
		v := bad
		if err := store.CheckClientSettings(store.ClientSettings{MinimumACR: &v}); err == nil {
			t.Errorf("a floor of %q was accepted", bad)
		}
	}
}
