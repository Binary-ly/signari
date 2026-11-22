package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A grant of offline_access outlives the session it was given in (5.10), within
// its own lifetime, and ends with every session the person has.

// endSessionHoursAgo moves the fixture's session back so it expired hours ago,
// as thirteen hours of waiting would have.
func (f *tokenFixture) endSessionHoursAgo(t *testing.T, hours int) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.sessions SET auth_time = auth_time - make_interval(hours => $2),
		       created_at = created_at - make_interval(hours => $2),
		       last_seen_at = last_seen_at - make_interval(hours => $2),
		       not_after = not_after - make_interval(hours => $2),
		       absolute_not_after = absolute_not_after - make_interval(hours => $2)
		 WHERE sid = $1`, f.sid, hours); err != nil {
		t.Fatal(err)
	}
}

func (f *tokenFixture) setOfflineLifetime(t *testing.T, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, err := store.SetOfflineLifetime(ctx, tx, f.orgID, d); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f *tokenFixture) userinfo(t *testing.T, accessToken string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code
}

func TestARefreshThirteenHoursOnWorksForAnOfflineGrantAndNotAnOnlineOne(t *testing.T) {
	t.Run("offline", func(t *testing.T) {
		f := newTokenFixture(t)
		rt := f.firstRefreshToken(t)
		var days float64
		if err := f.pool.QueryRow(context.Background(), `SELECT extract(epoch FROM offline_not_after - now()) / 86400
			FROM core.refresh_token_families WHERE sid = $1`, f.sid).Scan(&days); err != nil || days < 29 {
			t.Fatalf("the grant lasts %.1f days offline (%v), want the organisation's thirty", days, err)
		}
		f.endSessionHoursAgo(t, 13)
		status, body := f.refreshWith(t, rt, "")
		if status != http.StatusOK {
			t.Fatalf("an offline grant thirteen hours on, its session long expired: %d %v", status, body)
		}
		at, _ := body["access_token"].(string)
		if code := f.userinfo(t, at); code != http.StatusOK {
			t.Errorf("userinfo refused the access token the offline grant minted: %d", code)
		}
	})
	t.Run("online", func(t *testing.T) {
		f := newTokenFixture(t)
		f.setOfflineLifetime(t, 0)
		rt := f.firstRefreshToken(t)
		f.endSessionHoursAgo(t, 13)
		if status, _ := f.refreshWith(t, rt, ""); status == http.StatusOK {
			t.Fatal("a grant bound to its session was refreshed thirteen hours on, after the session expired")
		}
	})
}

// A logout ends one session and leaves the grant; ending every session the
// person has -- a password change here -- ends it.
func TestAnOfflineGrantEndsWithEverySessionNotWithOne(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	rt := f.firstRefreshToken(t)
	end := func(sid, userID string, reason store.TerminationReason) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.TerminateSessions(ctx, tx, sid, userID, reason); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	end(f.sid, "", store.ReasonLogout)
	status, body := f.refreshWith(t, rt, "")
	if status != http.StatusOK {
		t.Fatalf("a logout ended the offline grant: %d %v", status, body)
	}
	rt, _ = body["refresh_token"].(string)
	end("", f.userID, store.ReasonPasswordChange)
	if status, _ := f.refreshWith(t, rt, ""); status == http.StatusOK {
		t.Fatal("an offline grant survived a password change, which ends every session")
	}
}

// The ended session an offline grant lives on is kept by the janitor while the
// grant lives, and goes once it ends; a shorter offline lifetime reaches live
// grants; an impersonation's grant is never offline.
func TestAnOfflineGrantsSessionIsKeptAndItsLifetimeTightens(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	f.firstRefreshToken(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET revoked_at = now() - interval '400 days',
		revocation_reason = 'logout', not_after = now() - interval '400 days', absolute_not_after = now() - interval '400 days'
		WHERE sid = $1`, f.sid); err != nil {
		t.Fatal(err)
	}
	sessionKept := func() bool {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.PurgeRetained(ctx, tx, store.Retention{Sessions: time.Hour, Families: 1000 * time.Hour,
			Delivered: 1000 * time.Hour, Received: 1000 * time.Hour}, 100000); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.sessions WHERE sid = $1`, f.sid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !sessionKept() {
		t.Fatal("the janitor deleted the session a live offline grant was given in, and the grant with it")
	}

	f.setOfflineLifetime(t, time.Hour)
	var left float64
	if err := f.pool.QueryRow(ctx, `SELECT extract(epoch FROM offline_not_after - now()) FROM core.refresh_token_families
		WHERE sid = $1`, f.sid).Scan(&left); err != nil || left > 3600 {
		t.Errorf("a one-hour offline lifetime left the live grant %.0fs (%v)", left, err)
	}
	f.setOfflineLifetime(t, 0)
	if sessionKept() {
		t.Error("the session was kept after its offline grant ended")
	}

	g := newTokenFixture(t)
	if _, err := g.pool.Exec(ctx, `UPDATE core.sessions SET impersonator_id = $2::uuid WHERE sid = $1`,
		g.sid, g.userID); err != nil {
		t.Fatal(err)
	}
	g.firstRefreshToken(t)
	var offline bool
	if err := g.pool.QueryRow(ctx, `SELECT offline_not_after IS NOT NULL FROM core.refresh_token_families
		WHERE sid = $1`, g.sid).Scan(&offline); err != nil || offline {
		t.Errorf("a grant made in an impersonation is offline (%v): support access would outlive the episode", err)
	}
}

// The person sees, on their connected applications, until when each one can act
// for them while they are signed out, and can remove it. With no consent on
// record, as for a first-party client that skips the consent screen: the live
// check found such an application missing from the page entirely.
func TestConnectedApplicationsSayHowLongOfflineAccessLasts(t *testing.T) {
	f, cookie := enrolFixture(t)
	ctx := context.Background()
	sid, _, err := store.ResolveSessionCookie(ctx, f.pool, store.HashToken(cookie), "")
	if err != nil || sid == "" {
		t.Fatalf("the fixture's session: %v", err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.NewRefreshFamily(ctx, tx, f.orgID, f.clientID, f.userID, sid, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(store.DefaultOfflineLifetime).Format("2 January 2006")
	// The date arrives wrapped in bidirectional isolates, as every value does.
	page := accountGET(f, cookie, "/account/connected").Body.String()
	if !strings.Contains(page, "while you are signed out, until") || !strings.Contains(page, until) {
		if i := strings.Index(page, "<h1"); i >= 0 {
			page = page[i:]
		}
		t.Errorf("the page does not say the application can act offline until %s: %s", until, truncate(page, 900))
	}
	f.formPost(t, cookie, "/account/connected", "/account/connected/revoke", url.Values{"client_id": {f.clientID}})
	var live int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.refresh_token_families
		WHERE user_id = $1::uuid AND client_id = $2 AND revoked_at IS NULL`, f.userID, f.clientID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("removing the application left %d live grant(s)", live)
	}
}

// tokenSessionChecksExempt are the places that ask whether a session is live
// for a cookie rather than for a token, which an offline grant has no part in.
var tokenSessionChecksExempt = map[string]string{
	"rac.go":         "a remote-access connection is opened from the browser's session cookie",
	"forwardauth.go": "the proxy cookie stands for a browser session",
}

// Every place a token's session is checked asks TokenSessionLive, so a token an
// offline grant minted is not refused the moment its person signs out.
func TestEveryTokenSessionCheckHonoursOfflineGrants(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`store\.(?:Is)?SessionLive\(`)
	var bad []string
	for _, e := range files {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if call.Match(src) && tokenSessionChecksExempt[name] == "" {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		t.Errorf("%s check a session with SessionLive: if it is a token's session, use TokenSessionLive "+
			"with the token's grant, or an offline grant's tokens are refused once the person signs out; "+
			"if it is a cookie's, add the file to tokenSessionChecksExempt saying so", strings.Join(bad, ", "))
	}
}
