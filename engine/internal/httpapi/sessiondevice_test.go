package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"signari.dev/engine/internal/keys"
)

// A session records the browser that opened it (2.28). Both columns existed
// from the start and nothing wrote either, so a person with two browsers was
// shown two identical rows and could not tell which to end, and the admin list
// reported no address for anybody.
func TestTwoBrowsersShowAsTwoSessions(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	root, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)

	signIn := func(ua, ip string) string {
		t.Helper()
		peer := ip + ":443"
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		get.RemoteAddr = peer
		get.Header.Set("User-Agent", ua)
		grec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(grec, get)
		var csrfCookie string
		for _, c := range grec.Result().Cookies() {
			if c.Name == CSRFCookieName {
				csrfCookie = c.Value
			}
		}
		const marker = `name="` + csrfFormField + `" value="`
		body := grec.Body.String()
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("the sign-in form carries no CSRF field: %d", grec.Code)
		}
		rest := body[i+len(marker):]
		form := url.Values{"username": {f.email}, "password": {signInTestPassword},
			csrfFormField: {rest[:strings.Index(rest, `"`)]}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", ua)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		for _, c := range rec.Result().Cookies() {
			if c.Name == SessionCookieName {
				return c.Value
			}
		}
		t.Fatalf("signing in from %s gave %d and no session cookie: %.200s", ua, rec.Code, rec.Body.String())
		return ""
	}

	const firefox = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:131.0) Gecko/20100101 Firefox/131.0"
	const phone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148 Safari/604.1"
	cookie := signIn(firefox, "198.51.100.7")
	signIn(phone, "203.0.113.9")

	type row struct {
		ua   string
		hash []byte
	}
	read := func() []row {
		t.Helper()
		rows, err := f.pool.Query(ctx, `SELECT coalesce(user_agent, ''), ip_hash FROM core.sessions
			WHERE user_id = $1::uuid AND revoked_at IS NULL ORDER BY created_at`, f.userID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.ua, &r.hash); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	got := read()
	if len(got) != 2 {
		t.Fatalf("%d live sessions, want 2", len(got))
	}
	if got[0].ua != firefox || got[1].ua != phone {
		t.Errorf("the sessions recorded user agents %q and %q, want the two browsers'", got[0].ua, got[1].ua)
	}
	if string(got[0].hash) != string(root.AddressHash("198.51.100.7")) ||
		string(got[1].hash) != string(root.AddressHash("203.0.113.9")) {
		t.Errorf("the sessions' address hashes are not the keyed hashes of their addresses")
	}
	plain := sha256.Sum256([]byte("198.51.100.7"))
	if string(got[0].hash) == string(plain[:]) {
		t.Error("the address hash is an unkeyed SHA-256, which a copy of the database reverses " +
			"by trying every IPv4 address")
	}

	// What the person sees: both browsers, told apart.
	req := httptest.NewRequest(http.MethodGet, "/account/sessions", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	page := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(page, "Firefox/131.0") || !strings.Contains(page, "iPhone") {
		t.Errorf("the sessions page (%d) does not show both browsers", rec.Code)
	}

	// A header the client wrote is bounded and printable before it is kept.
	signIn("Evil\x00Agent\r\n"+strings.Repeat("é", 400), "192.0.2.1")
	got = read()
	last := got[len(got)-1].ua
	if len(last) > maxSessionUserAgent || !utf8.ValidString(last) || strings.ContainsAny(last, "\x00\r\n") {
		t.Errorf("a hostile user agent was kept as %d bytes, valid UTF-8 %v, with control "+
			"characters %v", len(last), utf8.ValidString(last), strings.ContainsAny(last, "\x00\r\n"))
	}
	if !strings.HasPrefix(last, "EvilAgent") {
		t.Errorf("the kept user agent lost its legible part: %.40q", last)
	}
}
