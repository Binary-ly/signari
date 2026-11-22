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

// A sign-in from a new device is told to the person (5.21).

const (
	uaFirefoxWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
	uaFirefoxNewer   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	uaSafariIPhone   = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	uaChromeMac      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	uaEdgeWindows    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
	uaChromeAndroid  = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
	uaChromeIOS      = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1"
)

func TestADeviceIsABrowserOnASystem(t *testing.T) {
	for ua, want := range map[string]string{
		uaFirefoxWindows: "Firefox on Windows",
		uaFirefoxNewer:   "Firefox on Windows",
		uaSafariIPhone:   "Safari on iOS",
		uaChromeMac:      "Chrome on macOS",
		uaEdgeWindows:    "Edge on Windows",
		uaChromeAndroid:  "Chrome on Android",
		uaChromeIOS:      "Chrome on iOS",
		"curl/8.7.1":     "",
		"":               "",
	} {
		if got := deviceFamily(ua); got != want {
			t.Errorf("deviceFamily(%.40q) = %q, want %q", ua, got, want)
		}
	}
}

func TestASignInFromANewDeviceIsToldToThePerson(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, f.userID)
	})
	notices := func() []string {
		t.Helper()
		rows, err := f.pool.Query(ctx, `SELECT payload->>'device' FROM core.outbox WHERE topic = $1
			AND payload->>'user_id' = $2 AND payload->>'notice' = $3 ORDER BY id`,
			store.AccountNoticeTopic, f.userID, store.NoticeNewDevice)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var d string
			_ = rows.Scan(&d)
			out = append(out, d)
		}
		return out
	}
	signIn := func(ua string, cookies ...*http.Cookie) {
		t.Helper()
		clearSignInBucket(t, f.pool)
		b := newTestBrowser(t, f.srv.Routes())
		for _, c := range cookies {
			b.jar[c.Name] = c
		}
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		get.Header.Set("User-Agent", ua)
		page := b.do(get)
		m := csrfValue.FindStringSubmatch(page.Body.String())
		form := url.Values{"username": {f.email}, "password": {signInTestPassword}, csrfFormField: {m[1]}}
		post := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		post.Header.Set("User-Agent", ua)
		b.do(post)
		if b.value(SessionCookieName) == "" {
			t.Fatalf("signing in as %q did not", ua)
		}
	}

	signIn(uaFirefoxWindows)
	if n := notices(); len(n) != 0 {
		t.Errorf("the first sign-in, with nothing to differ from, was told: %v", n)
	}
	signIn(uaFirefoxNewer)
	if n := notices(); len(n) != 0 {
		t.Errorf("a browser update was told as a new device: %v", n)
	}
	signIn(uaSafariIPhone)
	if n := notices(); len(n) != 1 || n[0] != "Safari on iOS" {
		t.Fatalf("a sign-in from a new device: told %v, want [Safari on iOS]", n)
	}

	// A device the person chose to remember is not new.
	if _, err := f.pool.Exec(ctx, `UPDATE core.organizations SET remember_device_days = 30 WHERE id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	deviceToken, err := newSID()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.trusted_devices WHERE user_id = $1::uuid`, f.userID)
	})
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if ok, err := store.RememberDevice(ctx, tx, f.orgID, f.userID, store.HashToken(deviceToken), uaChromeMac); err != nil || !ok {
		t.Fatalf("remembering a device: %v %v", ok, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	signIn(uaChromeMac, &http.Cookie{Name: DeviceCookieName, Value: deviceToken})
	if n := notices(); len(n) != 1 {
		t.Errorf("a remembered device was told as new: %v", n)
	}

	// Off, nobody is told.
	if _, err := f.pool.Exec(ctx, `UPDATE core.organizations SET new_device_notice = false WHERE id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	signIn(uaEdgeWindows)
	if n := notices(); len(n) != 1 {
		t.Errorf("with the notice off, a new device was told: %v", n)
	}
}

// The notice reads as the person's own language says it should.
func TestTheNewDeviceNoticeNamesTheDevice(t *testing.T) {
	f := newSignInFixture(t)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	if err := f.srv.DeliverAccountNotice(context.Background(), store.AccountNotice{UserID: f.userID,
		Notice: store.NoticeNewDevice, Device: "Safari on iOS"}); err != nil {
		t.Fatal(err)
	}
	msgs := mailer.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0].Body, "Safari on iOS") || !strings.Contains(msgs[0].Body, "change your password") {
		t.Errorf("the notice: %+v", msgs)
	}
}
