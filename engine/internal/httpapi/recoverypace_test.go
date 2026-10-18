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
)

// A reset request writes a row, supersedes the earlier link and sends mail,
// and there was no pace at all.

func liveRecoveryRequests(t *testing.T, f *signInFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.recovery_requests
		 WHERE user_id = $1::uuid AND cancelled_at IS NULL AND consumed_at IS NULL`,
		f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestASecondResetRequestWithinAMinuteSendsNothing(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, time.Minute)
	ctx := context.Background()
	cap := &captureMailer{}
	f.srv.mailer = cap

	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	if len(cap.messages()) != 1 || liveRecoveryRequests(t, f) != 1 {
		t.Fatalf("the first request sent %d message(s) and left %d live request(s), want 1 and 1",
			len(cap.messages()), liveRecoveryRequests(t, f))
	}
	var first string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.recovery_requests
		 WHERE user_id = $1::uuid AND cancelled_at IS NULL`, f.userID).Scan(&first); err != nil {
		t.Fatal(err)
	}

	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	if n := len(cap.messages()); n != 1 {
		t.Fatalf("a second request within a minute sent %d messages in all, want 1", n)
	}
	var still string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.recovery_requests
		 WHERE user_id = $1::uuid AND cancelled_at IS NULL`, f.userID).Scan(&still); err != nil || still != first {
		t.Fatalf("the paced request superseded the person's own link (%v): an attacker "+
			"could keep it from ever working", err)
	}

	// Five an hour, whatever the minutes: step the minute bucket back each time.
	stepMinute := func() {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `
			UPDATE core.rate_limits SET window_start = window_start - interval '2 minutes'
			 WHERE bucket_key = $1`, "recover:user:min:"+f.userID); err != nil {
			t.Fatal(err)
		}
	}
	for i := 2; i <= recoveryPerAccountHour; i++ {
		stepMinute()
		if err := f.srv.beginRecovery(ctx, f.email); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(cap.messages()); n != recoveryPerAccountHour {
		t.Fatalf("%d paced requests sent %d messages, want %d", recoveryPerAccountHour, n, recoveryPerAccountHour)
	}
	stepMinute()
	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	if n := len(cap.messages()); n != recoveryPerAccountHour {
		t.Fatalf("a request over the hourly pace sent mail (%d in all)", n)
	}
}

func TestOneAddressCannotSweepResetMailAcrossAccounts(t *testing.T) {
	f := newSignInFixture(t)
	cap := &captureMailer{}
	f.srv.mailer = cap
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.18.%d.%d", (n/13)%250, n%250+1)

	post := func(identifier string) int {
		t.Helper()
		get := httptest.NewRequest(http.MethodGet, "/recover", nil)
		get.RemoteAddr = addr + ":443"
		grec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(grec, get)
		var cookie string
		for _, c := range grec.Result().Cookies() {
			if c.Name == CSRFCookieName {
				cookie = c.Value
			}
		}
		const marker = `name="` + csrfFormField + `" value="`
		body := grec.Body.String()
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("the recovery form carries no CSRF field: %d", grec.Code)
		}
		rest := body[i+len(marker):]
		form := url.Values{"username": {identifier}, csrfFormField: {rest[:strings.Index(rest, `"`)]}}
		req := httptest.NewRequest(http.MethodPost, "/recover", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookie})
		req.RemoteAddr = addr + ":443"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < recoveryPerAddressLimit; i++ {
		post(fmt.Sprintf("nobody-%d-%d@example.test", n, i))
	}
	if code := post(f.email); code != http.StatusOK {
		t.Fatalf("a paced request answered %d; it must answer the same page as any other", code)
	}
	if len(cap.messages()) != 0 || liveRecoveryRequests(t, f) != 0 {
		t.Fatalf("after %d requests from one address, a real account was still sent %d message(s)",
			recoveryPerAddressLimit, len(cap.messages()))
	}
}
