package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// A device waiting on a person is answered in one statement a poll (E.24): pending, polled
// too soon, refused for another client, expired. Each was a transaction of four round trips,
// every few seconds of every device for minutes. What each answer records is what it was:
// a poll too soon grows the interval by five seconds, and another client's poll and an
// expired code's move nothing.
func TestADevicePollIsOneStatement(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	create := func(name string, lifetime time.Duration) string {
		t.Helper()
		code := "device-poll-" + name + "-" + stamp
		if _, err := store.CreateDeviceAuthorization(ctx, f.pool, f.orgID, f.clientID, "openid", nil,
			store.HashToken(code), store.HashToken("POLL-"+name+"-"+stamp), 5, lifetime); err != nil {
			t.Fatalf("creating a device authorization: %v", err)
		}
		return code
	}
	poll := func(clientID, code string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{
			"grant_type": {oauth.GrantTypeDeviceCode}, "device_code": {code},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		f.srv.handleDeviceCodeGrant(rec, req, clientID)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	lastPolled := func(code string) *time.Time {
		t.Helper()
		var at *time.Time
		if err := f.pool.QueryRow(ctx, `SELECT last_polled_at FROM core.device_authorizations
			WHERE device_code_hash = $1`, store.HashToken(code)).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	waiting := create("waiting", 10*time.Minute)
	gone := create("gone", time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	trips := countRoundTripsOf(t, f.srv)
	step := func(name, clientID, code, want string) {
		t.Helper()
		trips.reset()
		if _, body := poll(clientID, code); body["error"] != want {
			t.Fatalf("%s answered %v, want %s", name, body, want)
		}
		if n := trips.n.Load(); n != 1 {
			t.Errorf("%s took %d round trips, want the one statement:%s", name, n, trips)
		}
	}

	step("the first poll", f.clientID, waiting, "authorization_pending")
	if lastPolled(waiting) == nil {
		t.Error("the first poll was not recorded, so the next is never told to slow down")
	}
	before := f.interval(t, waiting)
	step("a poll at once after it", f.clientID, waiting, "slow_down")
	if after := f.interval(t, waiting); after != before+5 {
		t.Errorf("polling too soon took the interval %d -> %d; RFC 8628 §3.5 adds five seconds", before, after)
	}

	at, interval := lastPolled(waiting), f.interval(t, waiting)
	step("another client's poll", f.otherClient, waiting, "invalid_grant")
	if now := lastPolled(waiting); now == nil || !now.Equal(*at) || f.interval(t, waiting) != interval {
		t.Error("another client's poll of this device's code moved its state")
	}

	step("an expired code's poll", f.clientID, gone, "expired_token")
	if lastPolled(gone) != nil {
		t.Error("an expired code's poll was recorded on it")
	}
}
