package httpapi

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Distributed guessing against ONE account, which is the attack a per-address
// limit cannot see.
//
// Every other sign-in test drives a single `testClientIP`, so all of them charge
// the per-address bucket and none can distinguish a server that also protects the
// account from one that does not. These requests come from thirty-one different
// addresses, so the per-address limit (20 failures / 5 minutes) is never reached
// by any one of them.
//
// **What this test asserts, and why it is not the obvious thing.** A first version
// looked for HTTP 429 and failed, and the failure was the test's fault rather than
// the server's. There are three layers here, not one:
//
//	signin:fail:ip:<addr>   20 / 5m    one source, many accounts
//	signin:fail:user:<id>   30 / 15m   many sources, one identifier
//	password_credentials    per USER   exponential throttle, engages first
//
// The third engages well before the second and returns early — with the *generic*
// failure message and a Retry-After header, deliberately, because saying "this
// account is throttled" confirms the account exists. So the correct observable is
// Retry-After appearing, not a 429; the account is protected, and looking only for
// the status code reports a hole that is not there.
func TestOneAccountIsProtectedFromManyAddresses(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerAccountWindow)

	// Addresses of this run's own, each in a /64 of its own since an IPv6 budget
	// is keyed by its /64, and only this run's buckets deleted afterwards. It used
	// to sign in from fixed addresses and so first deleted every `signin:` key,
	// which emptied the account bucket of a test running beside it in another
	// process on the same database: TestTheLDAPAndFormBudgetsAreTheSameBudget then
	// read 11 failures after 30, and 27 runs in 400 failed with the two looped
	// side by side (0.11).
	run := rand.Uint32()
	keys := []string{"signin:fail:user:" + strings.ToLower(f.email), "signin:fail:account:" + f.userID}
	address := func(i int) string {
		a := fmt.Sprintf("2001:db8:%x:%x::1", run>>16, run&0xff00|uint32(i))
		keys = append(keys, "signin:fail:ip:"+budgetIP(a))
		return a
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(),
			`DELETE FROM core.rate_limits WHERE bucket_key = ANY($1)`, keys); err != nil {
			t.Logf("deleting this test's sign-in buckets: %v", err)
		}
	})

	attemptFrom := func(addr, password string) *http.Response {
		t.Helper()
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		grec := httptest.NewRecorder()
		f.srv.handleLoginGet(grec, get)
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
			t.Fatal("the sign-in form carries no CSRF field")
		}
		rest := body[i+len(marker):]
		csrfField := rest[:strings.Index(rest, `"`)]

		form := url.Values{
			"username": {f.email}, "password": {password},
			csrfFormField: {csrfField},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		req.RemoteAddr = net.JoinHostPort(addr, "5555")
		rec := httptest.NewRecorder()
		f.srv.rateLimitedLogin(rec, req)
		return rec.Result()
	}

	throttledAt := -1
	for i := 0; i < signInPerAccountLimit+1; i++ {
		// A fresh address every time: no per-address budget is ever spent twice.
		res := attemptFrom(address(i), "not-the-password")
		if res.Header.Get("Retry-After") != "" || res.StatusCode == http.StatusTooManyRequests {
			throttledAt = i
			break
		}
	}
	if throttledAt < 0 {
		t.Fatalf("%d failed sign-ins against one account, each from a different "+
			"address, produced neither a throttle nor a rate limit; guessing "+
			"spread across addresses would be unbounded against a named person",
			signInPerAccountLimit+1)
	}
	t.Logf("the account was protected after %d distributed failures", throttledAt+1)

	// It must be the ACCOUNT that is protected, not the addresses used so far:
	// an address never seen before must meet the same wall.
	//
	// While the wall stands. The first window past the free attempts is one
	// second, and a refused attempt does not extend it, so on a loaded parallel
	// run the two sign-ins before this one outlasted it and the test reported
	// the keying as broken (0.24). The window is held open: the question here is
	// whose window it is, not how long it lasts.
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.password_credentials
		SET throttled_until = now() + interval '1 minute' WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	res := attemptFrom(address(255), "not-the-password")
	if res.Header.Get("Retry-After") == "" && res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("an unseen address was allowed to keep guessing at the same "+
			"account (status %d, no Retry-After); the protection is keyed on the "+
			"address rather than on the account", res.StatusCode)
	}

	// And the refusal must not become an account-existence oracle. §the throttle
	// branch keeps the generic message precisely so that "throttled" and "wrong
	// password" are indistinguishable to someone probing for valid usernames.
	if body := readAll(t, res); strings.Contains(strings.ToLower(body), "throttl") ||
		strings.Contains(strings.ToLower(body), "locked") {
		t.Errorf("the throttled response names the throttle, which confirms the " +
			"account exists to anyone enumerating usernames")
	}
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
