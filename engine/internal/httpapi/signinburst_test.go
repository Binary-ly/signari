package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"signari.dev/engine/internal/store"
)

// A burst of guesses at one account, each from an address of its own, so that nothing
// but the account's own defences stand in the way. What counts is how many hashes ran,
// which is what guessing buys, and not how many requests were answered without a 429:
// a throttled guess is answered with the generic refusal and is never evaluated.
func TestABurstOfGuessesAtOneAccountIsNotEvaluated(t *testing.T) {
	f := newSignInFixture(t)
	get := httptest.NewRecorder()
	f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	m := csrfValue.FindStringSubmatch(get.Body.String())
	if m == nil {
		t.Fatalf("no CSRF token: %.200s", get.Body.String())
	}
	form := url.Values{"username": {f.email}, "password": {"not-the-password"}, csrfFormField: {m[1]}}
	csrf := cookieFrom(get, CSRFCookieName)

	const burst = 2 * signInPerAccountLimit
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range burst {
		wg.Go(func() {
			<-start
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(csrf)
			r.RemoteAddr = fmt.Sprintf("198.51.100.%d:5555", i+1)
			f.srv.rateLimitedLogin(httptest.NewRecorder(), r)
		})
	}
	close(start)
	wg.Wait()

	var hashed, free int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM core.audit_events
		         WHERE subject_id = $1::uuid AND event_type = 'login.failed' AND detail->>'reason' = 'bad_password'),
		       (SELECT login_free_attempts FROM core.organizations WHERE id = $2::uuid)`,
		f.userID, f.orgID).Scan(&hashed, &free); err != nil {
		t.Fatal(err)
	}
	if hashed == 0 {
		t.Fatal("no guess was evaluated, so this says nothing about the throttle")
	}
	if hashed > free+1 {
		t.Errorf("%d of %d guesses were hashed, with %d free", hashed, burst, free)
	}
}

// A wrong guess whose sender hung up was still a guess.
func TestAGuessIsChargedThoughItsSenderHungUp(t *testing.T) {
	f := newSignInFixture(t)
	addr := "198.51.100.250"
	ip := budgetIP(addr)
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key = $1`,
		"signin:fail:ip:"+ip); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=nobody%40example.test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = addr + ":5555"
	f.srv.recordSignInFailure(ctx, r)

	charged, err := store.CountRate(context.Background(), f.pool, "signin:fail:ip:"+ip, signInPerIPWindow)
	if err != nil {
		t.Fatal(err)
	}
	if charged != 1 {
		t.Errorf("%d charges for a guess whose sender hung up", charged)
	}
}
