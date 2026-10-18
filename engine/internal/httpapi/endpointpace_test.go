package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// PAR wrote a row for anybody with no limit; dynamic registration spent its
// shared bucket before asking who was registering; CIBA could put any number
// of approval prompts in front of one person.

func TestPushedRequestsArePacedPerAddress(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, parPerAddressWindow)
	addr := freshAddress()
	push := func() int {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(url.Values{
			"client_id": {"nobody-" + addr}, "response_type": {"code"},
			"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = addr + ":443"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < parPerAddressLimit; i++ {
		if code := push(); code == http.StatusTooManyRequests {
			t.Fatalf("paced after only %d pushed requests", i)
		}
	}
	if code := push(); code != http.StatusTooManyRequests {
		t.Fatalf("pushed request %d from one address in a minute gave %d, want 429",
			parPerAddressLimit+1, code)
	}
}

func TestUnauthenticatedCallersCannotSpendTheRegistrationBucket(t *testing.T) {
	f := newTokenFixture(t)
	// Far more than the shared bucket holds, each from its own address so the
	// per-address limit is not what is being exercised.
	for i := 0; i < 40; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register",
			strings.NewReader(`{"redirect_uris":["https://rp.test/cb"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer not-a-registration-token")
		req.RemoteAddr = fmt.Sprintf("%s:%d", freshAddress(), 1000+i)
		f.srv.Routes().ServeHTTP(httptest.NewRecorder(), req)
	}
	if status, body := registerWithMode(t, f, ""); status != http.StatusCreated {
		t.Fatalf("after unauthenticated garbage a real registration gave %d: %.200s", status, body)
	}
}

func TestRegistrationIsPacedPerAddress(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, registrationAddressWindow)
	addr := freshAddress()
	register := func() int {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register",
			strings.NewReader(`{"redirect_uris":["https://rp.test/cb"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = addr + ":443"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < registrationsPerAddress; i++ {
		register()
	}
	if code := register(); code != http.StatusTooManyRequests {
		t.Fatalf("registration attempt %d from one address gave %d, want 429",
			registrationsPerAddress+1, code)
	}
}

func TestOnePersonGetsALimitedNumberOfApprovalPrompts(t *testing.T) {
	f := newCIBAFixture(t)
	for i := 0; i < cibaPerUserLimit; i++ {
		if status, body := f.backchannel(t, f.clientID, f.secret, f.goodRequest()); status != http.StatusOK {
			t.Fatalf("request %d for one person gave %d %v", i+1, status, body)
		}
	}
	status, body := f.backchannel(t, f.clientID, f.secret, f.goodRequest())
	if status != http.StatusForbidden || body["error"] != "access_denied" {
		t.Fatalf("request %d for one person in the window gave %d %v, want 403 access_denied",
			cibaPerUserLimit+1, status, body)
	}
	// Another person is unaffected.
	other := f.goodRequest()
	var otherEmail string
	if err := f.pool.QueryRow(t.Context(), `SELECT email FROM core.users WHERE id = $1::uuid`,
		f.otherUserID).Scan(&otherEmail); err != nil {
		t.Fatal(err)
	}
	other.Set("login_hint", otherEmail)
	if status, body := f.backchannel(t, f.clientID, f.secret, other); status != http.StatusOK {
		t.Fatalf("a different person was refused too: %d %v", status, body)
	}
}
