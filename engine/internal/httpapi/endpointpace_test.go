package httpapi

import (
	"context"
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
		// The fixture's client is public, which is what is paced per address.
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(url.Values{
			"client_id": {f.clientID}, "response_type": {"code"},
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

// A confidential client's pushes come from its own servers, one per sign-in,
// often from one egress address. Paced per address, it was capped at sixty
// sign-ins a minute on the endpoint FAPI 2.0 requires; it is paced as itself
// once it has authenticated.
func TestAConfidentialClientIsPacedAsItselfNotByAddress(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, parPerAddressWindow)
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.clients SET client_type = 'confidential', client_secret_hash = $2
		 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	addr := freshAddress()
	// Measured as the change across these pushes. The address is drawn from
	// 62,500, a bucket outlives its window, and one drawn again from an earlier
	// run of the paced test above once read that run's 61 (0.25).
	charged := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(context.Background(),
			`SELECT COALESCE(sum(count), 0) FROM core.rate_limits WHERE bucket_key = $1`,
			"par:ip:"+addr).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := charged()
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(url.Values{
			"client_id": {f.clientID}, "client_secret": {secret}, "response_type": {"code"},
			"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = addr + ":443"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("push %d from one address answered %d: %s", i+1, rec.Code, rec.Body.String())
		}
	}
	if after := charged(); after != before {
		t.Errorf("an authenticated client's pushes were charged to its address (%d -> %d)", before, after)
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
	// And another client may still ask for the first person. Keyed on the
	// person alone, one client's prompts denied them CIBA from every client.
	if status, body := f.backchannel(t, f.otherClient, f.otherSecret, f.goodRequest()); status != http.StatusOK {
		t.Fatalf("one client's prompts denied the person CIBA from another client: %d %v", status, body)
	}
}
