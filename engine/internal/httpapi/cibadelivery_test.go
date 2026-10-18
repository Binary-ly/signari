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

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// CIBA ping and push, through the page a person actually decides on.
//
// Every earlier CIBA test approved by calling store.DecideBackchannel, which is
// why none of them noticed that the page around it never delivered anything:
// ping and push parked a delivery at the request, and the decision -- made here
// and only here -- released neither, so neither mode ever told its client.

// signedInCookie gives the fixture's user a live session reachable by cookie.
func (f *cibaFixture) signedInCookie(t *testing.T) string {
	t.Helper()
	cookie := fmt.Sprintf("ciba-cookie-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '1', ARRAY['pwd'], now(), now() + interval '1 hour')`,
		"sid-"+cookie, store.HashToken(cookie), f.orgID, f.userID); err != nil {
		t.Fatal(err)
	}
	return cookie
}

// decide answers a request on /account/requests, as the person would.
func (f *cibaFixture) decide(t *testing.T, cookie, authReqID, decision string) {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id::text FROM core.device_authorizations WHERE device_code_hash = $1`,
		store.HashToken(authReqID)).Scan(&id); err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRequest(http.MethodGet, "/account/requests", nil)
	get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	page := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(page, get)
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("the requests page carries no CSRF field (status %d)", page.Code)
	}
	var csrfCookie string
	for _, c := range page.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}

	form := url.Values{"id": {id}, "decision": {decision}, csrfFormField: {m[1]}}
	post := httptest.NewRequest(http.MethodPost, "/account/requests", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	post.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, post)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("deciding answered %d", rec.Code)
	}
}

// parked reports the outbox row for one request on one topic: whether it is due
// now, whether it carries sealed tokens, and whether it exists at all.
func (f *cibaFixture) parked(t *testing.T, topic, authReqID string) (due, sealed, exists bool) {
	t.Helper()
	err := f.pool.QueryRow(context.Background(), `
		SELECT o.next_attempt_at <= now(), (o.payload::jsonb ? 'sealed')
		  FROM core.outbox o
		  JOIN core.device_authorizations d ON d.id::text = o.subject_key
		 WHERE o.topic = $1 AND d.device_code_hash = $2`,
		topic, store.HashToken(authReqID)).Scan(&due, &sealed)
	if err != nil {
		return false, false, false
	}
	return due, sealed, true
}

func (f *cibaFixture) deliveryClient(t *testing.T, mode string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.clients
		   SET backchannel_token_delivery_mode = $2,
		       backchannel_client_notification_endpoint = 'https://rp.test/ciba'
		 WHERE client_id = $1`, f.clientID, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *cibaFixture) notifiedRequest(t *testing.T) string {
	t.Helper()
	form := f.goodRequest()
	form.Set("client_notification_token", fmt.Sprintf("notify-%d-abcdefghijklmnop", time.Now().UnixNano()))
	code, body := f.backchannel(t, f.clientID, f.secret, form)
	if code != http.StatusOK {
		t.Fatalf("backchannel request: %d %v", code, body)
	}
	id, _ := body["auth_req_id"].(string)
	return id
}

func TestApprovingAPingRequestNotifiesTheClient(t *testing.T) {
	f := newCIBAFixture(t)
	f.deliveryClient(t, "ping")
	cookie := f.signedInCookie(t)

	approved := f.notifiedRequest(t)
	if due, _, ok := f.parked(t, "ciba_ping", approved); !ok || due {
		t.Fatalf("the ping was not parked before the decision (exists %v, due %v)", ok, due)
	}
	f.decide(t, cookie, approved, "approve")
	if due, _, ok := f.parked(t, "ciba_ping", approved); !ok || !due {
		t.Fatalf("approving did not release the ping (exists %v, due %v): the client is never told", ok, due)
	}

	// §10 notifies on the result, so a refusal is announced too.
	denied := f.notifiedRequest(t)
	f.decide(t, cookie, denied, "deny")
	if due, _, ok := f.parked(t, "ciba_ping", denied); !ok || !due {
		t.Fatalf("refusing did not release the ping (exists %v, due %v)", ok, due)
	}
}

func TestApprovingAPushRequestDeliversTheTokens(t *testing.T) {
	f := newCIBAFixture(t)
	// Push seals the tokens it parks under the root key, as every deployment
	// has one.
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	f.deliveryClient(t, "push")
	cookie := f.signedInCookie(t)

	approved := f.notifiedRequest(t)
	f.decide(t, cookie, approved, "approve")
	due, sealed, ok := f.parked(t, store.CIBAPushTopicName, approved)
	if !ok || !due || !sealed {
		t.Fatalf("approving did not seal and release the push (exists %v, due %v, sealed %v)",
			ok, due, sealed)
	}

	// A refusal has no tokens to push, so the parked delivery is dropped.
	denied := f.notifiedRequest(t)
	f.decide(t, cookie, denied, "deny")
	if _, _, ok := f.parked(t, store.CIBAPushTopicName, denied); ok {
		t.Fatal("refusing left the push parked, to be delivered empty or never")
	}
}
