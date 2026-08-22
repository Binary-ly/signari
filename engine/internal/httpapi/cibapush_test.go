package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// CIBA push mode, Core 1.0 §10.3 and §11.
//
// Push differs from ping in what travels and in what the client may do
// afterwards: the notification carries the TOKENS, and §11 forbids the client
// from calling the token endpoint at all. Both halves need pinning, because a
// client configured for one behaving as the other either hangs forever or is
// handed the same authentication twice.

// pushClient switches the fixture's client to push delivery.
func (f *cibaFixture) pushClient(t *testing.T, endpoint string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.clients
		SET backchannel_token_delivery_mode = 'push',
		    backchannel_client_notification_endpoint = $2
		WHERE client_id = $1`, f.clientID, endpoint); err != nil {
		t.Fatalf("switching the client to push: %v", err)
	}
}

// §9: "It MUST be an HTTPS URL". Enforced in the schema, so a plaintext endpoint
// cannot even be registered — push sends tokens there, and a plaintext endpoint
// hands them to whatever is on the network path, with delivery still succeeding.
func TestAPlaintextNotificationEndpointCannotBeRegistered(t *testing.T) {
	f := newCIBAFixture(t)
	_, err := f.pool.Exec(context.Background(), `
		UPDATE core.clients
		SET backchannel_token_delivery_mode = 'push',
		    backchannel_client_notification_endpoint = 'http://rp.test/cb'
		WHERE client_id = $1`, f.clientID)
	if err == nil {
		t.Fatal("a plaintext notification endpoint was accepted; push would deliver " +
			"an access token over an unencrypted connection")
	}
}

// A push request parks a delivery rather than issuing anything immediately.
func TestAPushRequestParksADelivery(t *testing.T) {
	f := newCIBAFixture(t)
	f.pushClient(t, "https://rp.test/ciba")

	form := f.goodRequest()
	form.Set("client_notification_token", "tok-"+f.clientID+"-notification-value")
	code, body := f.backchannel(t, f.clientID, f.secret, form)
	if code != http.StatusOK {
		t.Fatalf("a push request was refused: %d %v", code, body)
	}

	// Scoped to THIS client. The suite shares one database, so an unscoped count
	// measures whatever other tests happened to leave behind.
	var parked int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.outbox
		WHERE topic = $1 AND next_attempt_at = 'infinity'
		  AND payload::jsonb->>'client_id' = $2`,
		store.CIBAPushTopicName, f.clientID).Scan(&parked); err != nil {
		t.Fatal(err)
	}
	if parked == 0 {
		t.Fatal("no push delivery was parked, so approving would notify nobody")
	}
}

// §7.1: the notification token is required for push, as for ping — it is what
// authenticates the callback to the client.
func TestAPushRequestWithoutANotificationTokenIsRefused(t *testing.T) {
	f := newCIBAFixture(t)
	f.pushClient(t, "https://rp.test/ciba")

	code, body := f.backchannel(t, f.clientID, f.secret, f.goodRequest())
	if code == http.StatusOK {
		t.Fatal("a push request with no client_notification_token was accepted; the " +
			"callback could be delivered but not proven to come from us")
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
}

// §11: "If the Client is registered to use the Push Mode then it MUST NOT call
// the Token Endpoint with the CIBA Grant Type."
//
// Serving it would deliver the tokens twice from one authentication — once here
// and once to the notification endpoint — which is two live credential sets for
// something the person approved once.
func TestAPushClientIsRefusedAtTheTokenEndpoint(t *testing.T) {
	f := newCIBAFixture(t)
	f.pushClient(t, "https://rp.test/ciba")

	form := url.Values{
		"grant_type":    {"urn:openid:params:grant-type:ciba"},
		"auth_req_id":   {"anything"},
		"client_id":     {f.clientID},
		"client_secret": {f.secret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code == http.StatusOK {
		t.Fatal("a push client redeemed an auth_req_id at the token endpoint")
	}
	if body["error"] != "unauthorized_client" {
		t.Errorf("error = %v, want unauthorized_client so the client can tell this "+
			"is a configuration mistake rather than a bad auth_req_id", body["error"])
	}
}

// A poll client must be unaffected: it parks nothing and may still redeem.
func TestPollClientsAreUnaffectedByPushMode(t *testing.T) {
	f := newCIBAFixture(t)
	form := f.goodRequest()
	if code, body := f.backchannel(t, f.clientID, f.secret, form); code != http.StatusOK {
		t.Fatalf("a poll request was refused: %d %v", code, body)
	}
	var parked int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.outbox
		WHERE topic = $1 AND payload::jsonb->>'client_id' = $2`,
		store.CIBAPushTopicName, f.clientID).Scan(&parked); err != nil {
		t.Fatal(err)
	}
	if parked != 0 {
		t.Errorf("a poll request parked %d push deliveries for this client", parked)
	}
}

// The delivery mode constant and the schema must agree about what exists.
func TestPushIsAKnownDeliveryMode(t *testing.T) {
	if oauth.DeliveryPush != "push" {
		t.Errorf("DeliveryPush = %q, want push", oauth.DeliveryPush)
	}
}
