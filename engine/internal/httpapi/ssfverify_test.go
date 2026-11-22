package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/ssf"
)

func (f *tokenFixture) verifyStream(t *testing.T, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, ssf.VerifyPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.SetBasicAuth(f.clientID, secret)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// A receiver whose stream has gone quiet asks for an event, collects it the way
// it collects any other, and finds its stream named and its state in it.
func TestAReceiverGetsItsStateBack(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	ctx := context.Background()
	var streamID string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.ssf_streams WHERE client_id = $1`,
		f.clientID).Scan(&streamID); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"stream_id": streamID, "state": "VGhpcyBpcyBhIHN0YXRl"})
	if err != nil {
		t.Fatal(err)
	}

	if rec := f.verifyStream(t, "", string(body)); rec.Code != http.StatusUnauthorized {
		t.Errorf("with no credentials the endpoint answered %d", rec.Code)
	}
	if rec := f.verifyStream(t, secret, "not json"); rec.Code != http.StatusBadRequest {
		t.Errorf("an unparsable body answered %d", rec.Code)
	}
	if rec := f.verifyStream(t, secret, `{"state":"s"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("no stream_id answered %d", rec.Code)
	}
	if rec := f.verifyStream(t, secret, `{"stream_id":"00000000-0000-0000-0000-000000000000"}`); rec.Code != http.StatusNotFound {
		t.Errorf("a stream that is not this client's answered %d", rec.Code)
	}
	var other string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash) VALUES ($1, $2, 'other', 'confidential', 'x') RETURNING client_id`,
		f.clientID+"-other", f.orgID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, other)
	})
	var theirs string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.ssf_streams (org_id, client_id, delivery_method,
		events_requested, status) VALUES ($1, $2, 'poll', $3, 'enabled') RETURNING id::text`,
		f.orgID, other, []string{ssf.EventSessionRevoked}).Scan(&theirs); err != nil {
		t.Fatal(err)
	}
	if rec := f.verifyStream(t, secret, `{"stream_id":"`+theirs+`"}`); rec.Code != http.StatusNotFound {
		t.Errorf("another receiver's stream answered %d", rec.Code)
	}

	if rec := f.verifyStream(t, secret, string(body)); rec.Code != http.StatusNoContent {
		t.Fatalf("the request answered %d %q", rec.Code, rec.Body.String())
	}
	status, got := f.poll(t, secret, `{"returnImmediately":true}`)
	if status != http.StatusOK || len(got.Sets) != 1 {
		t.Fatalf("the poll answered %d with %d SETs", status, len(got.Sets))
	}
	for _, jws := range got.Sets {
		claims := setPayload(t, jws)
		sub, _ := claims["sub_id"].(map[string]any)
		if sub["format"] != "opaque" || sub["id"] != streamID {
			t.Errorf("sub_id is %v, want the stream as an opaque subject", sub)
		}
		if audString(claims["aud"]) != f.clientID {
			t.Errorf("aud is %v", claims["aud"])
		}
		event, ok := claims["events"].(map[string]any)[ssf.Verification].(map[string]any)
		if !ok || event["state"] != "VGhpcyBpcyBhIHN0YXRl" {
			t.Errorf("events are %v, want a verification carrying the state", claims["events"])
		}
	}

	rec := f.verifyStream(t, secret, string(body))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("a second request at once answered %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// §8.1.4.2's 204 says the event "will" go. A disabled stream holds nothing, so
// saying that of one would be false; a paused one holds it and that remains true.
func TestAVerificationIsPromisedOnlyWhereItCanBeSent(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	ctx := context.Background()
	var streamID string
	if err := f.pool.QueryRow(ctx, `UPDATE core.ssf_streams SET status = 'disabled' WHERE client_id = $1
		RETURNING id::text`, f.clientID).Scan(&streamID); err != nil {
		t.Fatal(err)
	}
	if rec := f.verifyStream(t, secret, `{"stream_id":"`+streamID+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("a disabled stream answered %d", rec.Code)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.ssf_streams SET status = 'paused' WHERE id = $1::uuid`, streamID); err != nil {
		t.Fatal(err)
	}
	if rec := f.verifyStream(t, secret, `{"stream_id":"`+streamID+`"}`); rec.Code != http.StatusNoContent {
		t.Errorf("a paused stream answered %d", rec.Code)
	}
	if _, got := f.poll(t, secret, `{"returnImmediately":true}`); len(got.Sets) != 0 {
		t.Errorf("a paused stream handed over %d SETs", len(got.Sets))
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.ssf_streams SET status = 'enabled' WHERE id = $1::uuid`, streamID); err != nil {
		t.Fatal(err)
	}
	if _, got := f.poll(t, secret, `{"returnImmediately":true}`); len(got.Sets) != 1 {
		t.Errorf("resuming the stream handed over %d SETs, want the one it held", len(got.Sets))
	}
}

// The document names the endpoint only because it is there.
func TestTheVerificationEndpointIsAdvertisedAndRouted(t *testing.T) {
	f := newTokenFixture(t)
	req := httptest.NewRequest(http.MethodGet, ssf.WellKnownBase, nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["verification_endpoint"] != strings.TrimRight(tokenTestIssuer, "/")+ssf.VerifyPath {
		t.Errorf("verification_endpoint is %v", doc["verification_endpoint"])
	}
	if got := f.verifyStream(t, "", "{}"); got.Code != http.StatusUnauthorized {
		t.Errorf("the advertised endpoint answered %d", got.Code)
	}
}
