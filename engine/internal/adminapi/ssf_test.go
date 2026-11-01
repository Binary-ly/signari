package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// A Shared Signals stream is registered and paused, and a transmitter
// accepted, through the Admin API as `signari ssf` does it (6.07): a
// receiver's token sealed and never read back, and a stream only ever for a
// client of the organisation named.
func TestSharedSignalsAreConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	client := clientIn(t, s, org)
	theirs := clientIn(t, s, newDriftMigrationOrg(t, s, false))
	base := "/admin/organizations/" + org
	errorOf := func(method, path string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, path, body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	const token = "a-token-the-receiver-issued-us"
	for _, bad := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"client_id": client, "poll": true, "endpoint": "https://r.example.test/e"}, "invalid_stream"},
		{map[string]any{"client_id": client, "endpoint": "http://r.example.test/e"}, "invalid_stream"},
		{map[string]any{"client_id": client, "endpoint": "https://r.example.test/e", "events": []string{"x"}}, "invalid_stream"},
		{map[string]any{"client_id": client, "endpoint": "https://10.0.0.5/e"}, "invalid_url"},
	} {
		if e := errorOf(http.MethodPost, base+"/ssf-streams", bad.body, http.StatusBadRequest); e != bad.want {
			t.Errorf("%v answered %q, want %q", bad.body, e, bad.want)
		}
	}
	if e := errorOf(http.MethodPost, base+"/ssf-streams", map[string]any{"client_id": theirs, "poll": true},
		http.StatusNotFound); e != "client_not_found" {
		t.Errorf("another organisation's client answered %q", e)
	}

	rec := call(t, s, http.MethodPost, base+"/ssf-streams", testToken, map[string]any{"client_id": client,
		"endpoint": "https://receiver.example.test/events", "receiver_token": token})
	var made struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), ssf.EventSessionRevoked) {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var sealed []byte
	if err := s.db.QueryRow(ctx, `SELECT auth_token FROM core.ssf_streams WHERE id = $1::uuid`, made.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	// Sealed where the delivery worker opens it.
	if opened, err := s.root.Open(sealed, store.SealContextSSFToken); err != nil || string(opened) != token {
		t.Errorf("the stored token opens to the one given: %v", err)
	}
	if e := errorOf(http.MethodPost, base+"/ssf-streams", map[string]any{"client_id": client, "poll": true},
		http.StatusConflict); e != "already_exists" {
		t.Errorf("a second stream for the client answered %q", e)
	}
	list := call(t, s, http.MethodGet, base+"/ssf-streams", testToken, nil)
	if strings.Contains(list.Body.String(), token) || !strings.Contains(list.Body.String(), `"has_receiver_token":true`) {
		t.Errorf("the streams read %s", list.Body.String())
	}

	status := "/admin/clients/" + client + "/ssf-stream"
	if e := errorOf(http.MethodPatch, status, map[string]any{"status": "stopped"}, http.StatusBadRequest); e != "invalid_status" {
		t.Errorf("an unknown status answered %q", e)
	}
	rec = call(t, s, http.MethodPatch, status, testToken, map[string]any{"status": "paused", "reason": "maintenance"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"was":"enabled"`) {
		t.Fatalf("pausing: %d %s", rec.Code, rec.Body.String())
	}
	var queued int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.outbox WHERE topic = 'ssf_event' AND payload->>'stream_id' = $1
		AND payload->>'event' = $2`, made.ID, ssf.StreamUpdated).Scan(&queued)
	if queued != 1 {
		t.Errorf("pausing queued %d stream-updated events for the receiver, want 1", queued)
	}
	if e := errorOf(http.MethodPatch, "/admin/clients/"+theirs+"/ssf-stream", map[string]any{"status": "paused"},
		http.StatusNotFound); e != "stream_not_found" {
		t.Errorf("a client with no stream answered %q", e)
	}

	source := map[string]any{"name": "Upstream", "issuer": "https://transmitter.example.test",
		"jwks_uri": "https://transmitter.example.test/keys", "audience": "https://receiver.example.test/" + org,
		"events": []string{ssf.EventSessionRevoked}}
	insecure := map[string]any{}
	for k, v := range source {
		insecure[k] = v
	}
	insecure["jwks_uri"] = "http://transmitter.example.test/keys"
	if e := errorOf(http.MethodPut, base+"/ssf-sources", insecure, http.StatusBadRequest); e != "invalid_source" {
		t.Errorf("a plaintext jwks_uri answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, base+"/ssf-sources", testToken, source); rec.Code != http.StatusOK {
		t.Fatalf("accepting a source: %d %s", rec.Code, rec.Body.String())
	}
	// The same issuer and audience from another organisation.
	other := "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/ssf-sources"
	if e := errorOf(http.MethodPut, other, source, http.StatusConflict); e != "audience_taken" {
		t.Errorf("a second organisation's source for the pair answered %q", e)
	}
	if got := call(t, s, http.MethodGet, base+"/ssf-sources", testToken, nil); !strings.Contains(got.Body.String(),
		`"issuer":"https://transmitter.example.test"`) {
		t.Errorf("the sources read %s", got.Body.String())
	}

	// Pulled rather than pushed (12.04): the credential goes one way.
	poll := func(issuer, url, clientID, secret string) map[string]any {
		return map[string]any{"issuer": issuer, "poll_url": url, "client_id": clientID, "secret": secret}
	}
	const issuer, queue = "https://transmitter.example.test", "https://transmitter.example.test/ssf/poll"
	if e := errorOf(http.MethodPut, base+"/ssf-sources/poll", poll(issuer, "http://transmitter.example.test/q", "c", "x"),
		http.StatusBadRequest); e != "invalid_source" {
		t.Errorf("a plaintext queue answered %q", e)
	}
	if e := errorOf(http.MethodPut, base+"/ssf-sources/poll", poll(issuer, queue, "c", ""),
		http.StatusBadRequest); e != "invalid_source" {
		t.Errorf("a queue with no credential answered %q", e)
	}
	if e := errorOf(http.MethodPut, base+"/ssf-sources/poll", poll(issuer, "", "c", "x"),
		http.StatusBadRequest); e != "invalid_source" {
		t.Errorf("a credential with no queue answered %q", e)
	}
	if e := errorOf(http.MethodPut, base+"/ssf-sources/poll", poll("https://nobody.example.test", queue, "c", "x"),
		http.StatusNotFound); e != "source_not_found" {
		t.Errorf("an unknown issuer answered %q", e)
	}
	// Issuers are unique with an audience, so another organisation's is not this one's.
	otherPoll := strings.TrimSuffix(other, "/ssf-sources") + "/ssf-sources/poll"
	if e := errorOf(http.MethodPut, otherPoll, poll(issuer, queue, "c", "x"), http.StatusNotFound); e != "source_not_found" {
		t.Errorf("another organisation's source answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, base+"/ssf-sources/poll", testToken,
		poll(issuer, queue, "rx", "the-poll-credential")); rec.Code != http.StatusOK {
		t.Fatalf("polling a source: %d %s", rec.Code, rec.Body.String())
	}
	listed := call(t, s, http.MethodGet, base+"/ssf-sources", testToken, nil).Body.String()
	if strings.Contains(listed, "the-poll-credential") {
		t.Fatalf("the credential was read back: %s", listed)
	}
	for _, want := range []string{`"poll_url":"` + queue + `"`, `"poll_client_id":"rx"`, `"poll_has_secret":true`} {
		if !strings.Contains(listed, want) {
			t.Errorf("the sources read %s, without %s", listed, want)
		}
	}
	// Replacing what a transmitter may send leaves how it is reached.
	if rec := call(t, s, http.MethodPut, base+"/ssf-sources", testToken, source); rec.Code != http.StatusOK {
		t.Fatalf("replacing a polled source: %d %s", rec.Code, rec.Body.String())
	}
	if listed := call(t, s, http.MethodGet, base+"/ssf-sources", testToken, nil).Body.String(); !strings.Contains(listed, `"poll_has_secret":true`) {
		t.Errorf("replacing the source lost its polling: %s", listed)
	}
	if rec := call(t, s, http.MethodPut, base+"/ssf-sources/poll", testToken, poll(issuer, "", "", "")); rec.Code != http.StatusOK {
		t.Fatalf("stopping: %d %s", rec.Code, rec.Body.String())
	}
	if listed := call(t, s, http.MethodGet, base+"/ssf-sources", testToken, nil).Body.String(); !strings.Contains(listed, `"poll_url":""`) ||
		!strings.Contains(listed, `"poll_has_secret":false`) {
		t.Errorf("stopping left %s", listed)
	}
}
