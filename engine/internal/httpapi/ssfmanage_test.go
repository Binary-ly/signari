package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// SSF 1.0 §8.1, from the receiver's side. An operator makes the stream; the fixtures
// here write one straight in, as `signari ssf add-stream` would leave it.

func (f *tokenFixture) streamCall(t *testing.T, secret, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		r.SetBasicAuth(f.clientID, secret)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (f *tokenFixture) streamID(t *testing.T) string {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(), `SELECT id::text FROM core.ssf_streams WHERE client_id = $1`,
		f.clientID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *tokenFixture) readStream(t *testing.T, secret, id string) map[string]any {
	t.Helper()
	rec := f.streamCall(t, secret, http.MethodGet, ssf.StreamPath+"?stream_id="+url.QueryEscape(id), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reading the stream answered %d %.200s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// §8.1.1.2, and the configuration §8.1.1 describes.
func TestAReceiverReadsItsStream(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	id := f.streamID(t)

	got := f.readStream(t, secret, id)
	if got["stream_id"] != id || got["iss"] != f.srv.cfg.Issuer || got["aud"] != f.clientID {
		t.Errorf("the stream reads %v", got)
	}
	delivered, _ := got["events_delivered"].([]any)
	if len(delivered) != 1 || delivered[0] != ssf.EventSessionRevoked {
		t.Errorf("events_delivered is %v", got["events_delivered"])
	}
	way, _ := got["delivery"].(map[string]any)
	if way["method"] != ssf.DeliveryPoll || way["endpoint_url"] != f.srv.cfg.Issuer+"/ssf/poll" {
		t.Errorf("delivery is %v", got["delivery"])
	}
	if got["min_verification_interval"] != float64(30) {
		t.Errorf("min_verification_interval is %v", got["min_verification_interval"])
	}

	// "If the "stream_id" parameter is missing, then the Transmitter MUST return a list".
	list := f.streamCall(t, secret, http.MethodGet, ssf.StreamPath, nil)
	var all []map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &all); err != nil || len(all) != 1 || all[0]["stream_id"] != id {
		t.Errorf("the list is %d %s (%v)", list.Code, list.Body, err)
	}
	if list.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control is %q", list.Header().Get("Cache-Control"))
	}

	if rec := f.streamCall(t, secret, http.MethodGet, ssf.StreamPath+"?stream_id=somebody-elses", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another stream's id answered %d", rec.Code)
	}
	if rec := f.streamCall(t, "", http.MethodGet, ssf.StreamPath, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("nobody at all answered %d", rec.Code)
	}

	// "In the event that there are no Event Streams configured, the Transmitter MUST
	// return an empty list."
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.ssf_streams WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	empty := f.streamCall(t, secret, http.MethodGet, ssf.StreamPath, nil)
	if empty.Code != http.StatusOK || strings.TrimSpace(empty.Body.String()) != "[]" {
		t.Errorf("no stream answered %d %q", empty.Code, empty.Body)
	}
}

// Who hears about whom is the operator's to say, which is what an operator making a
// stream comes to.
func TestAReceiverCanNeitherMakeNorDeleteAStream(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	id := f.streamID(t)
	if rec := f.streamCall(t, secret, http.MethodPost, ssf.StreamPath, map[string]any{}); rec.Code != http.StatusForbidden {
		t.Errorf("making one answered %d", rec.Code)
	}
	if rec := f.streamCall(t, secret, http.MethodDelete, ssf.StreamPath+"?stream_id="+id, nil); rec.Code != http.StatusForbidden {
		t.Errorf("deleting one answered %d", rec.Code)
	}
	if rec := f.streamCall(t, "", http.MethodPost, ssf.StreamPath, map[string]any{}); rec.Code != http.StatusUnauthorized {
		t.Errorf("a stranger trying answered %d", rec.Code)
	}
	if f.streamID(t) != id {
		t.Error("the stream is not what it was")
	}
}

// §8.1.1.3 and §8.1.1.4: a PATCH leaves alone what it does not name, and a PUT deletes it.
func TestAReceiverChangesWhatItHearsOfItsStream(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	id := f.streamID(t)
	ctx := context.Background()
	before, err := store.CurrentConfigVersion(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}

	patched := f.streamCall(t, secret, http.MethodPatch, ssf.StreamPath, map[string]any{
		"stream_id": id, "description": "the fraud team's",
		"events_requested": []string{ssf.EventSessionRevoked, ssf.EventAccountDisabled, "https://example.test/not-a-thing"}})
	if patched.Code != http.StatusOK {
		t.Fatalf("patching answered %d %.200s", patched.Code, patched.Body)
	}
	got := f.readStream(t, secret, id)
	if got["description"] != "the fraud team's" {
		t.Errorf("description is %v", got["description"])
	}
	// "A Transmitter MUST ignore any array values that it does not understand."
	if asked, _ := got["events_requested"].([]any); len(asked) != 2 {
		t.Errorf("events_requested is %v", got["events_requested"])
	}
	if after, err := store.CurrentConfigVersion(ctx, f.pool); err != nil || after <= before {
		t.Errorf("the configuration version went from %d to %d (%v)", before, after, err)
	}
	// The operator's stream changed, and they should be able to find out who did it.
	var recorded int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE event_type = 'ssf.stream_changed'
		AND detail->>'stream_id' = $1`, id).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Errorf("%d audit events for one change", recorded)
	}

	if rec := f.streamCall(t, secret, http.MethodPatch, ssf.StreamPath, map[string]any{"stream_id": id, "description": "shorter"}); rec.Code != http.StatusOK {
		t.Fatalf("a second patch answered %d", rec.Code)
	}
	if asked, _ := f.readStream(t, secret, id)["events_requested"].([]any); len(asked) != 2 {
		t.Errorf("a patch that did not name events changed them: %v", asked)
	}

	if rec := f.streamCall(t, secret, http.MethodPut, ssf.StreamPath, map[string]any{"stream_id": id,
		"events_requested": []string{ssf.EventSessionRevoked}}); rec.Code != http.StatusOK {
		t.Fatalf("replacing answered %d %.200s", rec.Code, rec.Body)
	}
	replaced := f.readStream(t, secret, id)
	if _, there := replaced["description"]; there {
		t.Errorf("a replacement that left the description out kept it: %v", replaced["description"])
	}

	for name, tc := range map[string]struct {
		body map[string]any
		code int
	}{
		"no stream_id":      {map[string]any{"description": "x"}, http.StatusBadRequest},
		"another's stream":  {map[string]any{"stream_id": "somebody-elses"}, http.StatusNotFound},
		"another issuer":    {map[string]any{"stream_id": id, "iss": "https://other.test"}, http.StatusBadRequest},
		"another audience":  {map[string]any{"stream_id": id, "aud": "somebody"}, http.StatusBadRequest},
		"delivered altered": {map[string]any{"stream_id": id, "events_delivered": []string{}}, http.StatusBadRequest},
		"an endless note":   {map[string]any{"stream_id": id, "description": strings.Repeat("x", 1025)}, http.StatusBadRequest},
		"somewhere else": {map[string]any{"stream_id": id,
			"delivery": map[string]any{"method": ssf.DeliveryPush, "endpoint_url": "https://attacker.test/in"}}, http.StatusForbidden},
	} {
		if rec := f.streamCall(t, secret, http.MethodPatch, ssf.StreamPath, tc.body); rec.Code != tc.code {
			t.Errorf("%s answered %d, want %d: %.200s", name, rec.Code, tc.code, rec.Body)
		}
	}
	// What is already so can be said back: a read, changed, and sent, §8.1.1.4 suggests.
	current := f.readStream(t, secret, id)
	current["description"] = "read, changed and sent back"
	if rec := f.streamCall(t, secret, http.MethodPut, ssf.StreamPath, current); rec.Code != http.StatusOK {
		t.Errorf("a stream sent back answered %d %.200s", rec.Code, rec.Body)
	}
}

// §8.1.2, and what the operator's own status change does, because it is the same one.
func TestAReceiverPausesItsOwnStream(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	id := f.streamID(t)

	status := func() map[string]string {
		t.Helper()
		rec := f.streamCall(t, secret, http.MethodGet, ssf.StatusPath+"?stream_id="+id, nil)
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return out
	}
	if got := status(); got["status"] != "enabled" || got["stream_id"] != id {
		t.Errorf("the status is %v", got)
	}
	rec := f.streamCall(t, secret, http.MethodPost, ssf.StatusPath, map[string]any{"stream_id": id, "status": "paused", "reason": "a migration"})
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["status"] != "paused" || out["reason"] != "a migration" {
		t.Errorf("pausing answered %d %s", rec.Code, rec.Body)
	}
	if got := status(); got["status"] != "paused" {
		t.Errorf("the status is %v", got)
	}

	for name, tc := range map[string]struct {
		body map[string]any
		code int
	}{
		"no such status":   {map[string]any{"stream_id": id, "status": "asleep"}, http.StatusBadRequest},
		"no stream_id":     {map[string]any{"status": "enabled"}, http.StatusBadRequest},
		"another's stream": {map[string]any{"stream_id": "somebody-elses", "status": "enabled"}, http.StatusNotFound},
	} {
		if rec := f.streamCall(t, secret, http.MethodPost, ssf.StatusPath, tc.body); rec.Code != tc.code {
			t.Errorf("%s answered %d, want %d", name, rec.Code, tc.code)
		}
	}
	if rec := f.streamCall(t, secret, http.MethodGet, ssf.StatusPath, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("reading with no stream_id answered %d", rec.Code)
	}
}

// §8.1.3: a subject removed is not told about, by any of the three roads an event takes
// to a stream, and adding them takes that back. The whole way round: an operator's
// stream, a receiver's request, and what the receiver then collects.
func TestRemovingASubjectStopsEventsAboutThem(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	id := f.streamID(t)
	ctx := context.Background()
	subject := map[string]any{"format": "iss_sub", "iss": f.srv.cfg.Issuer, "sub": f.userID}

	if rec := f.streamCall(t, secret, http.MethodPost, ssf.RemoveSubjectPath, map[string]any{"stream_id": id, "subject": subject}); rec.Code != http.StatusOK {
		t.Fatalf("removing answered %d %.200s", rec.Code, rec.Body)
	}
	change := func(tx pgx.Tx) error {
		return store.QueueCredentialChange(ctx, tx, f.userID, store.CredentialPassword, store.ChangeUpdate, "user")
	}
	f.inTx(t, change)
	if got := f.collected(t, secret); len(got[ssf.EventCredentialChange]) != 0 {
		t.Errorf("a removed subject's credential change was queued: %v", got)
	}

	if rec := f.streamCall(t, secret, http.MethodPost, ssf.AddSubjectPath, map[string]any{"stream_id": id, "subject": subject, "verified": true}); rec.Code != http.StatusOK {
		t.Fatalf("adding answered %d %.200s", rec.Code, rec.Body)
	}
	f.inTx(t, change)
	if got := f.collected(t, secret); len(got[ssf.EventCredentialChange]) != 1 {
		t.Errorf("a subject added back heard %v", got)
	}

	// The road a session's end takes is another statement, and it was the first to
	// exist, so it is the one a change to the function would have left behind.
	if rec := f.streamCall(t, secret, http.MethodPost, ssf.RemoveSubjectPath, map[string]any{"stream_id": id, "subject": subject}); rec.Code != http.StatusOK {
		t.Fatalf("removing again answered %d", rec.Code)
	}
	f.inTx(t, func(tx pgx.Tx) error {
		_, err := store.TerminateSessions(ctx, tx, f.sid, "", store.ReasonAdminRevoke)
		return err
	})
	if got := f.collected(t, secret); len(got[ssf.EventSessionRevoked]) != 0 {
		t.Errorf("a removed subject's session end was queued: %v", got)
	}
}

// The same for a stream pushed to, whose events are written by another pair of statements.
func TestRemovingASubjectStopsPushedEventsToo(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	id := f.streamID(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.ssf_streams SET delivery_method = 'push',
		endpoint_url = 'https://receiver.test/in' WHERE id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = 'ssf_event'
			AND payload->>'stream_id' = $1`, id)
	})
	queued := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.outbox WHERE topic = 'ssf_event'
			AND payload->>'stream_id' = $1 AND payload->>'subject' = $2`, id, f.userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	subject := map[string]any{"format": "iss_sub", "iss": f.srv.cfg.Issuer, "sub": f.userID}
	if rec := f.streamCall(t, secret, http.MethodPost, ssf.RemoveSubjectPath, map[string]any{"stream_id": id, "subject": subject}); rec.Code != http.StatusOK {
		t.Fatalf("removing answered %d %.200s", rec.Code, rec.Body)
	}
	f.inTx(t, func(tx pgx.Tx) error {
		if err := store.QueueCredentialChange(ctx, tx, f.userID, store.CredentialPassword, store.ChangeUpdate, "user"); err != nil {
			return err
		}
		_, err := store.TerminateSessions(ctx, tx, f.sid, "", store.ReasonAdminRevoke)
		return err
	})
	if n := queued(); n != 0 {
		t.Errorf("%d events about a removed subject were queued to push", n)
	}
}

// §9.1: nothing in the answer says whether a subject is anybody, and a subject in any
// form this server can read is found, in its own organisation alone.
func TestASubjectIsFoundWithoutSayingWhoExists(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	id := f.streamID(t)
	ctx := context.Background()
	var email string
	if err := f.pool.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, f.userID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	removed := func() bool {
		t.Helper()
		var there bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.ssf_removed_subjects
			WHERE stream_id = $1::uuid AND user_id = $2::uuid)`, id, f.userID).Scan(&there); err != nil {
			t.Fatal(err)
		}
		return there
	}
	remove := func(subject any) *httptest.ResponseRecorder {
		t.Helper()
		return f.streamCall(t, secret, http.MethodPost, ssf.RemoveSubjectPath, map[string]any{"stream_id": id, "subject": subject})
	}

	for name, subject := range map[string]any{
		"an address nobody has": map[string]any{"format": "email", "email": "nobody-here@example.test"},
		"a subject nobody is":   map[string]any{"format": "iss_sub", "iss": f.srv.cfg.Issuer, "sub": "00000000-0000-0000-0000-000000000000"},
		"not even an id":        map[string]any{"format": "iss_sub", "iss": f.srv.cfg.Issuer, "sub": "not-a-uuid"},
		"another issuer's":      map[string]any{"format": "iss_sub", "iss": "https://other.test", "sub": f.userID},
		"a phone number":        map[string]any{"format": "phone_number", "phone_number": "+15555550100"},
	} {
		if rec := remove(subject); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Errorf("%s answered %d %q, which tells a receiver something", name, rec.Code, rec.Body)
		}
		if removed() {
			t.Errorf("%s removed somebody", name)
		}
	}
	for name, subject := range map[string]any{
		"by address":   map[string]any{"format": "email", "email": strings.ToUpper(email)},
		"in a complex": map[string]any{"format": "complex", "user": map[string]any{"format": "email", "email": email}},
	} {
		if rec := remove(subject); rec.Code != http.StatusOK {
			t.Fatalf("%s answered %d", name, rec.Code)
		}
		if !removed() {
			t.Errorf("%s found nobody", name)
		}
		if rec := f.streamCall(t, secret, http.MethodPost, ssf.AddSubjectPath, map[string]any{"stream_id": id, "subject": subject}); rec.Code != http.StatusOK {
			t.Fatalf("adding back answered %d", rec.Code)
		}
		if removed() {
			t.Errorf("%s stayed removed", name)
		}
	}

	// Somebody at another organisation is nobody here, by any name.
	other := newTokenFixture(t)
	if rec := remove(map[string]any{"format": "iss_sub", "iss": f.srv.cfg.Issuer, "sub": other.userID}); rec.Code != http.StatusOK {
		t.Errorf("another organisation's person answered %d", rec.Code)
	}
	var crossed bool
	if err := f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.ssf_removed_subjects WHERE user_id = $1::uuid)`,
		other.userID).Scan(&crossed); err != nil {
		t.Fatal(err)
	}
	if crossed {
		t.Error("a receiver reached a person in another organisation")
	}

	if rec := remove(nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no subject answered %d", rec.Code)
	}
	if rec := f.streamCall(t, secret, http.MethodPost, ssf.RemoveSubjectPath, map[string]any{"stream_id": "somebody-elses",
		"subject": map[string]any{"format": "email", "email": email}}); rec.Code != http.StatusNotFound {
		t.Errorf("another's stream answered %d", rec.Code)
	}
}

// §7.1: an endpoint is advertised once it works.
func TestTheStreamEndpointsAreAdvertisedAndRouted(t *testing.T) {
	f := newTokenFixture(t)
	md := ssf.Metadata(f.srv.cfg.Issuer, f.srv.cfg.Issuer+"/jwks")
	for name, endpoint := range map[string]string{"configuration": md.ConfigurationEndpoint, "status": md.StatusEndpoint,
		"add subject": md.AddSubjectEndpoint, "remove subject": md.RemoveSubjectEndpoint} {
		path := strings.TrimPrefix(endpoint, f.srv.cfg.Issuer)
		if path == endpoint || path == "" {
			t.Fatalf("%s is %q", name, endpoint)
		}
		method := http.MethodPost
		if rec := f.streamCall(t, "", method, path, map[string]any{}); rec.Code == http.StatusNotFound {
			t.Errorf("%s at %s is not routed", name, path)
		}
	}
}
