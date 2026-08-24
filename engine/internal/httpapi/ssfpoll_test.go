package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// makePollStream turns the fixture client into a confidential poll receiver and
// returns the secret it authenticates with.
func (f *tokenFixture) makePollStream(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients SET client_type='confidential', client_secret_hash=$2
		WHERE client_id=$1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	// The session must record that this client participated, or the revoke
	// fan-out has no reason to tell this stream about it.
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO core.session_clients (sid, client_id) VALUES ($1,$2)
		 ON CONFLICT DO NOTHING`, f.sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url,
		                              events_requested, status)
		VALUES ($1, $2, 'poll', NULL, $3, 'enabled')`,
		f.orgID, f.clientID, []string{ssf.EventSessionRevoked}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.ssf_streams WHERE client_id=$1`, f.clientID)
	})
	return secret
}

func (f *tokenFixture) poll(t *testing.T, secret, body string) (int, pollResponse) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, "/ssf/poll", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, "/ssf/poll", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		r.SetBasicAuth(f.clientID, secret)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	var out pollResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// setPayload decodes the claims of a compact JWS SET without verifying the
// signature -- the test asserts the shape of the event, which is what a receiver
// reads after it has verified.
func setPayload(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("a SET is a compact JWS with three parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding the SET payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("the SET payload is not JSON: %v", err)
	}
	return claims
}

// audString reads a JWT aud claim, which JSON gives back as a string or a
// []any of strings.
func audString(v any) string {
	switch a := v.(type) {
	case string:
		return a
	case []any:
		if len(a) == 1 {
			if s, ok := a[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// The whole journey: a session is revoked, its SET waits on the poll stream, the
// receiver pulls it, then acknowledges it and the queue drains.
func TestPollDeliversAndDrainsOnAcknowledgement(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	ctx := context.Background()

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TerminateSessions(ctx, tx, f.sid, "", store.ReasonAdminRevoke); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Poll: exactly one SET, about our user, addressed to our client.
	code, resp := f.poll(t, secret, "")
	if code != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", code)
	}
	if len(resp.Sets) != 1 {
		t.Fatalf("poll returned %d SETs, want 1", len(resp.Sets))
	}
	var jti, jws string
	for k, v := range resp.Sets {
		jti, jws = k, v
	}
	claims := setPayload(t, jws)
	// aud is a string or a single-element array; both are spec-valid (RFC 7519
	// §4.1.3, Shared Signals §4.1.8).
	if got := audString(claims["aud"]); got != f.clientID {
		t.Errorf("SET aud = %v, want the polling client %q", claims["aud"], f.clientID)
	}
	if claims["iss"] != tokenTestIssuer {
		t.Errorf("SET iss = %v, want %q", claims["iss"], tokenTestIssuer)
	}
	if claims["jti"] != jti {
		t.Errorf("SET jti = %v, want the map key %q", claims["jti"], jti)
	}
	events, _ := claims["events"].(map[string]any)
	if _, ok := events[ssf.EventSessionRevoked]; !ok {
		t.Errorf("SET does not carry the session-revoked event: %v", claims["events"])
	}
	if _, ok := claims["sub_id"]; !ok {
		t.Error("SET has no top-level sub_id; SSF 1.0 §3.1 requires it")
	}

	// Polling again WITHOUT acking redelivers it -- a SET is not lost just because
	// it was handed over once.
	if _, resp2 := f.poll(t, secret, ""); len(resp2.Sets) != 1 {
		t.Fatalf("an un-acked SET was not redelivered: got %d", len(resp2.Sets))
	}

	// Ack it: the queue drains and the next poll is empty.
	code, resp3 := f.poll(t, secret, `{"ack":["`+jti+`"],"returnImmediately":true}`)
	if code != http.StatusOK {
		t.Fatalf("ack poll status = %d, want 200", code)
	}
	if len(resp3.Sets) != 0 {
		t.Errorf("after acking, the SET was still delivered: %v", resp3.Sets)
	}
	if _, resp4 := f.poll(t, secret, ""); len(resp4.Sets) != 0 {
		t.Errorf("the acknowledged SET is still queued: %v", resp4.Sets)
	}
}

func TestPollRequiresClientAuthentication(t *testing.T) {
	f := newTokenFixture(t)
	f.makePollStream(t)

	if code, _ := f.poll(t, "", ""); code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated poll got %d, want 401", code)
	}
	if code, _ := f.poll(t, "not-the-secret", ""); code != http.StatusUnauthorized {
		t.Errorf("a poll with the wrong secret got %d, want 401", code)
	}
}

// A confidential client that authenticates but has no poll stream is told so,
// rather than polling an empty queue forever.
func TestPollWithoutAStreamIs404(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients SET client_type='confidential', client_secret_hash=$2
		WHERE client_id=$1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.poll(t, secret, ""); code != http.StatusNotFound {
		t.Errorf("polling with no stream got %d, want 404", code)
	}
}
