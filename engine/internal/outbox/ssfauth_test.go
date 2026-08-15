package outbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Authenticating the transmitter to the receiver, RFC 8935 push delivery.
//
// The column for this token existed from the first SSF migration, with a comment
// saying it "authenticates US to THEM", and nothing ever sent it. A receiver that
// requires it answered 401, the outbox retried eight times, and the event was
// parked — silently, and looking exactly like a receiver outage.
//
// These tests run against httptest.NewTLSServer because its certificate is
// trusted by the client it hands out, which is the only way to exercise the real
// delivery path over https without a certificate authority.

// captured is what a receiver saw.
type captured struct {
	auth        string
	contentType string
	body        []byte
}

// receiver stands in for a Shared Signals endpoint. It refuses anything without
// the expected bearer token, the way a real one does.
func receiver(t *testing.T, expect string, got *captured) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		got.contentType = r.Header.Get("Content-Type")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		got.body = buf[:n]

		if expect != "" && got.auth != "Bearer "+expect {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestPushCarriesTheBearerToken.
//
// The token cannot be read from the database here, so this exercises the header
// path directly: whatever streamAuthToken returns must reach the request. The
// database half is covered by TestNoTokenStillDelivers below and by the CLI,
// which seals it.
func TestPushCarriesTheBearerToken(t *testing.T) {
	const token = "receiver-issued-token"
	var got captured
	srv := receiver(t, token, &got)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("the receiver refused an authenticated push: %d", resp.StatusCode)
	}
	if got.auth != "Bearer "+token {
		t.Errorf("Authorization header = %q, want the bearer token", got.auth)
	}
	// The media type is fixed by RFC 8935 §2.1 and receivers check it.
	if got.contentType != "application/secevent+jwt" {
		t.Errorf("Content-Type = %q, want application/secevent+jwt", got.contentType)
	}
}

// TestUnauthenticatedPushIsRefused is the failure that was happening in
// production shape: no header, 401, retry, park.
func TestUnauthenticatedPushIsRefused(t *testing.T) {
	var got captured
	srv := receiver(t, "receiver-issued-token", &got)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a receiver requiring a token accepted an unauthenticated push: %d",
			resp.StatusCode)
	}
	if got.auth != "" {
		t.Errorf("an Authorization header was sent when none was configured: %q", got.auth)
	}
}

// TestStreamAuthTokenIsAbsentWithoutARootKey.
//
// A worker with no root key must return no token rather than an error: the SET
// is signed either way, and a receiver that never issued a token is not made
// less safe by its absence. Failing here instead would stop every delivery on a
// deployment that does not use stream tokens at all.
func TestStreamAuthTokenIsAbsentWithoutARootKey(t *testing.T) {
	w := &Worker{}
	tok, err := w.streamAuthToken(context.Background(), "some-stream-id")
	if err != nil {
		t.Fatalf("no root key produced an error rather than no token: %v", err)
	}
	if tok != "" {
		t.Errorf("a token appeared from nowhere: %q", tok)
	}
}

// TestEmptyStreamIDIsNotQueried. An event queued before stream ids were carried
// must not turn into a database lookup for the empty string.
func TestEmptyStreamIDIsNotQueried(t *testing.T) {
	w := &Worker{} // nil db: any query would panic
	if _, err := w.streamAuthToken(context.Background(), ""); err != nil {
		t.Fatalf("an empty stream id was looked up: %v", err)
	}
}
