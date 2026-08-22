package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The liveness endpoint answers one question and must keep answering only that.
//
// # Why this is pinned rather than left to judgement
//
// /healthz previously also returned the active signing algorithms. That was not a
// disclosure — the same list is in the discovery document, which OpenID Connect
// requires to be public — but it was configuration, and this is the endpoint most
// likely to be wired up by infrastructure that is not thinking about OIDC at all:
// a load balancer probe, a Kubernetes liveness check, a proxy path allow-listed
// before anyone reads the protocol docs.
//
// The rule that keeps that harmless is that the response describes the PROCESS
// and never the deployment. A rule like that survives exactly as long as someone
// remembers it, so it is a test: adding a field here fails, and whoever adds it
// gets to argue with this comment rather than with a reviewer's memory.
func TestHealthReturnsLivenessAndNothingElse(t *testing.T) {
	srv, _, _ := txnVerifyServer(t)

	rec := httptest.NewRecorder()
	srv.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not JSON: %v", err)
	}

	if body["status"] != "ok" {
		t.Errorf(`status = %v, want "ok"`, body["status"])
	}
	// The whole assertion: one key. Not "algs is absent" — that would pass for
	// any other configuration field somebody adds next.
	if len(body) != 1 {
		t.Errorf("the liveness response carries %d fields, want exactly 1 (status). "+
			"Anything describing the deployment rather than the process does not "+
			"belong on an endpoint this likely to be exposed by infrastructure: %v",
			len(body), body)
	}
}
