package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTwoDPoPHeadersAreRefused(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Two proofs. Neither needs to be valid: the request must be refused for
	// having two of them, before either is parsed.
	req.Header.Add("DPoP", "first.proof.value")
	req.Header.Add("DPoP", "second.proof.value")

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "DPoP header fields") {
		t.Errorf("a request with two DPoP headers was not refused for that reason.\n"+
			"status %d, body: %s", rec.Code, truncate(body, 300))
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// One header must still work, or the check is an outage for every DPoP client.
// A single malformed proof is refused as a malformed proof, not as a duplicate.
func TestOneDPoPHeaderIsStillProcessed(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", "not.a.valid.proof")

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "DPoP header fields") {
		t.Errorf("a single DPoP header was refused as a duplicate: %s",
			truncate(rec.Body.String(), 200))
	}
}
