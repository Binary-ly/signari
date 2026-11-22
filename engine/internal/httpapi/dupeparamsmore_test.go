package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The device authorization and CIBA endpoints were the two in the token family
// that still accepted a parameter twice: answered about the first while a log
// or proxy reading the last recorded a different request.

func TestTheDeviceAuthorizationEndpointRefusesDuplicateParameters(t *testing.T) {
	f := newTokenFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(url.Values{
		"client_id": {f.clientID}, "scope": {"openid", "openid"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = freshAddress() + ":443"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	desc, _ := body["error_description"].(string)
	if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" || !strings.Contains(desc, "scope") {
		t.Fatalf("scope twice gave %d %v, want 400 invalid_request naming scope", rec.Code, body)
	}
}

func TestTheBackchannelEndpointRefusesDuplicateParameters(t *testing.T) {
	f := newCIBAFixture(t)
	// The CIBA parser already refused a repeated parameter, but only after the
	// client had authenticated, and authentication read the FIRST copy of each
	// credential. A wrong secret followed by the right one was therefore judged
	// on the wrong one and charged to the client's failure budget, while a log
	// reading the last copy recorded a request that should have succeeded. The
	// refusal now comes before authentication, from the same rule as the rest of
	// the family.
	form := f.goodRequest()
	form["client_secret"] = []string{"not-the-secret", f.secret}
	status, body := f.backchannel(t, f.clientID, "", form)
	desc, _ := body["error_description"].(string)
	if status != http.StatusBadRequest || body["error"] != "invalid_request" || !strings.Contains(desc, "client_secret") {
		t.Fatalf("client_secret twice gave %d %v, want 400 invalid_request naming client_secret", status, body)
	}
}
