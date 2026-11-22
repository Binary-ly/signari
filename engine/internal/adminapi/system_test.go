package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// /admin/v1/ serves the same routes as /admin/, reads and writes (6.08).
func TestTheV1PathServesTheSameAPI(t *testing.T) {
	s, _ := newTestServer(t)
	plain := call(t, s, http.MethodGet, "/admin/config-version", testToken, nil)
	v1 := call(t, s, http.MethodGet, "/admin/v1/config-version", testToken, nil)
	if plain.Code != http.StatusOK || v1.Code != http.StatusOK || plain.Body.String() != v1.Body.String() {
		t.Errorf("/admin/v1/ answered %d %s where /admin/ answered %d %s", v1.Code, v1.Body.String(),
			plain.Code, plain.Body.String())
	}
	client := newPreconditionClient(t, s)
	if rec := call(t, s, http.MethodPatch, "/admin/v1/clients/"+client, testToken, map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Errorf("a write under /admin/v1/ answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodGet, "/admin/v2/config-version", testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a version that does not exist answered %d", rec.Code)
	}
}

// The deployment is a deployment-wide token's to read.
func TestTheSystemIsReadOnlyByADeploymentWideToken(t *testing.T) {
	s, _ := newTestServer(t)
	scoped := mintToken(t, s, "system-scoped", anyOrgID(t, s), []string{ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodGet, "/admin/system", scoped, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token read the deployment: %d", rec.Code)
	}
	rec := call(t, s, http.MethodGet, "/admin/system", testToken, nil)
	var sys struct {
		Schema struct {
			Applied, Binary int
		}
		RateLimits struct {
			Arrivals int `json:"arrivals_per_second"`
		} `json:"rate_limits"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sys)
	if rec.Code != http.StatusOK || sys.Schema.Applied == 0 || sys.Schema.Applied != sys.Schema.Binary ||
		sys.RateLimits.Arrivals != adminArrivalsPerSecond {
		t.Errorf("the system read: %d %s", rec.Code, rec.Body.String())
	}
}

// The rates come from the environment, and a bad one stops the start.
func TestTheAdminRatesComeFromTheEnvironment(t *testing.T) {
	t.Setenv("SIGNARI_ADMIN_RATE", "400")
	t.Setenv("SIGNARI_ADMIN_TOKEN_RATE", "300")
	l, err := limitsFromEnv()
	if err != nil || l.arrivals != 400 || l.perToken != 300 {
		t.Errorf("set rates read as %+v (%v)", l, err)
	}
	for _, bad := range [][2]string{{"0", "1"}, {"many", "1"}, {"10", "20"}, {"10", "-1"}} {
		t.Setenv("SIGNARI_ADMIN_RATE", bad[0])
		t.Setenv("SIGNARI_ADMIN_TOKEN_RATE", bad[1])
		if _, err := limitsFromEnv(); err == nil {
			t.Errorf("rates %v were accepted", bad)
		}
	}
}
