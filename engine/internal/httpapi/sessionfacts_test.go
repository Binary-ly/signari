package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/posture"
	"signari.dev/engine/internal/risk"
)

// Device posture and risk, kept with the session a sign-in made and read by a decision made
// later, when there is no browser to ask (11.07).

func TestASignInWritesDownWhatItShowed(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	// London, Paris and São Paulo.
	t.Setenv("SIGNARI_GEOIP_STATIC",
		"192.0.2.0/25=GB,51.51,-0.13;192.0.2.128/25=FR,48.86,2.35;198.51.100.0/24=BR,-23.55,-46.63")
	f.srv.geo = risk.NewResolver()
	_, proxies, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetPosture(&posture.Config{TrustedProxies: []*net.IPNet{proxies}, ManagedHeader: "X-Device-Managed",
		CompliantHeader: "X-Device-Compliant"})

	history := func(country string, lat, lon float64, ago string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `DELETE FROM core.auth_locations WHERE user_id = $1::uuid`, f.userID); err != nil {
			t.Fatal(err)
		}
		if country == "" {
			return
		}
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.auth_locations (user_id, org_id, country, latitude, longitude, source, occurred_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, 'geoip', now() - $6::interval)`,
			f.userID, f.orgID, country, lat, lon, ago); err != nil {
			t.Fatal(err)
		}
	}
	type shown struct {
		risk               int
		managed, compliant bool
	}
	signIn := func(ip string, headers map[string]string) shown {
		t.Helper()
		rec := f.signInShowing(t, ip, headers)
		cookie := cookieFrom(rec, SessionCookieName)
		if cookie == nil {
			t.Fatalf("no session from %s: %d %s", ip, rec.Code, rec.Body)
		}
		var s shown
		if err := f.pool.QueryRow(ctx, `SELECT risk, device_managed, device_compliant FROM core.sessions
			WHERE cookie_hash = sha256($1::bytea)`, cookie.Value).Scan(&s.risk, &s.managed, &s.compliant); err != nil {
			t.Fatal(err)
		}
		return s
	}

	history("", 0, 0, "")
	if got := signIn("198.51.100.7", nil); got != (shown{}) {
		t.Errorf("a first sign-in, with nothing to compare, wrote %+v", got)
	}
	history("GB", 51.51, -0.13, "1 hour")
	if got := signIn("192.0.2.10", nil); got.risk != 0 {
		t.Errorf("signing in from the same place wrote risk %d", got.risk)
	}
	history("GB", 51.51, -0.13, "1 hour")
	if got := signIn("198.51.100.7", nil); got.risk != risk.ScoreImpossibleTravel {
		t.Errorf("London to São Paulo in an hour wrote risk %d", got.risk)
	}
	history("GB", 51.51, -0.13, "7 days")
	if got := signIn("192.0.2.200", nil); got.risk != risk.ScoreNewCountry {
		t.Errorf("a first sign-in from France wrote risk %d", got.risk)
	}
	history("GB", 51.51, -0.13, "1 hour")
	if got := signIn("203.0.113.9", nil); got.risk != 0 {
		t.Errorf("an address nothing can place wrote risk %d", got.risk)
	}

	history("GB", 51.51, -0.13, "1 hour")
	device := map[string]string{"X-Device-Managed": "true", "X-Device-Compliant": "true"}
	if got := signIn("192.0.2.10", device); !got.managed || !got.compliant {
		t.Errorf("a device a trusted proxy vouched for wrote %+v", got)
	}
	if got := signIn("192.0.2.10", map[string]string{"X-Device-Managed": "true"}); !got.managed || got.compliant {
		t.Errorf("a managed device nobody called compliant wrote %+v", got)
	}
	// The same words from anybody else are only words.
	history("BR", -23.55, -46.63, "1 hour")
	if got := signIn("198.51.100.7", device); got.managed || got.compliant {
		t.Errorf("a client claiming its own device wrote %+v", got)
	}
}

func TestADecisionReadsWhatTheSessionShowed(t *testing.T) {
	a := newAuthzProviderFixture(t)
	ctx := context.Background()
	f := a.f
	model := authzen.Model{Types: map[string]authzen.Type{"doc": {
		Relations:   map[string][]string{"owner": nil},
		Permissions: map[string][]string{"can_edit": {"owner"}},
		Require:     map[string]authzen.Condition{"can_edit": {MaxRisk: 10, DeviceManaged: true}},
	}}}
	compiled, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.authorization_models SET compiled = $2::jsonb WHERE org_id = $1::uuid`,
		f.orgID, compiled); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'user', $2, 'owner', 'doc', $3)`, f.orgID, f.userID, a.resource); err != nil {
		t.Fatal(err)
	}
	session := func(risk int, managed bool) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET risk = $2, device_managed = $3 WHERE sid = $1`,
			f.sid, risk, managed); err != nil {
			t.Fatal(err)
		}
	}
	decide := func(context string) (bool, string) {
		t.Helper()
		body := fmt.Sprintf(`{"subject":{"type":"user","id":%q},"action":{"name":"can_edit"},
			"resource":{"type":"doc","id":%q}%s}`, f.userID, a.resource, context)
		req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("evaluation gave %d: %s", rec.Code, rec.Body)
		}
		var resp struct {
			Decision bool `json:"decision"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Decision, rec.Body.String()
	}
	inSession := fmt.Sprintf(`,"context":{"sid":%q}`, f.sid)

	session(0, true)
	if ok, body := decide(inSession); !ok {
		t.Fatalf("a calm session on a managed device was refused: %s", body)
	}
	session(50, true)
	if ok, body := decide(inSession); ok || !strings.Contains(body, "it is 50") {
		t.Errorf("risk 50 against a cap of 10 gave %v: %s", ok, body)
	}
	session(0, false)
	if ok, body := decide(inSession); ok {
		t.Errorf("no managed device was allowed: %s", body)
	}
	session(0, true)
	if ok, body := decide(""); ok || !strings.Contains(body, "no live session") {
		t.Errorf("no session named gave %v: %s", ok, body)
	}
	// A session of nobody in particular says nothing about this subject.
	if ok, body := decide(`,"context":{"sid":"not-a-session"}`); ok {
		t.Errorf("a session that is not this person's was allowed: %s", body)
	}
}
