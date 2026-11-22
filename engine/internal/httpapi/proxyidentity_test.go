package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/tokens"
)

// setProxyHost says what a host is told, and puts the person in two groups.
func (pa *proxyAuthz) setProxyHost(t *testing.T, release []string, signed bool) {
	t.Helper()
	ctx := context.Background()
	f := pa.f
	if _, err := f.pool.Exec(ctx, `UPDATE core.proxy_hosts SET release_groups = $3, signed_identity = $4
		WHERE org_id = $1::uuid AND host = $2`, f.orgID, pa.own, release, signed); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admins", "payroll"} {
		var group string
		if err := f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, $2, $2)
			ON CONFLICT (org_id, name) DO UPDATE SET display_name = EXCLUDED.display_name RETURNING id::text`,
			f.orgID, name).Scan(&group); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid) ON CONFLICT DO NOTHING`, group, f.userID, f.orgID); err != nil {
			t.Fatal(err)
		}
	}
}

// An application hears only the groups released to it, and a person's others stay
// unsaid. The header is there either way, so a client's own copy never survives.
func TestAHostHearsOnlyTheGroupsReleasedToIt(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)

	pa.setProxyHost(t, []string{}, false)
	rec := pa.verify(t, tok, pa.own, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("it answered %d", rec.Code)
	}
	if values, ok := rec.Header()["X-Forwarded-Groups"]; !ok || len(values) != 1 || values[0] != "" {
		t.Errorf("with nothing released the header is %v, %v, want present and empty", values, ok)
	}
	if values, ok := rec.Header()["X-Forwarded-Jwt"]; !ok || len(values) != 1 || values[0] != "" {
		t.Errorf("with nothing signed the header is %v, %v, want present and empty", values, ok)
	}

	pa.setProxyHost(t, []string{"admins", "a-group-they-are-not-in"}, false)
	rec = pa.verify(t, tok, pa.own, "")
	if got := rec.Header().Get("X-Forwarded-Groups"); got != "admins" {
		t.Errorf("the host heard %q", got)
	}
}

// The application can check the statement itself, against this issuer's keys, and
// it says the same as the headers.
func TestASignedIdentityCanBeCheckedByTheApplication(t *testing.T) {
	pa := newProxyAuthz(t)
	pa.setProxyHost(t, []string{"admins"}, true)
	rec := pa.verify(t, pa.token(t, pa.f.orgID), pa.own, "")
	raw := rec.Header().Get("X-Forwarded-Jwt")
	if rec.Code != http.StatusOK || raw == "" {
		t.Fatalf("it answered %d with %q", rec.Code, raw)
	}
	payload, err := tokens.VerifyTyped(pa.f.srv.cfg.Keys, pa.f.srv.cfg.Issuer, raw, typProxyIdentity)
	if err != nil {
		t.Fatalf("the statement did not verify: %v", err)
	}
	var got proxyIdentity
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Subject != pa.f.userID || got.Audience != "https://"+pa.own || !slices.Equal(got.Groups, []string{"admins"}) {
		t.Errorf("it says %+v", got)
	}
	if left := time.Until(time.Unix(got.Expiry, 0)); left <= 0 || left > proxyIdentityTTL {
		t.Errorf("it lasts %s", left)
	}
	if strings.Contains(string(payload), "payroll") {
		t.Errorf("it carries an unreleased group: %s", payload)
	}

	// Not a proxy cookie, an access token or anything else this issuer signs.
	if _, err := tokens.VerifyTyped(pa.f.srv.cfg.Keys, pa.f.srv.cfg.Issuer, raw, typProxy); err == nil {
		t.Error("the statement passed as a proxy token")
	}
	if rec := pa.verify(t, raw, pa.own, ""); rec.Code == http.StatusOK {
		t.Error("the statement passed forward auth as a cookie")
	}
}

// A token is told to the host what a cookie is.
func TestABearerGetsWhatACookieGets(t *testing.T) {
	pa := newProxyAuthz(t)
	pa.setProxyHost(t, []string{"admins"}, true)
	token := pa.mintFor(t, "https://"+pa.own, pa.sid, "")
	rec := pa.verifyBearer(t, token, pa.own)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Forwarded-Groups") != "admins" ||
		rec.Header().Get("X-Forwarded-Jwt") == "" {
		t.Errorf("a token answered %d, groups %q, jwt %q", rec.Code, rec.Header().Get("X-Forwarded-Groups"),
			rec.Header().Get("X-Forwarded-Jwt"))
	}
}
