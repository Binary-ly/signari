package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"signari.dev/engine/internal/tokens"
)

// A SCIM deactivation or deletion ends the person's sessions through
// store.TerminateSessions, as every other one does: the session stops passing
// forward auth, and every application the person reached is sent a
// back-channel logout notice.
//
// A PUT or a POST carrying active:false ended nothing, so the proxy cookie of a
// deprovisioned person kept passing forward auth until it expired. A PATCH and
// a DELETE revoked the rows with an UPDATE of their own, which told no
// application, and a DELETE under on_delete=delete cascaded the rows away
// before anyone could be told.
func TestASCIMDeprovisioningEndsSessionsAndTellsTheApplications(t *testing.T) {
	f := newSCIMFixture(t)
	ctx := context.Background()
	host := fmt.Sprintf("scim-px-%d.example.com", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO core.proxy_hosts (org_id, host, enabled) VALUES ($1::uuid, $2, true)`,
		f.orgID, host); err != nil {
		t.Fatal(err)
	}
	clientID := fmt.Sprintf("scim-rp-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, backchannel_logout_uri)
		VALUES ($1, $2::uuid, 'RP', 'public', 'https://rp.example.test/backchannel')`,
		clientID, f.orgID); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, onDelete, reason string
		act                    func(userName, resourceID string) int
	}{
		{"PUT active:false", "deactivate", "user_deactivated", func(userName, id string) int {
			status, _ := f.do(t, http.MethodPut, "/scim/v2/Users/"+id, fmt.Sprintf(
				`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
				  "externalId":%q,"userName":%q,"active":false,
				  "emails":[{"value":%q,"primary":true}]}`, "ext-"+userName, userName, userName))
			return status
		}},
		{"POST resent with active:false", "deactivate", "user_deactivated", func(userName, _ string) int {
			status, _ := f.do(t, http.MethodPost, "/scim/v2/Users", fmt.Sprintf(
				`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
				  "externalId":%q,"userName":%q,"active":false,
				  "emails":[{"value":%q,"primary":true}]}`, "ext-"+userName, userName, userName))
			return status
		}},
		{"PATCH active:false", "deactivate", "user_deactivated", func(_, id string) int {
			status, _ := f.do(t, http.MethodPatch, "/scim/v2/Users/"+id,
				`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				  "Operations":[{"op":"replace","path":"active","value":false}]}`)
			return status
		}},
		{"DELETE kept as deactivated", "deactivate", "user_deactivated", func(_, id string) int {
			status, _ := f.do(t, http.MethodDelete, "/scim/v2/Users/"+id, "")
			return status
		}},
		{"DELETE that deletes", "delete", "user_deleted", func(_, id string) int {
			status, _ := f.do(t, http.MethodDelete, "/scim/v2/Users/"+id, "")
			return status
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := f.pool.Exec(ctx, `UPDATE core.scim_sources SET on_delete = $2 WHERE id = $1::uuid`,
				f.srcID, c.onDelete); err != nil {
				t.Fatal(err)
			}
			userName, resourceID := f.provisionUser(t, "leaver")
			userID := f.userIDFor(t, resourceID)
			sid := fmt.Sprintf("scim-sid-%d", time.Now().UnixNano())
			if _, err := f.pool.Exec(ctx, `
				INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
				VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '1 hour')`,
				sid, f.orgID, userID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(ctx,
				`INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)`, sid, clientID); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = f.pool.Exec(context.Background(),
					`DELETE FROM core.outbox WHERE topic = 'backchannel_logout' AND payload->>'sub' = $1`, userID)
			})
			proxy := f.proxyToken(t, userID, sid)
			if code := f.forwardAuth(t, proxy, host); code != http.StatusOK {
				t.Fatalf("forward auth answered %d before the deprovisioning, so this proves nothing", code)
			}

			if status := c.act(userName, resourceID); status >= 300 {
				t.Fatalf("the SCIM request answered %d", status)
			}

			if code := f.forwardAuth(t, proxy, host); code != http.StatusUnauthorized {
				t.Errorf("forward auth answered %d after the deprovisioning, want 401: the proxy "+
					"cookie of a person the directory removed still reaches every protected host", code)
			}
			var live, notices int
			if err := f.pool.QueryRow(ctx, `
				SELECT (SELECT count(*) FROM core.sessions WHERE sid = $1 AND revoked_at IS NULL),
				       (SELECT count(*) FROM core.outbox WHERE topic = 'backchannel_logout'
				           AND payload->>'sub' = $2 AND payload->>'client_id' = $3
				           AND payload->>'reason' = $4)`,
				sid, userID, clientID, c.reason).Scan(&live, &notices); err != nil {
				t.Fatal(err)
			}
			if live != 0 {
				t.Errorf("the session is still live after the deprovisioning")
			}
			if notices != 1 {
				t.Errorf("%d back-channel logout notices with reason %s queued for the application "+
					"the person was signed in to, want 1: it keeps them signed in", notices, c.reason)
			}
		})
	}
}

func (f *scimFixture) proxyToken(t *testing.T, userID, sid string) string {
	t.Helper()
	key, err := f.srv.anySigningKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.NewSigner(key).SignJSON(proxyClaims{
		Issuer: f.srv.cfg.Issuer, Subject: userID, SID: sid, OrgID: f.orgID,
		Expiry: time.Now().Add(10 * time.Minute).Unix(),
	}, typProxy)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *scimFixture) forwardAuth(t *testing.T, token, host string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.AddCookie(&http.Cookie{Name: ProxyCookieName, Value: token})
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", "/")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec.Code
}
