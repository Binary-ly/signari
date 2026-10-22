package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// This deployment's own access tokens at the Admin API (6.01), acting with
// their holder's roles, every property read per request.

const testIssuer = "https://idp.example.test"

type adminTokens struct {
	s      *Server
	signer *tokens.Signer
	other  *tokens.Signer
	org    string
	client string
}

func newAdminTokens(t *testing.T) *adminTokens {
	t.Helper()
	s, _ := newTestServer(t)
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	set, err := keys.NewSet(k)
	if err != nil {
		t.Fatal(err)
	}
	s.SetAccessTokens(set, testIssuer)
	client := newPreconditionClient(t, s)
	if _, err := s.db.Exec(context.Background(),
		`UPDATE core.clients SET admin_api = true WHERE client_id = $1`, client); err != nil {
		t.Fatal(err)
	}
	return &adminTokens{s: s, signer: tokens.NewSigner(k), other: tokens.NewSigner(stranger),
		org: anyOrgID(t, s), client: client}
}

// claims is a token from the designated client, for sub and sid.
func (a *adminTokens) claims(sub, sid string) tokens.AccessTokenClaims {
	now := time.Now()
	return tokens.AccessTokenClaims{Issuer: testIssuer, Subject: sub,
		Audience: []string{tokens.AdminAudience(testIssuer)}, Expiry: now.Add(time.Hour).Unix(),
		IssuedAt: now.Unix(), JTI: fmt.Sprintf("jti-%d", now.UnixNano()), ClientID: a.client, SessionID: sid}
}

func (a *adminTokens) sign(t *testing.T, c tokens.AccessTokenClaims) string {
	t.Helper()
	raw, err := a.signer.SignJSON(c, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// session plants a session for user with the factors amr.
func (a *adminTokens) session(t *testing.T, user string, amr ...string) string {
	t.Helper()
	sid := newDriftSession(t, a.s, user)
	if _, err := a.s.db.Exec(context.Background(), `UPDATE core.sessions SET amr = $2 WHERE sid = $1`,
		sid, amr); err != nil {
		t.Fatal(err)
	}
	return sid
}

func (a *adminTokens) grant(t *testing.T, b store.RoleBinding) string {
	t.Helper()
	b.OrgID = a.org
	id, err := store.GrantRole(context.Background(), a.s.db, b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAnApplicationActsAtTheAdminAPIWithItsOwnRoles(t *testing.T) {
	a := newAdminTokens(t)
	binding := a.grant(t, store.RoleBinding{ClientID: a.client, Role: "app-manager"})
	tok := a.sign(t, a.claims(a.client, ""))

	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("an app manager listing applications: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/users?limit=1", tok, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an app manager listed people: %d", rec.Code)
	}

	// Taken away, refused from the next request: nothing in the token says
	// what it may do.
	if _, err := store.RevokeRole(context.Background(), a.s.db, a.org, binding); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", tok, nil); rec.Code != http.StatusForbidden {
		t.Errorf("after the role was taken away the same token answered %d", rec.Code)
	}
	a.grant(t, store.RoleBinding{ClientID: a.client, Role: "app-manager"})
	if _, err := a.s.db.Exec(context.Background(),
		`UPDATE core.clients SET admin_api = false WHERE client_id = $1`, a.client); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", tok, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the client was undesignated its token answered %d", rec.Code)
	}
}

func TestOnlyATokenForTheAdminAPIFromThisIssuerIsAccepted(t *testing.T) {
	a := newAdminTokens(t)
	a.grant(t, store.RoleBinding{ClientID: a.client, Role: "auditor"})
	good := a.claims(a.client, "")
	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", a.sign(t, good), nil); rec.Code != http.StatusOK {
		t.Fatalf("the well-formed token was refused: %d %s", rec.Code, rec.Body.String())
	}

	for why, edit := range map[string]func(*tokens.AccessTokenClaims){
		// tokens.AudienceAccepted's rule: an application's own token.
		"audienced to the client": func(c *tokens.AccessTokenClaims) { c.Audience = []string{a.client} },
		"audienced to the issuer": func(c *tokens.AccessTokenClaims) { c.Audience = []string{testIssuer} },
		"another issuer's": func(c *tokens.AccessTokenClaims) {
			c.Issuer = "https://elsewhere.test"
			c.Audience = []string{tokens.AdminAudience(c.Issuer)}
		},
		"expired": func(c *tokens.AccessTokenClaims) { c.Expiry = time.Now().Add(-time.Hour).Unix() },
		"sender-constrained": func(c *tokens.AccessTokenClaims) {
			c.Cnf = &tokens.Confirmation{JKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
		},
	} {
		c := a.claims(a.client, "")
		edit(&c)
		if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", a.sign(t, c), nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("a token %s answered %d", why, rec.Code)
		}
	}
	raw, err := a.other.SignJSON(good, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", raw, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token signed by a key not this deployment's answered %d", rec.Code)
	}

	revoked := a.claims(a.client, "")
	tx, err := a.s.db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeJTI(context.Background(), tx, revoked.JTI, a.client, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", a.sign(t, revoked), nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token answered %d", rec.Code)
	}
}

func TestAPersonActsWithTheirRolesFromAMultiFactorSession(t *testing.T) {
	a := newAdminTokens(t)
	person := newDriftUser(t, a.s)
	a.grant(t, store.RoleBinding{UserID: person, Role: "user-manager"})

	strong := a.sign(t, a.claims(person, a.session(t, person, "pwd", "otp")))
	weak := a.sign(t, a.claims(person, a.session(t, person, "pwd")))
	target := newDriftUser(t, a.s)

	rec := call(t, a.s, http.MethodPatch, "/admin/users/"+target, strong, map[string]any{"display_name": "set by a role"})
	if rec.Code != http.StatusOK {
		t.Fatalf("a user manager changing a person: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	rec = call(t, a.s, http.MethodPatch, "/admin/users/"+target, weak, map[string]any{"display_name": "x"})
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusForbidden || out["error"] != "multi_factor_required" {
		t.Errorf("a password-only session answered %d %v", rec.Code, out)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/clients?limit=1", strong, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a user manager listed applications: %d", rec.Code)
	}

	// The record names the person, and no admin token.
	var actor, principal string
	var tokenID *string
	if err := a.s.db.QueryRow(context.Background(), `
		SELECT COALESCE(actor_id::text, ''), detail->>'admin_principal', admin_token_id::text
		  FROM core.audit_events
		 WHERE event_type = 'admin.user_updated' AND subject_id = $1::uuid
		 ORDER BY occurred_at DESC LIMIT 1`, target).Scan(&actor, &principal, &tokenID); err != nil {
		t.Fatal(err)
	}
	if actor != person || principal != "user:"+person || tokenID != nil {
		t.Errorf("the record names actor %q, principal %q, token %v", actor, principal, tokenID)
	}

	// The session ended, or the person deactivated: refused at once.
	sid := a.session(t, person, "pwd", "hwk")
	tok := a.sign(t, a.claims(person, sid))
	if rec := call(t, a.s, http.MethodGet, "/admin/users/"+target, tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("before the session ended: %d", rec.Code)
	}
	if _, err := a.s.db.Exec(context.Background(), `UPDATE core.sessions
		SET revoked_at = now(), revocation_reason = 'logout' WHERE sid = $1`, sid); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/users/"+target, tok, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the session ended: %d", rec.Code)
	}
	if _, err := a.s.db.Exec(context.Background(), `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, person); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/users/"+target, strong, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the person was deactivated: %d", rec.Code)
	}

	// A person's token without a session is not a sign-in to administer with.
	if rec := call(t, a.s, http.MethodGet, "/admin/users/"+target, a.sign(t, a.claims(target, "")), nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a person's token with no session answered %d", rec.Code)
	}
}

// GET /admin/me says who the caller is (6.06): the console asks it on each
// request and signs out a person it no longer answers for.
func TestMeSaysWhoTheCallerIs(t *testing.T) {
	a := newAdminTokens(t)
	person := newDriftUser(t, a.s)
	group := newDriftGroup(t, a.s)
	a.grant(t, store.RoleBinding{UserID: person, Role: "user-manager", GroupID: group})
	a.grant(t, store.RoleBinding{UserID: person, Role: "auditor"})
	sid := a.session(t, person, "pwd", "otp")
	tok := a.sign(t, a.claims(person, sid))

	var me meView
	rec := call(t, a.s, http.MethodGet, "/admin/me", tok, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if rec.Code != http.StatusOK || me.Kind != "person" || me.User == nil || me.User.ID != person ||
		me.OrgID == nil || *me.OrgID != a.org || !slices.Contains(me.Scopes, ScopeAuditRead) ||
		len(me.Delegated[ScopeUsersWrite]) != 1 || me.Delegated[ScopeUsersRead] != nil || me.ExpiresAt == nil {
		t.Errorf("a person: %d %s", rec.Code, rec.Body.String())
	}

	// The session ended, the answer is 401, which is the console's cue.
	if _, err := a.s.db.Exec(context.Background(), `UPDATE core.sessions
		SET revoked_at = now(), revocation_reason = 'logout' WHERE sid = $1`, sid); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/me", tok, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the session ended: %d", rec.Code)
	}

	stored := mintToken(t, a.s, fmt.Sprintf("me-%d", time.Now().UnixNano()), a.org, []string{ScopeConfigRead}, nil)
	rec = call(t, a.s, http.MethodGet, "/admin/me", stored, nil)
	me = meView{}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if rec.Code != http.StatusOK || me.Kind != "token" || me.User != nil || !slices.Equal(me.Scopes, []string{ScopeConfigRead}) {
		t.Errorf("a stored token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, a.s, http.MethodGet, "/admin/me", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("nobody: %d", rec.Code)
	}
}

// The Admin API's audience is no organisation's resource server.
func TestTheAdminAudienceCannotBeRegisteredAsAResourceServer(t *testing.T) {
	s, _ := newTestServer(t)
	var issuer string
	if err := s.db.QueryRow(context.Background(), `SELECT issuer FROM core.instances ORDER BY created_at LIMIT 1`).Scan(&issuer); err != nil {
		t.Skip("no instance to take an issuer from")
	}
	rec := call(t, s, http.MethodPut, "/admin/organizations/"+anyOrgID(t, s)+"/resource-servers", testToken,
		map[string]any{"resource": tokens.AdminAudience(issuer), "name": "not the admin api"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("registering %s answered %d %s", tokens.AdminAudience(issuer), rec.Code, rec.Body.String())
	}
}
