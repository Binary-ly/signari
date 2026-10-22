package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Invitations over the Admin API (5.18).

func inviteBody(t *testing.T, rec interface{ Bytes() []byte }) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Bytes(), &out); err != nil {
		t.Fatalf("decoding %s: %v", rec.Bytes(), err)
	}
	return out
}

func forgetInvitation(t *testing.T, s *Server, id string) {
	t.Cleanup(func() {
		c := context.Background()
		_, _ = s.db.Exec(c, `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'link_id' = $2`,
			store.AccountNoticeTopic, id)
		_, _ = s.db.Exec(c, `DELETE FROM core.invitations WHERE id = $1::uuid`, id)
	})
}

// invitationState is what the list says of id, paging through it.
func invitationState(t *testing.T, s *Server, id string) string {
	t.Helper()
	cursor := ""
	for range 1000 {
		rec := call(t, s, http.MethodGet, "/admin/invitations?limit=200&cursor="+cursor, testToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("listing invitations gave %d %s", rec.Code, rec.Body.String())
		}
		var page struct {
			Invitations []invitationView `json:"invitations"`
			Next        string           `json:"next_cursor"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, v := range page.Invitations {
			if v.ID == id {
				return v.State
			}
		}
		if page.Next == "" {
			return "(not listed)"
		}
		cursor = page.Next
	}
	t.Fatal("paging never ended")
	return ""
}

// Made with its link returned once, the link works; revoked, it stops, and a
// second revoke is a 404.
func TestAnInvitationMadeThroughTheAPIWorksUntilRevoked(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	rec := call(t, s, http.MethodPost, "/admin/invitations", testToken, map[string]any{
		"org_id": org, "email": fmt.Sprintf("invitee-%d@example.test", time.Now().UnixNano()),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating an invitation gave %d %s", rec.Code, rec.Body.String())
	}
	out := inviteBody(t, rec.Body)
	id, _ := out["id"].(string)
	forgetInvitation(t, s, id)
	link, _ := out["link"].(string)
	u, err := url.Parse(link)
	if err != nil || !strings.HasSuffix(u.Path, "/signup") || u.Query().Get("invite") == "" {
		t.Fatalf("no usable link in %v", out)
	}
	token := u.Query().Get("invite")
	if inv, err := store.PeekInvitation(ctx, s.db, token); err != nil || inv.ID != id {
		t.Fatalf("the returned link does not open the invitation: %v", err)
	}
	if st := invitationState(t, s, id); st != "open" {
		t.Errorf("listed as %q, want open", st)
	}

	if rec := call(t, s, http.MethodDelete, "/admin/invitations/"+id, testToken, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking gave %d %s", rec.Code, rec.Body.String())
	}
	if _, err := store.PeekInvitation(ctx, s.db, token); err == nil {
		t.Error("the link still opens the invitation after it was revoked")
	}
	if rec := call(t, s, http.MethodDelete, "/admin/invitations/"+id, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a second revoke gave %d, want 404", rec.Code)
	}
	var created, revoked int
	if err := s.db.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE event_type = 'admin.invitation_created'),
		count(*) FILTER (WHERE event_type = 'admin.invitation_revoked' AND detail->>'via' = 'admin_api')
		FROM core.audit_events WHERE detail->>'invitation' = $1`, id).Scan(&created, &revoked); err != nil {
		t.Fatal(err)
	}
	if created != 1 || revoked != 1 {
		t.Errorf("audited created %d, revoked %d; want 1 and 1", created, revoked)
	}
}

// Sent, the link is never in the response nor in the outbox: it is made as
// the mail goes out, and made again by a retry, which ends the one before.
func TestASentInvitationsLinkIsNeverShown(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	if rec := call(t, s, http.MethodPost, "/admin/invitations", testToken, map[string]any{
		"org_id": org, "send": true,
	}); rec.Code != http.StatusBadRequest {
		t.Errorf("send with no address gave %d, want 400", rec.Code)
	}
	email := fmt.Sprintf("sent-%d@example.test", time.Now().UnixNano())
	rec := call(t, s, http.MethodPost, "/admin/invitations", testToken, map[string]any{
		"org_id": org, "email": email, "send": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating a sent invitation gave %d %s", rec.Code, rec.Body.String())
	}
	out := inviteBody(t, rec.Body)
	id, _ := out["id"].(string)
	forgetInvitation(t, s, id)
	if _, shown := out["link"]; shown {
		t.Errorf("a sent invitation's link was returned: %v", out)
	}
	var payload string
	if err := s.db.QueryRow(ctx, `SELECT payload::text FROM core.outbox WHERE topic = $1 AND payload->>'link_id' = $2`,
		store.AccountNoticeTopic, id).Scan(&payload); err != nil {
		t.Fatalf("no notice queued to send it: %v", err)
	}
	if strings.Contains(payload, "invite") && strings.Contains(payload, "token") {
		t.Errorf("the queued notice carries a token: %s", payload)
	}

	first, to, _, _, err := store.MintInvitationToken(ctx, s.db, id)
	if err != nil || to != email {
		t.Fatalf("minting for delivery: %q %v", to, err)
	}
	if _, err := store.PeekInvitation(ctx, s.db, first); err != nil {
		t.Errorf("the minted link does not open it: %v", err)
	}
	second, _, _, _, err := store.MintInvitationToken(ctx, s.db, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeekInvitation(ctx, s.db, first); err == nil {
		t.Error("a retry's new link left the earlier one working")
	}
	if _, err := store.PeekInvitation(ctx, s.db, second); err != nil {
		t.Errorf("the newest link does not open it: %v", err)
	}
}

// The groups an invitation grants are held to what adding a member is: they
// must exist, be ones the token may act on, and need the privileged scope when
// their members may impersonate.
func TestAnInvitationsGroupsAreHeldToMembershipRules(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	group := func(impersonate bool) (id, name string) {
		t.Helper()
		name = fmt.Sprintf("inv-%d", time.Now().UnixNano())
		if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
			VALUES ($1::uuid, $2, $2, $3) RETURNING id::text`, org, name, impersonate).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = s.db.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, id)
		})
		return id, name
	}
	invite := func(token string, groups ...string) (int, string) {
		t.Helper()
		rec := call(t, s, http.MethodPost, "/admin/invitations", token, map[string]any{"org_id": org, "groups": groups})
		if rec.Code == http.StatusCreated {
			id, _ := inviteBody(t, rec.Body)["id"].(string)
			forgetInvitation(t, s, id)
		}
		return rec.Code, rec.Body.String()
	}
	plainID, plain := group(false)
	_, admins := group(true)
	if code, body := invite(testToken, "no-such-group-anywhere"); code != http.StatusBadRequest || !strings.Contains(body, "no_such_group") {
		t.Errorf("a group that does not exist: %d %s", code, body)
	}
	usersOnly := narrowedToken(t, s, org, []string{ScopeUsersWrite}, nil, nil)
	if code, body := invite(usersOnly, admins); code != http.StatusForbidden || !strings.Contains(body, "privileged_target") {
		t.Errorf("into a group that may impersonate, without the privileged scope: %d %s", code, body)
	}
	if code, _ := invite(usersOnly, plain); code != http.StatusCreated {
		t.Errorf("into an ordinary group with users:write: %d", code)
	}
	narrowed := narrowedToken(t, s, org, []string{ScopeUsersWrite}, nil, []string{plainID})
	_, other := group(false)
	if code, body := invite(narrowed, other); code != http.StatusBadRequest || !strings.Contains(body, "no_such_group") {
		t.Errorf("a token narrowed to one group, into another: %d %s", code, body)
	}
	if code, _ := invite(narrowed, plain); code != http.StatusCreated {
		t.Errorf("a token narrowed to one group, into it: %d", code)
	}
}

// Another organisation's invitation answers as one that does not exist.
func TestAnotherOrganisationsInvitationCannotBeRevoked(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	id := newDriftInvitation(t, s)
	var other string
	if err := s.db.QueryRow(ctx, `SELECT id::text FROM core.organizations WHERE id <> $1::uuid LIMIT 1`, org).Scan(&other); err != nil {
		t.Skip("needs a second organisation")
	}
	elsewhere := narrowedToken(t, s, other, []string{ScopeUsersWrite}, nil, nil)
	if rec := call(t, s, http.MethodDelete, "/admin/invitations/"+id, elsewhere, nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation's token revoking: %d, want 404", rec.Code)
	}
	if st := invitationState(t, s, id); st != "open" {
		t.Errorf("after another organisation's attempt the invitation is %q, want open", st)
	}
}
