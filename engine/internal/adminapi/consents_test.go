package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"signari.dev/engine/internal/store"
)

// An administrator sees what a person consented to, and withdraws it through
// the path /account/connected takes (6.08).
func TestAnAdministratorWithdrawsAConsent(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	user, client := newDriftUser(t, s), newPreconditionClient(t, s)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordConsent(ctx, tx, user, client, []string{"openid", "profile"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	listed := func() []consentView {
		t.Helper()
		rec := call(t, s, http.MethodGet, "/admin/users/"+user+"/consents", testToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Consents []consentView `json:"consents"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return body.Consents
	}
	if got := listed(); len(got) != 1 || got[0].ClientID != client || len(got[0].Scopes) != 2 {
		t.Fatalf("the consent is not listed: %+v", got)
	}

	// A token narrowed to another client neither sees nor touches it.
	narrow := mintToken(t, s, "consent-narrow-"+client, anyOrgID(t, s), []string{ScopeUsersWrite},
		nil)
	if _, err := s.db.Exec(ctx, `UPDATE core.admin_tokens SET client_ids = ARRAY['some-other-client']
		WHERE name = $1`, "consent-narrow-"+client); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodDelete, "/admin/users/"+user+"/consents/"+client, narrow, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a token narrowed to another client withdrew this one's consent: %d", rec.Code)
	}

	rec := call(t, s, http.MethodDelete, "/admin/users/"+user+"/consents/"+client, testToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("withdraw: %d %s", rec.Code, rec.Body.String())
	}
	if got := listed(); len(got) != 0 {
		t.Errorf("the withdrawn consent is still listed: %+v", got)
	}
	var withdrawn bool
	if err := s.db.QueryRow(ctx, `SELECT withdrawn_at IS NOT NULL FROM core.consents
		WHERE user_id = $1::uuid AND client_id = $2`, user, client).Scan(&withdrawn); err != nil || !withdrawn {
		t.Errorf("the consent is not withdrawn: %v %v", withdrawn, err)
	}
	var recorded int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE event_type = 'admin.consent_revoked'
		AND subject_id = $1::uuid AND client_id = $2`, user, client).Scan(&recorded)
	if recorded != 1 {
		t.Errorf("%d withdrawal records", recorded)
	}
}
