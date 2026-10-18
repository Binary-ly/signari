package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A refresh lineage minted under another organisation than its client's is
// refused rather than asked about by the wrong organisation's policy. The
// authorization endpoint issued such codes until it compared the session's
// organisation with the client's, so families like this can exist.
func TestARefreshFromAnotherOrganisationsLineageIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	var otherOrg string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'xr-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}

	raw, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	family, err := store.NewRefreshFamily(ctx, tx, otherOrg, f.clientID, f.userID, f.sid, nil, "", "")
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := store.IssueRefreshToken(ctx, tx, family, hash, []string{"openid", "offline_access"},
		nil, time.Hour); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	status, body := f.post(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {f.clientID},
	})
	desc, _ := body["error_description"].(string)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" ||
		!strings.Contains(desc, "organisation") {
		t.Fatalf("a lineage from another organisation refreshed: %d %v", status, body)
	}
}
