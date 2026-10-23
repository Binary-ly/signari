package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An inbound SCIM source is registered and switched off and on through the
// Admin API as `signari scim-source` does it (6.07): its token shown once,
// stored hashed, and refused at /scim/v2 while the source is off.
func TestASCIMSourceIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/scim-sources"
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "hr-directory", "on_delete": "erase"}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown deletion policy answered %d", rec.Code)
	}
	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "hr-directory", "name": "HR directory"})
	var made struct{ ID, Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || len(made.Token) < 40 {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var hash []byte
	var onDelete string
	var enabled bool
	read := func() {
		if err := s.db.QueryRow(ctx, `SELECT token_hash, on_delete, enabled FROM core.scim_sources WHERE id = $1::uuid`,
			made.ID).Scan(&hash, &onDelete, &enabled); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if sum := sha256.Sum256([]byte(made.Token)); !bytes.Equal(hash, sum[:]) || onDelete != "deactivate" || !enabled {
		t.Errorf("stored with a matching hash %v, on_delete %q, enabled %v", bytes.Equal(hash, sum[:]), onDelete, enabled)
	}
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "hr-directory"}); rec.Code != http.StatusConflict {
		t.Errorf("a second source of the slug answered %d", rec.Code)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), made.Token) || !strings.Contains(list.Body.String(), `"slug":"hr-directory"`) {
		t.Errorf("the sources read %s", list.Body.String())
	}

	if rec := call(t, s, http.MethodPatch, base+"/hr-directory", testToken, map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disabling: %d %s", rec.Code, rec.Body.String())
	}
	if read(); enabled {
		t.Error("a disabled source is still enabled")
	}
	// The lookup /scim/v2 authenticates a bearer token with.
	if _, err := store.FindSCIMSourceByToken(ctx, s.db, hash); err == nil {
		t.Error("a disabled source's token still authenticates")
	}
	if rec := call(t, s, http.MethodPatch, base+"/hr-directory", testToken, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enabling: %d", rec.Code)
	}
	if read(); !enabled {
		t.Error("an enabled source is still disabled")
	}
	if _, err := store.FindSCIMSourceByToken(ctx, s.db, hash); err != nil {
		t.Errorf("an enabled source's token does not authenticate: %v", err)
	}
	if rec := call(t, s, http.MethodPatch, base+"/elsewhere", testToken, map[string]any{"enabled": false}); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown source answered %d", rec.Code)
	}
}
