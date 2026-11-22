package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A read's ETag is the version from before its rows were read (0.20): a change
// that commits while the handler reads must leave the tag behind it, so the
// write sent back with the tag is refused rather than made over the change.
func TestAReadIsTaggedWithTheVersionFromBeforeItsRows(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	var before int64
	read := s.auth(ScopeConfigRead, func(w http.ResponseWriter, r *http.Request) {
		// Somebody else's change, committed while this read is under way.
		if err := s.db.QueryRow(ctx, `SELECT version FROM core.config_version`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(ctx, `UPDATE core.config_version SET version = version + 1, bumped_at = now()`); err != nil {
			t.Fatal(err)
		}
		s.writeList(w, r, map[string]any{"rows": []string{}})
	})
	rec := httptest.NewRecorder()
	read(rec, adminReq(t, http.MethodGet, "/admin/anything", "", ""))
	// No newer than the version when the rows began: other packages may move
	// it earlier still, which only makes the tag more cautious.
	var tagged int64
	if _, err := fmt.Sscanf(rec.Header().Get("ETag"), `"%d"`, &tagged); err != nil || tagged > before {
		t.Errorf("the read was tagged %q, after its rows began at %d: a write carrying this tag "+
			"would overwrite a change its reader never saw", rec.Header().Get("ETag"), before)
	}
}
