package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An event subscription is made, rotated, re-enabled, tested and removed
// through the Admin API as `signari events` does it (6.07): its secret shown
// once and never read back, a destination and an event type checked first.
func TestAnEventSubscriptionIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/event-subscriptions"
	errorOf := func(body map[string]any, want int) string {
		t.Helper()
		rec := call(t, s, http.MethodPost, base, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%v answered %d, want %d", body, rec.Code, want)
		}
		e, _ := out["error"].(string)
		return e
	}
	if e := errorOf(map[string]any{"name": "siem", "url": "http://siem.example/hook"}, http.StatusBadRequest); e != "invalid_url" {
		t.Errorf("a plaintext URL answered %q", e)
	}
	if e := errorOf(map[string]any{"name": "siem", "url": "https://127.0.0.1/hook"}, http.StatusBadRequest); e != "invalid_url" {
		t.Errorf("a loopback URL answered %q", e)
	}
	if e := errorOf(map[string]any{"name": "siem", "url": "https://siem.example.test/hook",
		"event_types": []string{"login.failure"}}, http.StatusBadRequest); e != "unknown_event_type" {
		t.Errorf("an event type nothing records answered %q", e)
	}

	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"name": "siem",
		"url": "https://siem.example.test/hook", "event_types": []string{"login.failed"}})
	var made struct{ ID, Secret string }
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || made.Secret == "" {
		t.Fatalf("subscribing: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(map[string]any{"name": "siem", "url": "https://other.example.test/hook"}, http.StatusConflict); e != "already_exists" {
		t.Errorf("a second subscription of the name answered %q", e)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), made.Secret) || !strings.Contains(list.Body.String(), `"login.failed"`) {
		t.Errorf("the subscriptions read %s", list.Body.String())
	}

	sealed := func() []byte {
		var b []byte
		if err := s.db.QueryRow(ctx, `SELECT secret_sealed FROM core.event_subscriptions WHERE id = $1::uuid`,
			made.ID).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := sealed()
	rec = call(t, s, http.MethodPost, base+"/siem/rotate-secret", testToken, nil)
	var rotated struct{ Secret string }
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rec.Code != http.StatusOK || rotated.Secret == "" || rotated.Secret == made.Secret || bytes.Equal(sealed(), before) {
		t.Errorf("rotating the secret answered %d and the stored secret moved: %v", rec.Code, !bytes.Equal(sealed(), before))
	}

	if err := store.DisableSubscription(ctx, s.db, made.ID, "ten failures"); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodPost, base+"/siem/enable", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("enabling: %d", rec.Code)
	}
	var enabled bool
	_ = s.db.QueryRow(ctx, `SELECT enabled FROM core.event_subscriptions WHERE id = $1::uuid`, made.ID).Scan(&enabled)
	if !enabled {
		t.Error("an enabled subscription is still off")
	}

	if rec := call(t, s, http.MethodPost, base+"/siem/test", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("testing: %d %s", rec.Code, rec.Body.String())
	}
	var queued int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.event_deliveries WHERE subscription_id = $1::uuid`, made.ID).Scan(&queued)
	if queued != 1 {
		t.Errorf("a test queued %d deliveries", queued)
	}

	if rec := call(t, s, http.MethodDelete, base+"/siem", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing: %d", rec.Code)
	}
	for _, path := range []string{base + "/siem", base + "/siem/enable"} {
		method := http.MethodPost
		if path == base+"/siem" {
			method = http.MethodDelete
		}
		if rec := call(t, s, method, path, testToken, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s of a removed subscription answered %d", method, path, rec.Code)
		}
	}
}
