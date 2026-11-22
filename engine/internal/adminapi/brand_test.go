package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An instance is branded through the Admin API as `signari brand set` brands
// it (6.07), by a deployment-wide caller only, and the brand written is the
// one its pages load: refused when unreadable, shown once set, gone once
// removed.
func TestAnInstanceIsBrandedByTheDeployment(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	id := newDriftInstance(t, s)
	var issuer string
	if err := s.db.QueryRow(ctx, `SELECT issuer FROM core.instances WHERE id = $1::uuid`, id).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	path := "/admin/instances/" + id + "/brand"
	shown := func() string {
		t.Helper()
		b, err := store.LoadBrandByIssuer(ctx, s.db, issuer)
		if err != nil {
			t.Fatal(err)
		}
		if b == nil {
			return ""
		}
		return b.ProductName
	}

	if rec := call(t, s, http.MethodGet, "/admin/instances", testToken, nil); !strings.Contains(rec.Body.String(), id) {
		t.Errorf("the instance list omits the instance: %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []map[string]any{
		{"product_name": "Acme", "logo_url": "http://acme.example/logo.png"},
		{"product_name": "Acme", "colour_primary": "#123456"},
		{"product_name": "Acme", "colour_primary": "#000000", "colour_on_primary": "#ffffff",
			"colour_background": "#777777", "colour_text": "#ffffff"},
	} {
		rec := call(t, s, http.MethodPut, path, testToken, bad)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_brand" {
			t.Errorf("%v answered %d %v", bad, rec.Code, out)
		}
	}
	if got := shown(); got != "" {
		t.Fatalf("a refused brand is shown: %q", got)
	}

	tenant := mintToken(t, s, fmt.Sprintf("brand-tenant-%d", time.Now().UnixNano()), anyOrgID(t, s),
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodPut, path, tenant, map[string]any{"product_name": "Mine"}); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token branded its instance: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, "/admin/instances", tenant, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token listed the instances: %d", rec.Code)
	}

	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"product_name": "Acme",
		"support_url": "https://help.acme.example"}); rec.Code != http.StatusOK {
		t.Fatalf("branding the instance: %d %s", rec.Code, rec.Body.String())
	}
	if got := shown(); got != "Acme" {
		t.Errorf("the pages show %q", got)
	}
	rec := call(t, s, http.MethodGet, path, testToken, nil)
	var v brandView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Branded || v.ProductName != "Acme" || v.SupportURL != "https://help.acme.example" {
		t.Errorf("the brand reads %+v", v)
	}

	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing the brand: %d", rec.Code)
	}
	if got := shown(); got != "" {
		t.Errorf("a removed brand is still shown: %q", got)
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("removing a removed brand answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, "/admin/instances/00000000-0000-4000-8000-000000000000/brand", testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("an instance nobody has answered %d", rec.Code)
	}
}
