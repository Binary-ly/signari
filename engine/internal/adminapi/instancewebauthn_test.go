package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An instance's passkey identity and its legacy issuers are set through the
// Admin API as the instance commands set them (6.07), and a change of RP ID,
// which makes every passkey registered under the old unusable, is refused
// unless meant.
func TestAnInstancesPasskeyIdentityAndAliasesAreSetThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	id := newDriftInstance(t, s)
	webauthn := "/admin/instances/" + id + "/webauthn"
	errorOf := func(method, path string, body map[string]any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d %v, want %d", method, path, body, rec.Code, out, want)
		}
		e, _ := out["error"].(string)
		return e
	}

	for _, bad := range []string{"https://example.com", "192.168.1.1", "intranet", ""} {
		if e := errorOf(http.MethodPut, webauthn, map[string]any{"rp_id": bad}, http.StatusBadRequest); e != "invalid_rp_id" {
			t.Errorf("rp_id %q answered %q", bad, e)
		}
	}
	if e := errorOf(http.MethodPut, webauthn, map[string]any{"rp_id": "example.com",
		"related_origins": []string{"http://shop.example"}}, http.StatusBadRequest); e != "invalid_related_origin" {
		t.Errorf("a plaintext related origin answered %q", e)
	}
	if got, _ := store.InstanceWebAuthnOf(ctx, s.db, id); got.RPID != "" {
		t.Fatalf("a refused identity was stored: %+v", got)
	}

	if rec := call(t, s, http.MethodPut, webauthn, testToken, map[string]any{"rp_id": "example.com",
		"related_origins": []string{"https://example.co.uk"}}); rec.Code != http.StatusOK {
		t.Fatalf("setting the identity: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := store.InstanceWebAuthnOf(ctx, s.db, id)
	if got.RPID != "example.com" || got.DisplayName != "example.com" || len(got.RelatedOrigins) != 1 {
		t.Errorf("the identity reads %+v; an unnamed one is shown as its RP ID", got)
	}
	if e := errorOf(http.MethodPut, webauthn, map[string]any{"rp_id": "login.example.com"},
		http.StatusConflict); e != "rp_id_change_unconfirmed" {
		t.Errorf("an unconfirmed RP ID change answered %q", e)
	}
	if got, _ := store.InstanceWebAuthnOf(ctx, s.db, id); got.RPID != "example.com" {
		t.Errorf("an unconfirmed change moved the RP ID to %q", got.RPID)
	}
	rec := call(t, s, http.MethodPut, webauthn, testToken, map[string]any{"rp_id": "login.example.com",
		"replace_rp_id": true})
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out["replaced_rp_id"] != "example.com" || out["rp_id"] != "login.example.com" {
		t.Errorf("a confirmed change answered %d %v", rec.Code, out)
	}

	// Aliases: claimed, refused when malformed, retired.
	aliases := "/admin/instances/" + id + "/issuer-aliases"
	alias := fmt.Sprintf("https://legacy-%d.test", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.instance_issuer_aliases WHERE issuer = $1`, alias)
	})
	if e := errorOf(http.MethodPost, aliases, map[string]any{"alias": "http://plain.test"},
		http.StatusBadRequest); e != "invalid_issuer_alias" {
		t.Errorf("a plaintext alias answered %q", e)
	}
	if rec := call(t, s, http.MethodPost, aliases, testToken, map[string]any{"alias": alias}); rec.Code != http.StatusCreated {
		t.Fatalf("claiming the alias: %d %s", rec.Code, rec.Body.String())
	}
	live, err := store.LiveIssuerAliases(ctx, s.db, id)
	if err != nil || len(live) != 1 || live[0] != alias {
		t.Fatalf("the live aliases are %v (%v)", live, err)
	}
	if rec := call(t, s, http.MethodPatch, aliases, testToken, map[string]any{"alias": alias}); rec.Code != http.StatusOK {
		t.Fatalf("retiring the alias: %d %s", rec.Code, rec.Body.String())
	}
	if live, _ := store.LiveIssuerAliases(ctx, s.db, id); len(live) != 0 {
		t.Errorf("a retired alias is still accepted: %v", live)
	}
	if e := errorOf(http.MethodPatch, aliases, map[string]any{"alias": "https://never-claimed.test"},
		http.StatusBadRequest); e != "invalid_issuer_alias" {
		t.Errorf("retiring an alias the instance never claimed answered %q", e)
	}
}
