package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// Dynamic registration and its initial access tokens are managed through the
// Admin API as `signari registration` manages them (6.07), and what is written
// is what /oauth2/register redeems: a minted token registers while the policy
// is on, and not once it is revoked or registration is off.
func TestRegistrationAndItsTokensAreManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org
	redeems := func(token string) bool {
		t.Helper()
		sum := sha256.Sum256([]byte(token))
		_, _, err := store.RedeemRegistrationToken(ctx, s.db, sum[:], "")
		if err != nil && !errors.Is(err, store.ErrRegistrationClosed) {
			t.Fatal(err)
		}
		return err == nil
	}
	mint := func(tok string) (int, string) {
		t.Helper()
		rec := call(t, s, http.MethodPost, base+"/registration-tokens", tok, map[string]any{"name": "partner", "uses": 5})
		var out struct {
			ID, Token string
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Token + " " + out.ID
	}

	if rec := call(t, s, http.MethodPut, base+"/registration", testToken, map[string]any{"max_clients": 7,
		"allowed_scopes": []string{"openid"}}); rec.Code != http.StatusOK {
		t.Fatalf("turning registration on: %d %s", rec.Code, rec.Body.String())
	}
	rec := call(t, s, http.MethodGet, base+"/registration", testToken, nil)
	var v registrationView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Enabled || v.Open || v.AllowConfidential || v.MaxClients != 7 || len(v.AllowedScopes) != 1 {
		t.Errorf("the policy reads %+v", v)
	}

	code, minted := mint(testToken)
	if code != http.StatusCreated {
		t.Fatalf("minting a token: %d", code)
	}
	secret, id, _ := strings.Cut(minted, " ")
	if !redeems(secret) {
		t.Fatal("a minted token does not register while registration is on")
	}
	list := call(t, s, http.MethodGet, base+"/registration-tokens", testToken, nil)
	if !strings.Contains(list.Body.String(), id) || strings.Contains(list.Body.String(), secret) {
		t.Errorf("the token list either omits the token or shows its secret: %s", list.Body.String())
	}

	// Off, the token registers nothing; on again, it does.
	if rec := call(t, s, http.MethodDelete, base+"/registration", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("turning registration off: %d", rec.Code)
	}
	if redeems(secret) {
		t.Error("a token registered while registration was off")
	}
	if rec := call(t, s, http.MethodDelete, base+"/registration", testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("turning off registration that was off answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPut, base+"/registration", testToken, map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("turning registration on again: %d", rec.Code)
	}
	if !redeems(secret) {
		t.Error("the token did not register once registration was on again")
	}

	if rec := call(t, s, http.MethodDelete, base+"/registration-tokens/"+id, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoking the token: %d %s", rec.Code, rec.Body.String())
	}
	if redeems(secret) {
		t.Error("a revoked token registered")
	}
	if rec := call(t, s, http.MethodDelete, base+"/registration-tokens/"+id, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking a revoked token answered %d", rec.Code)
	}

	// A token limited to named applications lets nobody register new ones.
	narrowed, _, err := NewToken(ctx, s.db, "registration-narrowed-"+id, org,
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil, []string{"some-client"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := mint(narrowed); code != http.StatusForbidden {
		t.Errorf("a token limited to named applications minted a registration token: %d", code)
	}
	if rec := call(t, s, http.MethodPut, base+"/registration", narrowed, map[string]any{"open": true}); rec.Code != http.StatusForbidden {
		t.Errorf("a token limited to named applications opened registration: %d", rec.Code)
	}
}
