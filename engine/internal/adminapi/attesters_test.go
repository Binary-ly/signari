package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/store"
)

// keySetOf is a JSON Web Key Set holding k, which may be public or private.
func keySetOf(t *testing.T, k any) []byte {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k, KeyID: "attester-1",
		Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// publicJWKS is an attester's public key set.
func publicJWKS(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keySetOf(t, &k.PublicKey)
}

// An attester is trusted and withdrawn through the Admin API as `signari
// attester add` trusts one (6.07): its key set checked before it is stored,
// a private key refused, and its keys never read back.
func TestAClientAttesterIsTrustedAndWithdrawnThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/attesters/wallet-provider"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for why, jwks := range map[string]string{
		"not a key set":   `"nope"`,
		"no keys":         `{"keys":[]}`,
		"a private key":   string(keySetOf(t, priv)),
		"an unusable key": `{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`,
	} {
		rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"jwks": json.RawMessage(jwks)})
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_attester" {
			t.Errorf("a key set with %s answered %d %v", why, rec.Code, out)
		}
	}
	if got, _ := store.OrgAttesters(ctx, s.db, org); len(got) != 0 {
		t.Fatalf("a refused attester was stored: %+v", got)
	}

	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"jwks": json.RawMessage(publicJWKS(t)),
		"description": "the wallet vendor"}); rec.Code != http.StatusOK {
		t.Fatalf("trusting the attester: %d %s", rec.Code, rec.Body.String())
	}
	rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/attesters", testToken, nil)
	if !strings.Contains(rec.Body.String(), `"name":"wallet-provider"`) || strings.Contains(rec.Body.String(), `"crv"`) {
		t.Errorf("the attesters read %s; listed by name, never by key", rec.Body.String())
	}
	// What client authentication verifies against.
	if trusted, err := store.TrustedAttesters(ctx, s.db, org); err != nil || len(trusted) != 1 {
		t.Fatalf("the authentication path trusts %d attesters (%v)", len(trusted), err)
	}

	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("withdrawing the attester: %d", rec.Code)
	}
	if trusted, _ := store.TrustedAttesters(ctx, s.db, org); len(trusted) != 0 {
		t.Errorf("a withdrawn attester is still trusted by the authentication path: %d", len(trusted))
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("withdrawing a withdrawn attester answered %d", rec.Code)
	}
}
