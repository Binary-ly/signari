package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

func tokenHeader(t *testing.T, tok string) (alg, kid string) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct{ Alg, Kid string }
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.Alg, h.Kid
}

// A client's tokens are signed with the algorithm it is set to, and it can be
// set only to one its instance holds an active key for. ES256 for everybody,
// so EdDSA, "opt-in per client", could not be opted into (2.23).
func TestAClientsTokensAreSignedWithItsAlgorithm(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = ARRAY['client_credentials'],
		client_type = 'confidential', client_secret_hash = $2, scopes = ARRAY['api']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	grantAlg := func() (string, string) {
		t.Helper()
		status, body := f.post(t, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {f.clientID},
			"client_secret": {secret}, "scope": {"api"},
		})
		if status != http.StatusOK {
			t.Fatalf("client_credentials answered %d %v", status, body)
		}
		return tokenHeader(t, body["access_token"].(string))
	}
	set := func(alg string) error {
		t.Helper()
		return setClientSettings(t, f, store.ClientSettings{IDTokenAlg: &alg})
	}

	if alg, _ := grantAlg(); alg != "ES256" {
		t.Fatalf("by default the token is signed %s", alg)
	}
	for _, alg := range []string{"HS256", "none", "RS256", "EdDSA"} {
		if err := set(alg); !errors.Is(err, store.ErrInvalidClientSetting) {
			t.Errorf("%s with no such active key answered %v", alg, err)
		}
	}

	// An active RS256 key, in the database for the check and in the server's
	// set for the signature, as `keys rotate -alg RS256` would leave it.
	rk, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := keys.WithState(rk, keys.StateActive)
	next, err := keys.NewSet(append(f.srv.cfg.Keys.Keys(), rs)...)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Keys = next
	root, err := keys.NewRootKey("clientalg-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Save(ctx, tx, instanceID, rs, root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE kid = $1`, rs.KID())
	})

	if err := set("RS256"); err != nil {
		t.Fatalf("RS256 with an active key answered %v", err)
	}
	if alg, kid := grantAlg(); alg != "RS256" || kid != rs.KID() {
		t.Errorf("set to RS256, the token is signed %s by %s", alg, kid)
	}
}
