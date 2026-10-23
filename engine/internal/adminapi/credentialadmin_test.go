package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/store"
)

// newDriftWallet is an organisation of the test's own served by an instance
// of its own, with a wallet client registered for the pre-authorized code
// grant, a credential it issues and a person to offer it to.
func newDriftWallet(t *testing.T, s *Server) (org, client, config, userID string) {
	t.Helper()
	ctx := context.Background()
	instance := newDriftInstance(t, s) // first, so it is removed after the organisation
	org = newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `UPDATE core.organizations SET instance_id = $1::uuid WHERE id = $2::uuid`,
		instance, org); err != nil {
		t.Fatal(err)
	}
	client = clientIn(t, s, org)
	if _, err := s.db.Exec(ctx, `UPDATE core.clients SET grant_types = array_append(grant_types, $2)
		WHERE client_id = $1`, client, oid4vci.GrantType); err != nil {
		t.Fatal(err)
	}
	config = "drift-id"
	if _, err := store.DefineCredential(ctx, s.db, org, store.CredentialSpec{ConfigID: config,
		VCT: "https://drift.example.test/id", Always: []string{"email"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2)
		RETURNING id::text`, org, "holder-"+org[:8]+"@example.test").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	// Before the organisation's cleanup, which a person in it would refuse.
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, userID) })
	return org, client, config, userID
}

// testCertPEM is a certificate, a CA's or not, and its key's PEM.
func testCertPEM(t *testing.T, ca bool) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: "Drift Wallet Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

// A credential is defined, a key proof root trusted and withdrawn, and an
// offer minted for a person through the Admin API as `signari credential`
// does it (6.07), the offer redeemable for that person by the client chosen.
func TestCredentialIssuanceIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, client, config, userID := newDriftWallet(t, s)
	answer := func(method, p string, body any, want int) map[string]any {
		t.Helper()
		rec := call(t, s, method, p, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, p, body, rec.Code, want, rec.Body.String())
		}
		return out
	}

	// Definitions, keeping an attestation requirement unless told.
	configs := "/admin/organizations/" + org + "/credential-configurations"
	answer(http.MethodPut, configs+"/staff", map[string]any{"vct": "https://drift.example.test/staff",
		"always": []string{"email"}, "selective": []string{"preferred_username"}, "lifetime_s": 3600,
		"require_key_attestation": true}, http.StatusOK)
	if out := answer(http.MethodPut, configs+"/staff", map[string]any{"vct": "https://drift.example.test/staff",
		"always": []string{"email", "sub"}}, http.StatusOK); out["require_key_attestation"] != true {
		t.Errorf("redefining without the requirement answered %v", out)
	}
	got, err := store.CredentialConfigurations(ctx, s.db, org)
	if err != nil {
		t.Fatal(err)
	}
	if c := got["staff"]; !c.RequireKeyAttestation || len(c.AlwaysClaims) != 2 || c.Lifetime != 0 {
		t.Errorf("the issuer loads %+v", c)
	}
	list := call(t, s, http.MethodGet, configs, testToken, nil)
	if !strings.Contains(list.Body.String(), `"id":"staff"`) || !strings.Contains(list.Body.String(), `"id":"`+config+`"`) {
		t.Errorf("the configurations read %s", list.Body.String())
	}
	for name, body := range map[string]map[string]any{
		"a claim off the list":  {"vct": "https://v.example.test", "always": []string{"ssn"}},
		"a claim in both lists": {"vct": "https://v.example.test", "always": []string{"email"}, "selective": []string{"email"}},
		"no claims":             {"vct": "https://v.example.test"},
		"no vct":                {"always": []string{"email"}},
		"a negative lifetime":   {"vct": "https://v.example.test", "always": []string{"email"}, "lifetime_s": -1},
	} {
		if out := answer(http.MethodPut, configs+"/refused", body, http.StatusBadRequest); out["error"] != "invalid_credential" {
			t.Errorf("%s answered %v", name, out)
		}
	}
	if _, ok := mustConfigs(t, s, org)["refused"]; ok {
		t.Error("a refused configuration was stored")
	}

	// Roots: a CA's certificate alone.
	roots := "/admin/organizations/" + org + "/credential-proof-roots"
	ca, caKey := testCertPEM(t, true)
	leaf, _ := testCertPEM(t, false)
	if out := answer(http.MethodPut, roots+"/wallet", map[string]any{"certificate": ca}, http.StatusOK); !strings.Contains(fmtAny(out["subject"]), "Drift Wallet Root") {
		t.Errorf("trusting the root answered %v", out)
	}
	if pool, err := store.CredentialProofRoots(ctx, s.db, org); err != nil || pool == nil {
		t.Errorf("the credential endpoint reads roots %v (%v)", pool, err)
	}
	for name, cert := range map[string]string{"a certificate with its key": ca + caKey, "two certificates": ca + ca,
		"a certificate that is not a CA's": leaf, "nothing": ""} {
		if out := answer(http.MethodPut, roots+"/refused", map[string]any{"certificate": cert}, http.StatusBadRequest); out["error"] != "invalid_root" {
			t.Errorf("%s answered %v", name, out)
		}
	}
	if list := call(t, s, http.MethodGet, roots, testToken, nil); !strings.Contains(list.Body.String(), `"name":"wallet"`) ||
		strings.Contains(list.Body.String(), `"name":"refused"`) {
		t.Errorf("the roots read %s", list.Body.String())
	}
	answer(http.MethodDelete, roots+"/wallet", nil, http.StatusOK)
	if out := answer(http.MethodDelete, roots+"/wallet", nil, http.StatusNotFound); out["error"] != "root_not_found" {
		t.Errorf("withdrawing it again answered %v", out)
	}

	// An offer, redeemable for the person by the client chosen, with the
	// instance's issuer when none is named.
	offers := "/admin/users/" + userID + "/credential-offers"
	out := answer(http.MethodPost, offers, map[string]any{"client_id": client, "credential_configurations": []string{config},
		"tx_code": true}, http.StatusCreated)
	offer, _ := out["offer"].(map[string]any)
	grants, _ := offer["grants"].(map[string]any)
	pre, _ := grants[oid4vci.GrantType].(map[string]any)
	code, _ := pre["pre-authorized_code"].(string)
	txCode, _ := out["tx_code"].(string)
	if code == "" || len(txCode) != 6 || !strings.HasPrefix(fmtAny(offer["credential_issuer"]), "https://drift-") ||
		!strings.HasPrefix(fmtAny(out["offer_uri"]), oid4vci.CredentialOfferURIScheme+"://?credential_offer=") {
		t.Fatalf("the offer answered %v", out)
	}
	stored, err := store.LookupPreAuthorizedCode(ctx, s.db, store.HashToken(code))
	if err != nil {
		t.Fatal(err)
	}
	if stored.UserID != userID || stored.ClientID != client || !stored.RequiresTxCode ||
		!stored.CheckTxCode(store.HashToken(txCode)) || stored.CheckTxCode(store.HashToken("000000x")) {
		t.Errorf("the redemption reads user %s, client %s, tx %v", stored.UserID, stored.ClientID, stored.RequiresTxCode)
	}

	// Another organisation's wallet client, registered for the grant, so the
	// organisation is the only thing refusing it.
	_, elsewhere, _, _ := newDriftWallet(t, s)
	noGrant := clientIn(t, s, org)
	for name, c := range map[string]struct {
		body map[string]any
		want int
		code string
	}{
		"an unknown configuration": {map[string]any{"client_id": client, "credential_configurations": []string{"nope"}},
			http.StatusBadRequest, "invalid_credential"},
		"a configuration twice": {map[string]any{"client_id": client, "credential_configurations": []string{config, config}},
			http.StatusBadRequest, "invalid_credential"},
		"an offer of two hours": {map[string]any{"client_id": client, "credential_configurations": []string{config},
			"expires_in_s": 7200}, http.StatusBadRequest, "invalid_credential"},
		"another organisation's client": {map[string]any{"client_id": elsewhere,
			"credential_configurations": []string{config}}, http.StatusBadRequest, "invalid_credential"},
		"a client that cannot redeem": {map[string]any{"client_id": noGrant, "credential_configurations": []string{config}},
			http.StatusConflict, "client_cannot_redeem"},
		"a plaintext issuer": {map[string]any{"client_id": client, "credential_configurations": []string{config},
			"credential_issuer": "http://issuer.example.test"}, http.StatusBadRequest, "invalid_credential"},
		"a three-digit code": {map[string]any{"client_id": client, "credential_configurations": []string{config},
			"tx_code": true, "tx_code_length": 3}, http.StatusBadRequest, "invalid_credential"},
	} {
		if out := answer(http.MethodPost, offers, c.body, c.want); out["error"] != c.code {
			t.Errorf("%s answered %v", name, out)
		}
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.preauthorized_codes WHERE user_id = $1::uuid`, userID).
		Scan(&n); err != nil || n != 1 {
		t.Errorf("the person has %d offers after one was made and the rest refused (%v)", n, err)
	}
}

func mustConfigs(t *testing.T, s *Server, org string) map[string]oid4vci.Configuration {
	t.Helper()
	got, err := store.CredentialConfigurations(context.Background(), s.db, org)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func fmtAny(v any) string {
	s, _ := v.(string)
	return s
}

// A token narrowed to some applications cannot change what the organisation
// issues, nor offer a credential through an application it was not given.
func TestANarrowedTokenCannotConfigureIssuance(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, client, config, userID := newDriftWallet(t, s)
	other := clientIn(t, s, org)
	narrowed, _, err := NewToken(ctx, s.db, "credential-narrowed-"+other, org,
		[]string{ScopeOrganizationsWrite, ScopeUsersWrite}, nil, []string{other}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(narrowed))
	})
	ca, _ := testCertPEM(t, true)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/admin/organizations/" + org + "/credential-configurations/narrowed",
			map[string]any{"vct": "https://v.example.test", "always": []string{"email"}}},
		{http.MethodPut, "/admin/organizations/" + org + "/credential-proof-roots/narrowed", map[string]any{"certificate": ca}},
		{http.MethodPost, "/admin/users/" + userID + "/credential-offers",
			map[string]any{"client_id": client, "credential_configurations": []string{config}}},
	} {
		if rec := call(t, s, c.method, c.path, narrowed, c.body); rec.Code != http.StatusForbidden {
			t.Errorf("a narrowed token's %s %s answered %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	var n int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.preauthorized_codes WHERE user_id = $1::uuid`, userID).Scan(&n)
	if n != 0 {
		t.Error("the narrowed token's offer was made")
	}
}
