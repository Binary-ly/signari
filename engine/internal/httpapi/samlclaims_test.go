package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
)

// A SAML assertion's attributes reach the same mapping an ID token's claims do. One
// value is a claim, and several stay a list, which maps onto nothing rather than onto
// a guess at which of them was meant.
func TestSAMLAttributesBecomeClaims(t *testing.T) {
	raw := samlAttributeClaims(&saml.InboundAssertion{Attributes: map[string][]string{
		"department":                      {"Maths"},
		"urn:oid:0.9.2342.19200300.100.1": {"ada"},
		"groups":                          {"a", "b"},
	}})
	claims := map[string]any{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["department"] != "Maths" || claims["urn:oid:0.9.2342.19200300.100.1"] != "ada" {
		t.Errorf("read %v", claims)
	}
	if list, ok := claims["groups"].([]any); !ok || len(list) != 2 {
		t.Errorf("several values read %v", claims["groups"])
	}
	if raw := samlAttributeClaims(&saml.InboundAssertion{}); string(raw) != "{}" {
		t.Errorf("no attributes read %s", raw)
	}
}

// A signed assertion through the real ACS: its attribute lands on the person, and one
// addressed to another service provider's ACS gets nobody signed in.
func TestAnAssertionsAttributeReachesThePerson(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	secret := make([]byte, 32)
	secret[0] = 8
	root, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	slug := fmt.Sprintf("src-%d", time.Now().UnixNano())
	const upstream = "https://upstream.test/idp"
	var providerID string
	if err := f.pool.QueryRow(ctx, `WITH ip AS (
		  INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		  VALUES ($1::uuid, $2, 'Upstream', 'saml', '', '{}') RETURNING id
		)
		INSERT INTO core.saml_sources (provider_id, org_id, entity_id, sso_url, cert_pem, allow_unsolicited)
		SELECT id, $1::uuid, $3, 'https://upstream.test/sso', $4, true FROM ip
		RETURNING provider_id::text`, f.orgID, slug, upstream, certPEM).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	var attribute string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.user_attribute_schema (org_id, name, display_name, value_type, personal)
		VALUES ($1::uuid, 'department', 'Department', 'string', false) RETURNING id::text`, f.orgID).Scan(&attribute); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.idp_attribute_map (provider_id, org_id, upstream_claim, attribute_id)
		VALUES ($1::uuid, $2::uuid, 'department', $3::uuid)`, providerID, f.orgID, attribute); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'ada-at-upstream')`, providerID, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}

	acs := f.srv.cfg.Issuer + "/saml/source/" + slug + "/acs"
	post := func(recipient string) *httptest.ResponseRecorder {
		t.Helper()
		doc, err := saml.BuildResponse(saml.ResponseInput{Issuer: upstream, Destination: recipient,
			Audience: f.srv.cfg.Issuer, Lifetime: 2 * time.Minute, Now: time.Now(),
			Subject: saml.Subject{NameID: "ada-at-upstream", NameIDFormat: saml.NameIDFormatPersistent,
				AuthnInstant: time.Now(), Attributes: map[string][]string{"department": {"Maths"}, "clearance": {"top"}}}},
			"k1", key, der)
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(doc))}}
		r := httptest.NewRequest(http.MethodPost, "/saml/source/"+slug+"/acs", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	held := func() string {
		t.Helper()
		var value string
		err := f.pool.QueryRow(ctx, `SELECT COALESCE(value, '') FROM core.user_attributes
			WHERE user_id = $1::uuid AND attribute_id = $2::uuid`, f.userID, attribute).Scan(&value)
		if err != nil && !strings.Contains(err.Error(), "no rows") {
			t.Fatal(err)
		}
		return value
	}

	signedIn := func(rec *httptest.ResponseRecorder) bool {
		for _, c := range rec.Result().Cookies() {
			if c.Name == SessionCookieName && c.Value != "" {
				return true
			}
		}
		return false
	}

	if rec := post("https://other-sp.test/saml/acs"); signedIn(rec) {
		t.Fatal("an assertion for another service provider signed somebody in")
	}
	if v := held(); v != "" {
		t.Fatalf("an assertion for another service provider wrote %q", v)
	}

	if rec := post(acs); !signedIn(rec) {
		t.Fatalf("a good assertion answered %d %q: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if v := held(); v != "Maths" {
		t.Errorf("the attribute reads %q", v)
	}
}
