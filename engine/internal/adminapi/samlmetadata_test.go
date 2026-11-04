package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// metadataCert is a certificate as PEM, and as metadata carries it.
func metadataCert(t *testing.T) (pemText, inMetadata string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "partner"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		base64.StdEncoding.EncodeToString(der)
}

func spDocument(entity, cert, acs string) string {
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
<ArtifactResolutionService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://sp.example.test/ars"/>
<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.test/slo"/>
<AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
<AssertionConsumerService index="2" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/other"/>
</SPSSODescriptor></EntityDescriptor>`, entity, cert, acs)
}

func idpDocument(entity, cert, sso string) string {
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
</IDPSSODescriptor></EntityDescriptor>`, entity, cert, sso)
}

func metadataBody(t *testing.T, document string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"metadata": document, "metadata_unsigned": true})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// spMetadata is a document for the provider at a path.
func spMetadata(t *testing.T, s *Server, path string) string {
	t.Helper()
	var entity string
	id := path[strings.LastIndex(path, "/")+1:]
	if err := s.db.QueryRow(context.Background(), `SELECT entity_id FROM core.saml_providers WHERE id = $1::uuid`,
		id).Scan(&entity); err != nil {
		t.Fatal(err)
	}
	_, cert := metadataCert(t)
	return spDocument(entity, cert, "https://sp.example.test/acs-moved")
}

func idpMetadata(t *testing.T, s *Server, path string) string {
	t.Helper()
	var entity string
	if err := s.db.QueryRow(context.Background(), `SELECT x.entity_id FROM core.saml_sources x
		JOIN core.identity_providers p ON p.id = x.provider_id WHERE p.slug = $1`,
		path[strings.LastIndex(path, "/")+1:]).Scan(&entity); err != nil {
		t.Fatal(err)
	}
	_, cert := metadataCert(t)
	return idpDocument(entity, cert, "https://idp.example.test/sso-moved")
}

// newDriftSAMLUpstream registers a SAML upstream, and answers its organisation,
// its slug and its path.
func newDriftSAMLUpstream(t *testing.T, s *Server) (org, slug, path string) {
	t.Helper()
	ctx := context.Background()
	org = newDriftMigrationOrg(t, s, false)
	slug = "saml-" + org[:8]
	certPEM, _ := metadataCert(t)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.AddIdentityProvider(ctx, tx, nil, org, store.IdentityProviderSpec{Slug: slug, Kind: "saml",
		EntityID: "https://idp-" + slug + ".example.test", SSOURL: "https://idp.example.test/sso", CertPEM: certPEM,
		NameIDFormat: "persistent"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return org, slug, "/admin/organizations/" + org + "/identity-providers/" + slug
}

// A service provider's whole life from its metadata: registered from the
// document, asked what a refresh would do, refreshed, and each thing that should
// be refused refused.
func TestAServiceProviderIsRegisteredFromItsMetadata(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/saml-providers"
	entity := "https://sp-" + org + ".example.test"
	_, cert := metadataCert(t)
	doc := spDocument(entity, cert, "https://sp.example.test/acs")

	// Nothing says how far to believe it.
	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"metadata": doc})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_metadata") {
		t.Fatalf("metadata with no word on trust: %d %s", rec.Code, rec.Body.String())
	}
	// Two answers to one question.
	rec = call(t, s, http.MethodPost, base, testToken, map[string]any{"metadata": doc, "metadata_unsigned": true,
		"acs_url": "https://elsewhere.example.test/acs"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("metadata and an ACS URL: %d %s", rec.Code, rec.Body.String())
	}

	rec = call(t, s, http.MethodPost, base, testToken, map[string]any{"metadata": doc, "metadata_unsigned": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering from metadata: %d %s", rec.Code, rec.Body.String())
	}
	var made struct {
		ID       string `json:"id"`
		EntityID string `json:"entity_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	if made.EntityID != entity {
		t.Errorf("entity id %q", made.EntityID)
	}
	listed := func() samlProviderView {
		t.Helper()
		rec := call(t, s, http.MethodGet, base, testToken, nil)
		var out struct {
			Providers []samlProviderView `json:"providers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Providers) != 1 {
			t.Fatalf("listing: %v, %s", err, rec.Body.String())
		}
		return out.Providers[0]
	}
	got := listed()
	if len(got.ACSURLs) != 2 || !got.HasSigningCert || len(got.SLOURLs) != 1 || got.MetadataReadAt == nil {
		t.Errorf("what was registered: %+v", got)
	}
	if len(got.ArtifactResolution) != 1 || got.ArtifactResolution[0] != (artifactResolutionService{1, "https://sp.example.test/ars"}) {
		t.Errorf("the artifact resolution service the metadata names was not taken: %+v", got.ArtifactResolution)
	}
	var def string
	if err := s.db.QueryRow(ctx, `SELECT url FROM core.saml_acs_urls WHERE provider_id = $1::uuid AND is_default`,
		made.ID).Scan(&def); err != nil || def != "https://sp.example.test/acs" {
		t.Errorf("the default ACS is %q, %v", def, err)
	}

	// A refresh with nothing moved reports that, and a move reports what moved.
	path := base + "/" + made.ID + "/metadata"
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": doc, "metadata_unsigned": true})
	var read struct {
		Applied bool                       `json:"applied"`
		Changes []store.SAMLMetadataChange `json:"changes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil || rec.Code != http.StatusOK || len(read.Changes) != 0 {
		t.Fatalf("a refresh that moves nothing: %d %s", rec.Code, rec.Body.String())
	}
	_, newCert := metadataCert(t)
	moved := spDocument(entity, newCert, "https://sp.example.test/moved")
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": moved, "metadata_unsigned": true, "dry_run": true})
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil || rec.Code != http.StatusOK || read.Applied || len(read.Changes) != 2 {
		t.Fatalf("a dry run: %d %s", rec.Code, rec.Body.String())
	}
	if after := listed(); after.ACSURLs[0] == "https://sp.example.test/moved" || after.ACSURLs[1] == "https://sp.example.test/moved" {
		t.Error("a dry run changed the provider")
	}
	// The version is the deployment's, and other tests move it, so what is read
	// is that a dry run has none to report.
	if strings.Contains(rec.Body.String(), "config_version") {
		t.Errorf("a dry run reports a configuration version: %s", rec.Body.String())
	}
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": moved, "metadata_unsigned": true})
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil || rec.Code != http.StatusOK || !read.Applied {
		t.Fatalf("a refresh: %d %s", rec.Code, rec.Body.String())
	}
	if err := s.db.QueryRow(ctx, `SELECT url FROM core.saml_acs_urls WHERE provider_id = $1::uuid AND is_default`,
		made.ID).Scan(&def); err != nil || def != "https://sp.example.test/moved" {
		t.Errorf("after a refresh the default ACS is %q, %v", def, err)
	}
	var audited int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE event_type = 'admin.saml_metadata_read'
		AND org_id = $1::uuid AND detail->>'entity_id' = $2`, org, entity).Scan(&audited); err != nil || audited != 2 {
		t.Errorf("recorded %d times, %v; a dry run is not recorded", audited, err)
	}

	// Another provider's document does not refresh this one.
	other := spDocument("https://somebody-else.example.test", newCert, "https://evil.example.test/acs")
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": other, "metadata_unsigned": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a stranger's metadata: %d %s", rec.Code, rec.Body.String())
	}
	// Nor does an identity provider's.
	idp := idpDocument(entity, newCert, "https://idp.example.test/sso")
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": idp, "metadata_unsigned": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("metadata in the wrong role: %d %s", rec.Code, rec.Body.String())
	}
	// Nor is another organisation's provider reached.
	stranger := newDriftMigrationOrg(t, s, false)
	rec = call(t, s, http.MethodPost, "/admin/organizations/"+stranger+"/saml-providers/"+made.ID+"/metadata",
		testToken, map[string]any{"metadata": moved, "metadata_unsigned": true})
	if rec.Code != http.StatusNotFound {
		t.Errorf("through another organisation: %d %s", rec.Code, rec.Body.String())
	}
}

// A provider imported under a signature does not lose it by being asked again:
// the signer is held, and an unsigned document is refused until somebody says so
// by name. What is held does not reach a timer: nothing calls this but a person.
func TestARefreshIsHeldToTheTermsOfTheImport(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	entity := "https://sp-" + org + ".example.test"
	_, cert := metadataCert(t)
	signerPEM, _ := metadataCert(t)
	ctx := context.Background()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := store.AddSAMLProvider(ctx, tx, org, store.SAMLProviderSpec{EntityID: entity,
		ACSURL: "https://sp.example.test/acs",
		Origin: store.SAMLMetadataOrigin{Read: true, SignerPEM: signerPEM}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	path := "/admin/organizations/" + org + "/saml-providers/" + id + "/metadata"
	doc := spDocument(entity, cert, "https://evil.example.test/acs")
	rec := call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": doc})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no signature") {
		t.Fatalf("an unsigned document for a signed partner: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": doc, "metadata_unsigned": true,
		"metadata_signer": signerPEM})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a signer and unsigned at once: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": doc, "metadata_unsigned": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("dropping the signature by name: %d %s", rec.Code, rec.Body.String())
	}
	var signer *string
	if err := s.db.QueryRow(ctx, `SELECT metadata_signer FROM core.saml_providers WHERE id = $1::uuid`, id).
		Scan(&signer); err != nil || signer != nil {
		t.Errorf("the signer after dropping it: %v, %v", signer, err)
	}

	// With nothing given and no URL held, there is nowhere to read from.
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata_unsigned": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("nothing to read: %d %s", rec.Code, rec.Body.String())
	}
}

// What a provider says it no longer needs does not undo an operator's decision.
func TestARefreshDoesNotUndoAnOperatorsDecision(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	entity := "https://sp-" + org + ".example.test"
	certPEM, cert := metadataCert(t)
	ctx := context.Background()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := store.AddSAMLProvider(ctx, tx, org, store.SAMLProviderSpec{EntityID: entity,
		ACSURL: "https://sp.example.test/acs", SigningCertPEM: certPEM, WantSignedRequests: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	path := "/admin/organizations/" + org + "/saml-providers/" + id + "/metadata"
	rec := call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata_unsigned": true,
		"metadata": spDocument(entity, cert, "https://sp.example.test/acs")})
	if rec.Code != http.StatusOK {
		t.Fatalf("a refresh: %d %s", rec.Code, rec.Body.String())
	}
	var want bool
	if err := s.db.QueryRow(ctx, `SELECT want_authn_requests_signed FROM core.saml_providers WHERE id = $1::uuid`, id).
		Scan(&want); err != nil || !want {
		t.Errorf("metadata silent on signed requests turned them off: %v, %v", want, err)
	}
	// And a document that takes away the key those requests are checked with is
	// not applied at all.
	noKey := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs"/>
</SPSSODescriptor></EntityDescriptor>`, entity)
	rec = call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": noKey, "metadata_unsigned": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a document that removes the only key: %d %s", rec.Code, rec.Body.String())
	}
}

// Encrypting is the operator's to turn on: a document offering a key does not,
// and for a provider already encrypted, a new key moves it along.
func TestAnEncryptionKeyIsTakenOnlyWhereEncryptionIsOn(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/saml-providers"
	entity := "https://sp-" + org + ".example.test"
	_, signing := metadataCert(t)
	rsaPEM := func() (string, string) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "encryption"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			base64.StdEncoding.EncodeToString(der)
	}
	offering := func(cert string) string {
		return strings.Replace(spDocument(entity, signing, "https://sp.example.test/acs"), "<SingleLogoutService",
			`<KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>`+
				cert+`</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService`, 1)
	}
	firstPEM, first := rsaPEM()
	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"metadata": offering(first), "metadata_unsigned": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var made struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	key := func() string {
		t.Helper()
		var got *string
		if err := s.db.QueryRow(ctx, `SELECT sp_encryption_cert FROM core.saml_providers WHERE id = $1::uuid`, made.ID).
			Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got == nil {
			return ""
		}
		return *got
	}
	if key() != "" {
		t.Fatal("a key offered turned encryption on at registration")
	}
	path := base + "/" + made.ID + "/metadata"
	if rec := call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": offering(first), "metadata_unsigned": true}); rec.Code != http.StatusOK {
		t.Fatalf("a refresh: %d %s", rec.Code, rec.Body.String())
	}
	if key() != "" {
		t.Fatal("a key offered turned encryption on at a refresh")
	}
	if _, err := s.db.Exec(ctx, `UPDATE core.saml_providers SET sp_encryption_cert = $2 WHERE id = $1::uuid`, made.ID, firstPEM); err != nil {
		t.Fatal(err)
	}
	secondPEM, second := rsaPEM()
	if rec := call(t, s, http.MethodPost, path, testToken, map[string]any{"metadata": offering(second), "metadata_unsigned": true}); rec.Code != http.StatusOK {
		t.Fatalf("a refresh with a new key: %d %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(key()) != strings.TrimSpace(secondPEM) {
		t.Error("a provider already encrypted did not move to its new key")
	}
	// And metadata_encrypt asks for it by name.
	other := newDriftMigrationOrg(t, s, false)
	entity = "https://sp-" + other + ".example.test"
	rec = call(t, s, http.MethodPost, "/admin/organizations/"+other+"/saml-providers", testToken, map[string]any{
		"metadata": offering(second), "metadata_unsigned": true, "metadata_encrypt": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("asking for encryption: %d %s", rec.Code, rec.Body.String())
	}
	var encrypted bool
	if err := s.db.QueryRow(ctx, `SELECT sp_encryption_cert IS NOT NULL FROM core.saml_providers WHERE entity_id = $1`, entity).
		Scan(&encrypted); err != nil || !encrypted {
		t.Errorf("metadata_encrypt: %v, %v", encrypted, err)
	}
}

// An upstream's whole life from its metadata, and read from where it publishes.
func TestAnUpstreamIsRegisteredFromItsMetadataAndReadAgain(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	slug := "saml-" + org[:8]
	entity := "https://idp-" + slug + ".example.test"
	_, cert := metadataCert(t)
	current := idpDocument(entity, cert, "https://idp.example.test/sso")
	published := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(current))
	}))
	defer published.Close()
	client := published.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	s.outbound = func(time.Duration) *http.Client { return client }

	base := "/admin/organizations/" + org + "/identity-providers"
	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"kind": "saml", "slug": slug,
		"metadata_url": published.URL + "/md", "metadata_unsigned": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering from a URL: %d %s", rec.Code, rec.Body.String())
	}
	var sso, stored string
	var read *time.Time
	row := func() {
		t.Helper()
		if err := s.db.QueryRow(ctx, `SELECT x.sso_url, COALESCE(x.metadata_url, ''), x.metadata_read_at
			FROM core.saml_sources x JOIN core.identity_providers p ON p.id = x.provider_id WHERE p.slug = $1`, slug).
			Scan(&sso, &stored, &read); err != nil {
			t.Fatal(err)
		}
	}
	row()
	if sso != "https://idp.example.test/sso" || stored != published.URL+"/md" || read == nil {
		t.Errorf("registered with %q from %q at %v", sso, stored, read)
	}

	// The upstream moves, and nothing happens until somebody asks.
	_, newCert := metadataCert(t)
	current = idpDocument(entity, newCert, "https://idp.example.test/moved")
	row()
	if sso != "https://idp.example.test/sso" {
		t.Fatal("the upstream's move took effect with nobody asking")
	}
	rec = call(t, s, http.MethodPost, base+"/"+slug+"/metadata", testToken, map[string]any{"metadata_unsigned": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("a refresh from the URL held: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Changes []store.SAMLMetadataChange `json:"changes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Changes) != 2 {
		t.Fatalf("what moved: %s", rec.Body.String())
	}
	row()
	if sso != "https://idp.example.test/moved" {
		t.Errorf("after a refresh the SSO URL is %q", sso)
	}

	// A document for somebody else does not take this upstream's place.
	current = idpDocument("https://somebody-else.example.test", newCert, "https://evil.example.test/sso")
	rec = call(t, s, http.MethodPost, base+"/"+slug+"/metadata", testToken, map[string]any{"metadata_unsigned": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a stranger's metadata at the same URL: %d %s", rec.Code, rec.Body.String())
	}
	// An OAuth provider has none.
	_, _, oidcPath := newDriftIdP(t, s, "oidc")
	rec = call(t, s, http.MethodPost, oidcPath+"/metadata", testToken, map[string]any{"metadata_unsigned": true})
	if rec.Code != http.StatusNotFound {
		t.Errorf("an OIDC provider's metadata: %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Providers []identityProviderView `json:"providers"`
	}
	rec = call(t, s, http.MethodGet, base, testToken, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Providers) != 1 ||
		list.Providers[0].MetadataURL != published.URL+"/md" {
		t.Errorf("the list: %v, %s", err, rec.Body.String())
	}
}
