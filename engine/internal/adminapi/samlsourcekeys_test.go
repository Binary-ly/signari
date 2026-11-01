package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// driftSAMLKey makes a key toward an upstream and says its id.
func driftSAMLKey(t *testing.T, s *Server, org, slug, purpose string) string {
	t.Helper()
	k, err := store.AddSAMLSourceKey(context.Background(), s.db, s.root, org, slug, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return k.ID
}

// A key is made, shown, used and retired through the API as `signari idp saml-key`
// does it, with its certificate going out and its private half never.
func TestAnUpstreamsKeysAreKeptThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org, _, path := newDriftSAMLUpstream(t, s)
	signing := map[string]any{"sign_requests": true}

	if got := call(t, s, http.MethodPut, path+"/saml-key-use", testToken, signing); got.Code != http.StatusConflict ||
		!strings.Contains(got.Body.String(), "no signing key") {
		t.Fatalf("held to signing with no key: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, s, http.MethodPost, path+"/saml-keys", testToken, map[string]any{"purpose": "decoration"}); got.Code != http.StatusConflict {
		t.Fatalf("a key for nothing: %d %s", got.Code, got.Body.String())
	}

	made := call(t, s, http.MethodPost, path+"/saml-keys", testToken, map[string]any{"purpose": "signing"})
	if made.Code != http.StatusCreated || !strings.Contains(made.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("making a key: %d %s", made.Code, made.Body.String())
	}
	if strings.Contains(made.Body.String(), "PRIVATE KEY") {
		t.Fatal("the answer carries a private key")
	}
	var id string
	if err := s.db.QueryRow(context.Background(), `SELECT id::text FROM core.saml_source_keys WHERE org_id = $1::uuid`, org).Scan(&id); err != nil {
		t.Fatal(err)
	}
	listed := call(t, s, http.MethodGet, path+"/saml-keys", testToken, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), id) {
		t.Fatalf("listing: %d %s", listed.Code, listed.Body.String())
	}

	if got := call(t, s, http.MethodPut, path+"/saml-key-use", testToken, signing); got.Code != http.StatusOK {
		t.Fatalf("holding it to signing: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, s, http.MethodDelete, path+"/saml-keys/"+id, testToken, nil); got.Code != http.StatusConflict ||
		!strings.Contains(got.Body.String(), "last signing key") {
		t.Fatalf("retiring the key it is held to: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, s, http.MethodPut, path+"/saml-key-use", testToken, map[string]any{"sign_requests": false}); got.Code != http.StatusOK {
		t.Fatalf("letting it go: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, s, http.MethodDelete, path+"/saml-keys/"+id, testToken, nil); got.Code != http.StatusOK {
		t.Fatalf("retiring it: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, s, http.MethodDelete, path+"/saml-keys/"+id, testToken, nil); got.Code != http.StatusNotFound {
		t.Fatalf("retiring it twice: %d %s", got.Code, got.Body.String())
	}
}

// Reading an upstream's metadata again takes its logout address with the rest, and
// says so.
func TestARefreshTakesAnUpstreamsLogoutAddress(t *testing.T) {
	s, _ := newTestServer(t)
	org, _, path := newDriftSAMLUpstream(t, s)
	held := func() string {
		t.Helper()
		var got string
		if err := s.db.QueryRow(context.Background(), `SELECT COALESCE(end_session_url, '') FROM core.identity_providers
			WHERE org_id = $1::uuid`, org).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	plain := idpMetadata(t, s, path)
	with := strings.Replace(plain, "<SingleSignOnService ", `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/slo"/>
<SingleSignOnService `, 1)
	body := func(document string) map[string]any {
		return map[string]any{"metadata": document, "metadata_unsigned": true}
	}
	rec := call(t, s, http.MethodPost, path+"/metadata", testToken, body(with))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "slo_url") {
		t.Fatalf("reading it: %d %s", rec.Code, rec.Body.String())
	}
	if got := held(); got != "https://idp.example.test/slo" {
		t.Errorf("holding %q", got)
	}
	if rec := call(t, s, http.MethodPost, path+"/metadata", testToken, body(plain)); rec.Code != http.StatusOK {
		t.Fatalf("reading it again: %d %s", rec.Code, rec.Body.String())
	}
	if got := held(); got != "" {
		t.Errorf("an address the upstream took back is still held: %q", got)
	}
}

// Another organisation's upstream is not reached by naming its slug under yours.
func TestAnotherOrganisationsUpstreamHasNoKeysHere(t *testing.T) {
	s, _ := newTestServer(t)
	_, slug, _ := newDriftSAMLUpstream(t, s)
	other := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + other + "/identity-providers/" + slug
	if got := call(t, s, http.MethodPost, path+"/saml-keys", testToken, map[string]any{"purpose": "signing"}); got.Code != http.StatusNotFound {
		t.Errorf("making a key: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, s, http.MethodPut, path+"/saml-key-use", testToken, map[string]any{"sign_requests": false}); got.Code != http.StatusNotFound {
		t.Errorf("setting its use: %d %s", got.Code, got.Body.String())
	}
}
