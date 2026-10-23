package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// `idp add` registers through the checks the Admin API makes
// (store.IdentityProviderSpec): a SAML upstream from its certificate file,
// believed about addresses since its assertion cannot say otherwise; a named
// provider by its client; and belief in a named provider's email_verified
// refused, since its preset decides it and the flag was dropped silently.
func TestIdPAddRegistersThroughTheSharedChecks(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) }) // after the delete below

	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation to register a provider in: %v", err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	samlSlug, ghSlug, googleSlug := "add-saml-"+suffix, "add-gh-"+suffix, "add-google-"+suffix
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = ANY($1)`,
			[]string{samlSlug, ghSlug, googleSlug})
	})

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	srv.Close() // only its certificate is wanted
	certFile := filepath.Join(t.TempDir(), "idp.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	add := func(args ...string) error {
		return run(append([]string{"idp", "add", "-dsn", dsn, "-org", org}, args...))
	}

	if err := add("-kind", "saml", "-slug", samlSlug, "-entity-id", "https://idp.example.test/"+suffix,
		"-sso-url", "https://idp.example.test/sso", "-sp-cert", certFile); err != nil {
		t.Fatal(err)
	}
	var format string
	var trusts bool
	if err := db.QueryRow(ctx, `SELECT x.name_id_format, p.trust_email_verification FROM core.saml_sources x
		JOIN core.identity_providers p ON p.id = x.provider_id WHERE p.slug = $1`, samlSlug).
		Scan(&format, &trusts); err != nil || format != "persistent" || !trusts {
		t.Errorf("the SAML upstream reads %q, trusts %v (%v)", format, trusts, err)
	}
	if err := add("-kind", "saml", "-slug", samlSlug, "-entity-id", "e", "-sso-url", "https://i.example.test",
		"-sp-cert", certFile); err == nil || !strings.Contains(err.Error(), "already taken") {
		t.Errorf("a taken slug: %v", err)
	}
	if err := add("-kind", "saml", "-slug", "add-transient-"+suffix, "-entity-id", "e", "-sso-url",
		"https://i.example.test", "-sp-cert", certFile, "-nameid-format", "transient"); err == nil {
		t.Error("a transient NameID was registered")
	}

	if err := add("-kind", "github", "-slug", ghSlug, "-client-id-ext", "signari"); err != nil {
		t.Fatal(err)
	}
	var scopes []string
	if err := db.QueryRow(ctx, `SELECT scopes FROM core.identity_providers WHERE slug = $1`, ghSlug).
		Scan(&scopes); err != nil || len(scopes) == 0 {
		t.Errorf("the GitHub provider has scopes %v (%v)", scopes, err)
	}
	if err := add("-kind", "google", "-slug", googleSlug, "-client-id-ext", "signari",
		"-trust-email-verification"); err == nil {
		t.Error("a Google provider was told to believe its own email_verified")
	}
	var n int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM core.identity_providers WHERE slug = $1`, googleSlug).Scan(&n)
	if n != 0 {
		t.Error("the refused Google provider was stored")
	}
}
