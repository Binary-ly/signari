package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
)

// SAML metadata publishes the certificate of every RS256 key that is not
// retired: the active one, the next one so a provider pins it before it signs,
// and the passive one. Only the active one's was published, against
// docs/saml.md, so every rotation broke every provider that pins (2.40).
func TestSAMLMetadataPublishesTheNextAndPassiveCertificates(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	root, err := keys.NewRootKey("samlmeta-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var set []keys.Key
	want := map[string]bool{}
	for _, c := range []struct {
		alg   keys.Algorithm
		state keys.State
	}{
		{keys.RS256, keys.StateActive}, {keys.RS256, keys.StateNext}, {keys.RS256, keys.StatePassive},
		{keys.ES256, keys.StateActive},
	} {
		k, err := keys.Generate(keys.NewKID(), c.alg)
		if err != nil {
			t.Fatal(err)
		}
		k, _ = keys.WithState(k, c.state)
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.Save(ctx, tx, instanceID, k, root); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		kid := k.KID()
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE kid = $1`, kid)
		})
		set = append(set, k)
		if c.alg == keys.RS256 {
			want[kid] = true
		}
	}
	ks, err := keys.NewSet(set...)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(oidc.Config{Issuer: tokenTestIssuer, Keys: ks, AllowInsecureIssuer: true}, f.pool,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/metadata", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata answered %d: %s", rec.Code, rec.Body.String())
	}
	certs := regexp.MustCompile(`<ds:X509Certificate>([^<]+)</ds:X509Certificate>`).FindAllStringSubmatch(rec.Body.String(), -1)
	got := map[string]bool{}
	for _, m := range certs {
		der, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range set {
			if reflect.DeepEqual(cert.PublicKey, k.Signer().Public()) {
				got[k.KID()] = true
			}
		}
	}
	if len(certs) != len(want) || !reflect.DeepEqual(got, want) {
		t.Errorf("metadata carries %d certificate(s) for keys %v, want one for each RS256 key %v",
			len(certs), got, want)
	}
}
