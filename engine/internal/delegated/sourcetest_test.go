package delegated

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated/ldaptest"
	"signari.dev/engine/internal/safedial"
)

func untrustedCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{Subject: pkix.Name{CommonName: "another CA"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A test of a migration source names the step that failed (7.18), so a
// wrong CA, a wrong template and a stopped directory are each seen before a
// person's first sign-in meets them; and it asks exactly as that sign-in does.
func TestATestOfASourceNamesTheStepThatFailed(t *testing.T) {
	ctx := context.Background()
	url, caPEM, _, stop := ldaptest.Directory(t, `uid=alice,ou=people,dc=example`, "correct horse")
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.AllowPrivate("") })
	good := Source{Kind: "ldap", TokenEndpoint: url, BindDNTemplate: "uid={username},ou=people,dc=example",
		CAPEM: caPEM}
	v := New()

	if r := v.Test(ctx, good, "alice", "correct horse"); !r.OK || r.Step != "" {
		t.Errorf("the right source and credential: %+v", r)
	}
	for name, c := range map[string]struct {
		mutate func(*Source)
		step   string
		says   string
	}{
		"a wrong CA": {func(s *Source) { s.CAPEM = untrustedCA(t) }, StepTLS, "TLS handshake"},
		"a wrong template": {func(s *Source) { s.BindDNTemplate = "cn={username},ou=staff,dc=example" }, StepBind,
			"Invalid Credentials"},
		"plaintext":     {func(s *Source) { s.TokenEndpoint = "ldap://" + strings.TrimPrefix(url, "ldaps://") }, StepConfiguration, "StartTLS"},
		"no {username}": {func(s *Source) { s.BindDNTemplate = "uid=alice,dc=example" }, StepConfiguration, "{username}"},
	} {
		s := good
		c.mutate(&s)
		r := v.Test(ctx, s, "alice", "correct horse")
		if r.OK || r.Step != c.step || !strings.Contains(r.Detail, c.says) {
			t.Errorf("%s: %+v, want the %s step, saying %q", name, r, c.step, c.says)
		}
	}
	if r := v.Test(ctx, good, "alice", "wrong"); r.OK || r.Step != StepBind {
		t.Errorf("a wrong password: %+v", r)
	}
	stop()
	if r := v.Test(ctx, good, "alice", "correct horse"); r.OK || r.Step != StepDial {
		t.Errorf("a stopped directory: %+v, want the dial step", r)
	}
}

// The handshake is made here rather than by go-ldap's dial, which took the
// server name from the URL when the configuration named none; a caller that
// names only its roots still reaches the directory it named.
func TestADirectoryIsVerifiedByTheNameInItsURL(t *testing.T) {
	url, caPEM, _, _ := ldaptest.Directory(t, `uid=alice,ou=people,dc=example`, "correct horse")
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.AllowPrivate("") })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	if err := VerifyLDAP(context.Background(), LDAPSource{URL: url, BindDNTemplate: "uid={username},ou=people,dc=example",
		CACerts: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, "alice", "correct horse"); err != nil {
		t.Errorf("a configuration naming its roots and no server name: %v", err)
	}
}

func TestATestOfATokenEndpointNamesTheStepThatFailed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch {
		case r.PostForm.Get("client_id") != "ours":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
		case r.PostForm.Get("password") != "correct horse":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
		default:
			fmt.Fprint(w, `{"access_token":"x","token_type":"Bearer"}`)
		}
	}))
	t.Cleanup(srv.Close)
	v := NewWithClient(srv.Client())
	ctx := context.Background()
	good := Source{Kind: "oidc_password", TokenEndpoint: srv.URL + "/token", ClientID: "ours", Scope: "openid"}
	if r := v.Test(ctx, good, "alice", "correct horse"); !r.OK {
		t.Errorf("the right client and credential: %+v", r)
	}
	theirs := good
	theirs.ClientID = "not-registered"
	if r := v.Test(ctx, theirs, "alice", "correct horse"); r.OK || r.Step != StepAnswer ||
		!strings.Contains(r.Detail, "OUR client") {
		t.Errorf("a client the provider refuses: %+v", r)
	}
	plain := good
	plain.TokenEndpoint = "http://" + strings.TrimPrefix(srv.URL, "https://")
	if r := v.Test(ctx, plain, "alice", "correct horse"); r.OK || r.Step != StepConfiguration {
		t.Errorf("a plaintext token endpoint: %+v", r)
	}
	srv.Close()
	if r := v.Test(ctx, good, "alice", "correct horse"); r.OK || r.Step != StepDial {
		t.Errorf("a provider that is down: %+v", r)
	}
}
