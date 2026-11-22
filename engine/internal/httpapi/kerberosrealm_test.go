package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"signari.dev/engine/internal/kerberos"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/store/storetest"
)

// testRealm is an organisation's realm, and the service key a KDC of it would hold.
type testRealm struct {
	org, realm, host, spn string
	keytab                *keytab.Keytab
}

func serviceKeytab(t *testing.T, realm string, services ...string) (*keytab.Keytab, []byte) {
	t.Helper()
	kt := keytab.New()
	for _, spn := range services {
		if err := kt.AddEntry(spn, realm, "the key of "+spn, time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return kt, raw
}

func newTestRealm(t *testing.T, f *signInFixture, org, name string, strip bool, extra ...string) *testRealm {
	t.Helper()
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	r := &testRealm{org: org, realm: fmt.Sprintf("%s%d.TEST", name, stamp), host: fmt.Sprintf("sso-%s-%d.test", strings.ToLower(name), stamp)}
	r.spn = "HTTP/" + r.host
	var raw []byte
	r.keytab, raw = serviceKeytab(t, r.realm, append([]string{r.spn}, extra...)...)
	if _, err := store.AddKerberosRealm(ctx, f.pool, f.srv.cfg.Root, org, store.KerberosRealmSpec{Realm: r.realm, Host: r.host,
		ServicePrincipal: r.spn, Keytab: raw, StripRealm: strip}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.kerberos_realms WHERE host = $1`, r.host)
	})
	return r
}

// ticket is what a browser sends: a service ticket a KDC of crealm would have issued,
// sealed with the service key in kt, and an authenticator made with its session key.
func ticket(t *testing.T, kt *keytab.Keytab, who, crealm, spn, srealm string) string {
	t.Helper()
	sname, _ := types.ParseSPNString(spn)
	now := time.Now().UTC()
	tkt, key, err := messages.NewTicket(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, who), crealm, sname, srealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1, now, now, now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	init, err := spnego.NewNegTokenInitKRB5(client.NewWithPassword(who, crealm, "unused", config.New()), tkt, key)
	if err != nil {
		t.Fatal(err)
	}
	token := spnego.SPNEGOToken{Init: true, NegTokenInit: init}
	raw, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(raw)
}

func kerberosAt(f *signInFixture, host, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/login/kerberos", nil)
	r.Host = host
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// signedInAs reads whose session an answer started.
func signedInAs(t *testing.T, f *signInFixture, rec *httptest.ResponseRecorder) (user, org string) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			if err := f.pool.QueryRow(context.Background(), `SELECT user_id::text, org_id::text FROM core.sessions
				WHERE cookie_hash = $1`, store.HashToken(c.Value)).Scan(&user, &org); err != nil {
				t.Fatal(err)
			}
			return user, org
		}
	}
	return "", ""
}

// Two organisations, two realms, the same name in each. Everything a ticket could do
// wrong here lands somebody in the other customer's organisation.
func TestATicketSignsInToTheOrganisationOfItsRealm(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root

	var otherOrg string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'realm-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, f.pool, otherOrg)
	alpha := newTestRealm(t, f, f.orgID, "ALPHA", false, "HTTP/another.service.test")
	beta := newTestRealm(t, f, otherOrg, "BETA", true)

	person := func(org, email, username string) string {
		t.Helper()
		var id string
		if err := f.pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email, username)
			VALUES ($1::uuid, decode(repeat(md5(random()::text),4),'hex'), $2, NULLIF($3, '')) RETURNING id::text`,
			org, email, username).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	inAlpha := person(f.orgID, "ada@"+strings.ToLower(alpha.realm), "")
	inBeta := person(otherOrg, "somebody.else@beta.test", "ada")

	rec := kerberosAt(f, alpha.host, ticket(t, alpha.keytab, "ada", alpha.realm, alpha.spn, alpha.realm))
	if user, org := signedInAs(t, f, rec); user != inAlpha || org != f.orgID {
		t.Errorf("alpha's ticket signed in %q of %q: %d %.200s", user, org, rec.Code, rec.Body.String())
	}
	// The other, matched by name: the realm is stripped, so the name is not an address.
	rec = kerberosAt(f, beta.host+":8443", ticket(t, beta.keytab, "ada", beta.realm, beta.spn, beta.realm))
	if user, org := signedInAs(t, f, rec); user != inBeta || org != otherOrg {
		t.Errorf("beta's ticket signed in %q of %q: %d %.200s", user, org, rec.Code, rec.Body.String())
	}

	for name, attempt := range map[string]func() *httptest.ResponseRecorder{
		"a ticket shown to the other realm's host": func() *httptest.ResponseRecorder {
			return kerberosAt(f, beta.host, ticket(t, alpha.keytab, "ada", alpha.realm, alpha.spn, alpha.realm))
		},
		"a ticket to another service in the keytab": func() *httptest.ResponseRecorder {
			return kerberosAt(f, alpha.host, ticket(t, alpha.keytab, "ada", alpha.realm, "HTTP/another.service.test", alpha.realm))
		},
		"a ticket the key cannot have made": func() *httptest.ResponseRecorder {
			forged, _ := serviceKeytab(t, alpha.realm, alpha.spn)
			forged.Entries[0].Key.KeyValue[0] ^= 0xff
			return kerberosAt(f, alpha.host, ticket(t, forged, "ada", alpha.realm, alpha.spn, alpha.realm))
		},
		"no ticket": func() *httptest.ResponseRecorder { return kerberosAt(f, alpha.host, "") },
	} {
		rec := attempt()
		if user, _ := signedInAs(t, f, rec); user != "" {
			t.Errorf("%s signed in %s", name, user)
		}
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Negotiate") {
			t.Errorf("%s answered %d %q", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}

	// A trust would have the other realm's person arrive with this key.
	rec = kerberosAt(f, beta.host, ticket(t, beta.keytab, "ada", alpha.realm, beta.spn, beta.realm))
	if user, _ := signedInAs(t, f, rec); user != "" || rec.Code != http.StatusForbidden {
		t.Errorf("a person of another realm: %d, signed in %q", rec.Code, user)
	}

	// With no keytab behind a host there is nothing here, or every domain browser
	// would show a credential dialog for a service that cannot check the answer.
	rec = kerberosAt(f, "nobody.test", "")
	if rec.Code != http.StatusNotFound || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("a host with no realm: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	// A host with none of its own takes the one the environment names, as before.
	envKeytab, _ := serviceKeytab(t, "ENV.TEST", "HTTP/env.test")
	f.srv.krbKeytab, f.srv.krbConfig = envKeytab, kerberos.Config{Realm: "ENV.TEST"}
	if err := f.pool.QueryRow(ctx, `SELECT i.issuer FROM core.instances i JOIN core.organizations o ON o.instance_id = i.id
		WHERE o.id = $1::uuid`, f.orgID).Scan(&f.srv.cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	rec = kerberosAt(f, "nobody.test", ticket(t, envKeytab, "ada", "ENV.TEST", "HTTP/env.test", "ENV.TEST"))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "no account") {
		t.Errorf("the environment's realm: %d %.200s", rec.Code, rec.Body.String())
	}
	f.srv.krbKeytab = nil

	// A server of another instance has no such host.
	served := f.srv.instanceID
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://other-' || gen_random_uuid() || '.test', 'Other') RETURNING id::text`).Scan(&f.srv.instanceID); err != nil {
		t.Fatal(err)
	}
	rec = kerberosAt(f, alpha.host, ticket(t, alpha.keytab, "ada", alpha.realm, alpha.spn, alpha.realm))
	if user, _ := signedInAs(t, f, rec); user != "" || rec.Code != http.StatusNotFound {
		t.Errorf("another instance's realm: %d, signed in %q", rec.Code, user)
	}
	f.srv.instanceID = served

	// Removed, it stops at once: nothing holds the keytab.
	if _, err := store.RemoveKerberosRealm(ctx, f.pool, f.orgID, alpha.realm); err != nil {
		t.Fatal(err)
	}
	rec = kerberosAt(f, alpha.host, ticket(t, alpha.keytab, "ada", alpha.realm, alpha.spn, alpha.realm))
	if user, _ := signedInAs(t, f, rec); user != "" || rec.Code != http.StatusNotFound {
		t.Errorf("after removing the realm: %d, signed in %q", rec.Code, user)
	}
}
