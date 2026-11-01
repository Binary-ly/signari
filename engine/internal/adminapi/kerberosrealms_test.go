package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"signari.dev/engine/internal/store"
)

const testKerberosRealm = "EXAMPLE.COM"

func uniqueHost() string { return fmt.Sprintf("sso-%d.example.test", time.Now().UnixNano()) }

func testKeytab(t *testing.T, spn string) []byte {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(spn, testKerberosRealm, "a service password", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func kerberosRealmBody(t *testing.T, host string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"realm": testKerberosRealm, "host": host, "service_principal": "HTTP/" + host,
		"keytab": base64.StdEncoding.EncodeToString(testKeytab(t, "HTTP/"+host))})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// newDriftKerberosRealm registers a realm, and answers with its path.
func newDriftKerberosRealm(t *testing.T, s *Server) string {
	t.Helper()
	org := newDriftMigrationOrg(t, s, false)
	host := uniqueHost()
	if _, err := store.AddKerberosRealm(context.Background(), s.db, s.root, org, store.KerberosRealmSpec{
		Realm: testKerberosRealm, Host: host, ServicePrincipal: "HTTP/" + host, Keytab: testKeytab(t, "HTTP/"+host)}); err != nil {
		t.Fatal(err)
	}
	return "/admin/organizations/" + org + "/kerberos-realms/" + testKerberosRealm
}

// A realm through its whole life, and what it is refused. The keytab comes in once and
// is in nothing that comes back.
func TestAKerberosRealmIsKeptThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/kerberos-realms"
	host := uniqueHost()
	raw := testKeytab(t, "HTTP/"+host)
	encoded := base64.StdEncoding.EncodeToString(raw)

	refused := func(name string, body map[string]any, status int, want string) {
		t.Helper()
		rec := call(t, s, http.MethodPost, base, testToken, body)
		if rec.Code != status || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	good := func(change func(map[string]any)) map[string]any {
		body := map[string]any{"realm": "example.com", "host": host, "service_principal": "HTTP/" + host, "keytab": encoded}
		change(body)
		return body
	}
	refused("no realm", good(func(b map[string]any) { delete(b, "realm") }), http.StatusBadRequest, "invalid_kerberos_realm")
	refused("no host", good(func(b map[string]any) { delete(b, "host") }), http.StatusBadRequest, "invalid_kerberos_realm")
	refused("a URL for a host", good(func(b map[string]any) { b["host"] = "https://" + host }), http.StatusBadRequest,
		"invalid_kerberos_realm")
	refused("not base64", good(func(b map[string]any) { b["keytab"] = "!!" }), http.StatusBadRequest, "base64")
	refused("not a keytab", good(func(b map[string]any) { b["keytab"] = "bm90IGEga2V5dGFi" }), http.StatusBadRequest,
		"not a keytab")
	refused("a keytab for another service", good(func(b map[string]any) { b["service_principal"] = "HTTP/elsewhere" }),
		http.StatusBadRequest, "no key for")
	refused("a keytab of another realm", good(func(b map[string]any) { b["realm"] = "OTHER.TEST" }),
		http.StatusBadRequest, "no key for")

	rec := call(t, s, http.MethodPost, base, testToken, good(func(map[string]any) {}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"realm":"EXAMPLE.COM"`) {
		t.Errorf("the realm is not in its one spelling: %s", rec.Body.String())
	}

	// A host answers for one realm, whichever organisation asks.
	other := "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/kerberos-realms"
	again := call(t, s, http.MethodPost, other, testToken, good(func(map[string]any) {}))
	if again.Code != http.StatusConflict {
		t.Errorf("a host taken: %d %s", again.Code, again.Body.String())
	}

	list := call(t, s, http.MethodGet, base, testToken, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), host) {
		t.Fatalf("the list: %d %s", list.Code, list.Body.String())
	}
	for _, body := range []string{rec.Body.String(), list.Body.String()} {
		if strings.Contains(body, encoded) || strings.Contains(body, "keytab") {
			t.Errorf("the keytab came back: %s", body)
		}
	}

	// At rest it is sealed, and opens to what went in.
	var sealed []byte
	if err := s.db.QueryRow(context.Background(), `SELECT keytab_sealed FROM core.kerberos_realms WHERE host = $1`, host).
		Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "HTTP") {
		t.Error("the keytab is in the clear")
	}
	opened, err := store.KerberosRealmOfOrg(context.Background(), s.db, s.root, org, "example.com")
	if err != nil || opened == nil || string(opened.Keytab) != string(raw) {
		t.Fatalf("opening it: %v %v", opened, err)
	}

	if rec := call(t, s, http.MethodDelete, base+"/NOBODY.TEST", testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("no such realm: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, other+"/EXAMPLE.COM", testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation's realm: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, base+"/EXAMPLE.COM", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing: %d %s", rec.Code, rec.Body.String())
	}
	if opened, err := store.KerberosRealmOfOrg(context.Background(), s.db, s.root, org, "EXAMPLE.COM"); err != nil || opened != nil {
		t.Errorf("after removing: %v %v", opened, err)
	}
}
