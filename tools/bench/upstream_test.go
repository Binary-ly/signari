package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// The mock is only worth measuring against if what it says would pass. So its ID token
// is read as a relying party reads one: by the key its own JWKS publishes, for the
// nonce that was sent, and its SCIM store answers the filter a client finds people by.
func TestTheUpstreamAnswersAsAProviderWould(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u := newUpstream("https://upstream.test", key, 3)
	srv := httptest.NewServer(u.routes())
	t.Cleanup(srv.Close)
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	getJSON := func(path string, into any) {
		t.Helper()
		resp, err := hc.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}

	resp, err := hc.Get(srv.URL + "/authorize?" + url.Values{"redirect_uri": {"https://engine.test/cb"},
		"state": {"s1"}, "nonce": {"n1"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || back.Query().Get("state") != "s1" || back.Query().Get("code") == "" {
		t.Fatalf("the redirect back was %q", resp.Header.Get("Location"))
	}
	resp, err = hc.PostForm(srv.URL+"/token", url.Values{"code": {back.Query().Get("code")}, "client_id": {"engine"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []struct {
			X, Y string
		} `json:"keys"`
	}
	getJSON("/jwks", &set)
	x, _ := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	y, _ := base64.RawURLEncoding.DecodeString(set.Keys[0].Y)
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("an ID token of %d parts", len(parts))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(public, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the ID token does not verify against the published key")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["nonce"] != "n1" || claims["aud"] != "engine" || claims["iss"] != "https://upstream.test" {
		t.Errorf("the ID token said %v", claims)
	}

	created, err := hc.Post(srv.URL+"/scim/v2/Users", "application/scim+json", strings.NewReader(`{"userName":"a@b.test"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("creating a person answered %d", created.StatusCode)
	}
	var found struct {
		Total     int              `json:"totalResults"`
		Resources []map[string]any `json:"Resources"`
	}
	getJSON("/scim/v2/Users?"+url.Values{"filter": {`userName eq "a@b.test"`}}.Encode(), &found)
	if found.Total != 1 || len(found.Resources) != 1 || found.Resources[0]["id"] == "" {
		t.Errorf("the filter found %+v", found)
	}
	getJSON("/scim/v2/Users?"+url.Values{"filter": {`userName eq "nobody@b.test"`}}.Encode(), &found)
	if found.Total != 0 {
		t.Errorf("the filter found somebody who is not there: %+v", found)
	}
}

// A provider that cannot be taken is an error, not a result: the scenario would
// otherwise time a password sign-in and call it a federated one.
func TestASignInViaAProviderTakesItsLink(t *testing.T) {
	var went []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<form method="POST" action="/login"><input name="username"></form>` +
			`<a href="/login/with/up?return=x&amp;y=1">Up</a>`))
	})
	mux.HandleFunc("GET /login/with/up", func(w http.ResponseWriter, r *http.Request) {
		went = append(went, r.URL.RawQuery)
		http.Error(w, "stop here", http.StatusTeapot)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	hc := httpClient(&config{})
	e := &env{cfg: &config{Via: "up", RedirectURI: "https://bench.invalid/cb"},
		md: discovery{AuthorizationEndpoint: srv.URL + "/login"}}
	if _, err := signIn(t.Context(), hc, e); err == nil || !strings.Contains(err.Error(), "418") {
		t.Errorf("the sign-in ended with %v", err)
	}
	if len(went) != 1 || went[0] != "return=x&y=1" {
		t.Errorf("the link was followed as %q", went)
	}
	e.cfg.Via = "other"
	if _, err := signIn(t.Context(), hc, e); err == nil || !strings.Contains(err.Error(), "offers no provider") {
		t.Errorf("a provider the page does not offer gave %v", err)
	}
}

// A real LDAP client reads the whole directory through it, page by page, as a sync does,
// which is what a short page or a bad cookie would stop: the client's paged search
// treats either as a failure.
func TestTheUpstreamDirectoryPagesToTheEnd(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = serveDirectory(l, 25) }()

	conn, err := ldap.DialURL("ldap://" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Bind("cn=reader,dc=load,dc=test", "x"); err != nil {
		t.Fatal(err)
	}
	res, err := conn.SearchWithPaging(ldap.NewSearchRequest("dc=load,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"entryUUID", "uid", "mail", "cn"}, nil), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 25 {
		t.Fatalf("read %d of 25", len(res.Entries))
	}
	first, last := res.Entries[0], res.Entries[24]
	if first.GetAttributeValue("uid") != "dir-1" || last.GetAttributeValue("uid") != "dir-25" {
		t.Errorf("read %s to %s", first.DN, last.DN)
	}
	if first.GetAttributeValue("entryUUID") == last.GetAttributeValue("entryUUID") ||
		!strings.HasSuffix(last.GetAttributeValue("mail"), "@"+benchDomain) {
		t.Errorf("entries that do not tell people apart: %+v", last.Attributes)
	}
}

// RFC 4226 Appendix D's first two vectors, the secret "12345678901234567890", which is
// what the TOTP scenario's codes are computed by.
func TestAnHOTPCodeIsWhatAnAppWouldShow(t *testing.T) {
	key := []byte("12345678901234567890")
	for counter, want := range []string{"755224", "287082"} {
		if got := hotpCode(key, uint64(counter)); got != want {
			t.Errorf("counter %d gave %s, want %s", counter, got, want)
		}
	}
}

// An assertion is signed over what WebAuthn says it is, and each use counts up, or an
// engine would read the second as a cloned authenticator.
func TestASoftPasskeySignsWhatItSays(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &softPasskey{id: []byte("credential"), handle: []byte("person"), key: key, rpID: "id.test", origin: "https://id.test"}
	counts := map[uint32]bool{}
	for range 2 {
		body, err := p.assert("challenge")
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Response struct {
				ClientDataJSON, AuthenticatorData, Signature string
			} `json:"response"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		data, _ := base64.RawURLEncoding.DecodeString(got.Response.AuthenticatorData)
		cdj, _ := base64.RawURLEncoding.DecodeString(got.Response.ClientDataJSON)
		sig, _ := base64.RawURLEncoding.DecodeString(got.Response.Signature)
		rp := sha256.Sum256([]byte("id.test"))
		if !bytes.Equal(data[:32], rp[:]) || data[32]&flagUserVerified == 0 {
			t.Errorf("the authenticator data does not name the party or say the person was verified: %x", data)
		}
		cdh := sha256.Sum256(cdj)
		digest := sha256.Sum256(append(append([]byte(nil), data...), cdh[:]...))
		if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
			t.Error("the assertion does not verify")
		}
		counts[binary.BigEndian.Uint32(data[33:37])] = true
	}
	if len(counts) != 2 {
		t.Errorf("the counter did not advance: %v", counts)
	}
}

// An assertion the scenario signs says what the grant needs, and each its own jti.
func TestAnAssertionVerifiesAndIsNeverReused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := signES256(key, map[string]any{"sub": "w"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("a signature that does not verify")
	}
	if randomString(16) == randomString(16) {
		t.Error("two jti the same")
	}
}
