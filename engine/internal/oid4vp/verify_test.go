package oid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/sdjwt"
)

const (
	testIssuer   = "https://issuer.example"
	testVCT      = "urn:example:person:1"
	testClientID = "x509_san_dns:verifier.example"
	testNonce    = "n-0S6_WzA2Mj"
)

type fixture struct {
	t                *testing.T
	issuerKey        *ecdsa.PrivateKey
	holderKey        *ecdsa.PrivateKey
	now              time.Time
	ask              Ask
	issuers          map[string]*jose.JSONWebKeySet
	always, selected map[string]any
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, issuerKey: genKey(t), holderKey: genKey(t), now: time.Now()}
	f.ask = Ask{ID: "person", VCTValues: []string{testVCT}, Claims: []Path{{"email"}, {"address", "country"}}}
	f.issuers = map[string]*jose.JSONWebKeySet{testIssuer: {Keys: []jose.JSONWebKey{
		{Key: f.issuerKey.Public(), KeyID: "issuer-1", Algorithm: "ES256", Use: "sig"}}}}
	f.always = map[string]any{"iss": testIssuer, "vct": testVCT, "iat": f.now.Unix(),
		"exp": f.now.Add(time.Hour).Unix()}
	f.selected = map[string]any{"email": "person@example.test", "given_name": "Ada",
		"address": map[string]any{"country": "LY"}}
	return f
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (f *fixture) expect() Expect {
	return Expect{ClientID: testClientID, Nonce: testNonce, Ask: f.ask, Issuers: f.issuers, Now: f.now}
}

func signJSON(t *testing.T, key crypto.Signer, typ, kid string, claims any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	alg, err := Algorithm(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// credential is the issuer's SD-JWT, every selective claim disclosable, and the
// disclosures; keep says which of those the holder presents.
type credential struct {
	jwt         string
	disclosures []sdjwt.Disclosure
}

func (f *fixture) credential(edit func(payload map[string]any), signer crypto.Signer, typ string) credential {
	f.t.Helper()
	payload, ds, err := sdjwt.Payload(f.always, f.selected)
	if err != nil {
		f.t.Fatal(err)
	}
	payload["cnf"] = map[string]any{"jwk": jose.JSONWebKey{Key: f.holderKey.Public()}}
	if edit != nil {
		edit(payload)
	}
	if signer == nil {
		signer = f.issuerKey
	}
	return credential{jwt: signJSON(f.t, signer, typ, "issuer-1", payload), disclosures: ds}
}

// present is the holder's SD-JWT+KB of c with the disclosures named, its key
// binding made by kbEdit's claims.
func (f *fixture) present(c credential, names []string, kbEdit func(map[string]any), kbSigner crypto.Signer) string {
	f.t.Helper()
	var keep []sdjwt.Disclosure
	for _, d := range c.disclosures {
		for _, n := range names {
			if d.Name == n {
				keep = append(keep, d)
			}
		}
	}
	sd := sdjwt.Combine(c.jwt, keep)
	kb := map[string]any{"iat": f.now.Unix(), "aud": testClientID, "nonce": testNonce, "sd_hash": sdjwt.DigestOf(sd)}
	if kbEdit != nil {
		kbEdit(kb)
	}
	if kbSigner == nil {
		kbSigner = f.holderKey
	}
	return sd + signJSON(f.t, kbSigner, TypKeyBinding, "", kb)
}

func token(id string, presentations ...string) string {
	b, _ := json.Marshal(map[string][]string{id: presentations})
	return string(b)
}

var both = []string{"email", "address"}

func TestAPresentationIsAccepted(t *testing.T) {
	f := newFixture(t)
	got, err := Verify(token("person", f.present(f.credential(nil, nil, "dc+sd-jwt"), both, nil, nil)), f.expect())
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != testIssuer || got.VCT != testVCT || got.Claims["email"] != "person@example.test" {
		t.Errorf("%+v", got)
	}
	// Withheld, so not there: the verifier sees what was disclosed and no more.
	if _, ok := got.Claims["given_name"]; ok {
		t.Error("a claim that was not disclosed came through")
	}
	// The type it replaced, for the transitional period.
	if _, err := Verify(token("person", f.present(f.credential(nil, nil, "vc+sd-jwt"), both, nil, nil)), f.expect()); err != nil {
		t.Errorf("vc+sd-jwt: %v", err)
	}
}

// The refusals, each named after what it is: most are a negative module of the
// OpenID Foundation's verifier plan.
func TestAPresentationIsRefused(t *testing.T) {
	f := newFixture(t)
	good := f.credential(nil, nil, "dc+sd-jwt")
	other := genKey(t)
	year := 365 * 24 * time.Hour

	// issued is a presentation of a credential whose payload edit changed, and
	// bound is one of the good credential whose key binding edit changed.
	issued := func(edit func(map[string]any)) string {
		return token("person", f.present(f.credential(edit, nil, "dc+sd-jwt"), both, nil, nil))
	}
	bound := func(edit func(map[string]any)) string {
		return token("person", f.present(good, both, edit, nil))
	}

	cases := []struct{ name, vp, want string }{
		{name: "credential signed by another key",
			vp: token("person", f.present(f.credential(nil, other, "dc+sd-jwt"), both, nil, nil)), want: "signature does not verify"},
		{name: "key binding signed by another key",
			vp: token("person", f.present(good, both, nil, other)), want: "not signed by the credential's holder key"},
		{name: "sd_hash over something else",
			vp: bound(func(kb map[string]any) { kb["sd_hash"] = sdjwt.DigestOf("x") }), want: "sd_hash"},
		{name: "a nonce from another request",
			vp: bound(func(kb map[string]any) { kb["nonce"] = "other" }), want: "nonce"},
		{name: "no nonce",
			vp: bound(func(kb map[string]any) { delete(kb, "nonce") }), want: "nonce"},
		{name: "made for another verifier",
			vp: bound(func(kb map[string]any) { kb["aud"] = "x509_san_dns:other.example" }), want: "made for"},
		{name: "aud without its prefix",
			vp: bound(func(kb map[string]any) { kb["aud"] = "verifier.example" }), want: "made for"},
		{name: "aud as an array",
			vp: bound(func(kb map[string]any) { kb["aud"] = []string{testClientID} }), want: "single string"},
		{name: "key binding a year old",
			vp: bound(func(kb map[string]any) { kb["iat"] = f.now.Add(-year).Unix() }), want: "older than"},
		{name: "key binding a year ahead",
			vp: bound(func(kb map[string]any) { kb["iat"] = f.now.Add(year).Unix() }), want: "in the future"},
		{name: "key binding without iat",
			vp: bound(func(kb map[string]any) { delete(kb, "iat") }), want: "no iat"},
		{name: "no key binding at all",
			vp: token("person", sdjwt.Combine(good.jwt, good.disclosures)), want: "no Key Binding JWT"},
		{name: "an issuer nobody believes",
			vp: issued(func(p map[string]any) { p["iss"] = "https://elsewhere.example" }), want: "not an issuer this verifier believes"},
		{name: "a type nobody asked for",
			vp: issued(func(p map[string]any) { p["vct"] = "urn:example:other" }), want: "type"},
		{name: "a JWT that is not a credential",
			vp: token("person", f.present(f.credential(nil, nil, "JWT"), both, nil, nil)), want: "typ"},
		{name: "expired",
			vp: issued(func(p map[string]any) { p["exp"] = f.now.Add(-time.Hour).Unix() }), want: "expired"},
		{name: "not yet valid",
			vp: issued(func(p map[string]any) { p["nbf"] = f.now.Add(time.Hour).Unix() }), want: "not valid until"},
		{name: "no cnf",
			vp: issued(func(p map[string]any) { delete(p, "cnf") }), want: "no cnf"},
		{name: "a claim asked for and withheld",
			vp: token("person", f.present(good, []string{"email"}, nil, nil)), want: "asked for"},
		{name: "two presentations for one query",
			vp: token("person", f.present(good, both, nil, nil), f.present(good, both, nil, nil)), want: "one was asked"},
		{name: "the answer to another query",
			vp: token("other", f.present(good, both, nil, nil)), want: "does not answer"},
		{name: "not JSON", vp: "eyJ.not.json", want: "not a JSON object"},
		{name: "the presentation as a bare string",
			vp: `{"person":"` + f.present(good, both, nil, nil) + `"}`, want: "not an array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(c.vp, f.expect())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}

// A disclosure for some other credential, appended to a good presentation, is
// refused (specs/rfc9901.txt:1745-1747), even with a key binding made over it.
func TestAnUnreferencedDisclosureIsRefused(t *testing.T) {
	f := newFixture(t)
	good := f.credential(nil, nil, "dc+sd-jwt")
	stranger, err := sdjwt.NewDisclosure("role", "admin")
	if err != nil {
		t.Fatal(err)
	}
	var keep []sdjwt.Disclosure
	keep = append(keep, good.disclosures...)
	keep = append(keep, stranger)
	sd := sdjwt.Combine(good.jwt, keep)
	kb := signJSON(t, f.holderKey, TypKeyBinding, "", map[string]any{"iat": f.now.Unix(), "aud": testClientID,
		"nonce": testNonce, "sd_hash": sdjwt.DigestOf(sd)})
	if _, err := Verify(token("person", sd+kb), f.expect()); err == nil || !strings.Contains(err.Error(), "not referenced") {
		t.Fatalf("got %v", err)
	}
}

// A credential signed with a MAC is refused before any key is tried: the list
// of algorithms has none, so a "key" published as a public value could not be
// the secret that forges one.
func TestAMACSignedCredentialIsRefused(t *testing.T) {
	f := newFixture(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := sdjwt.Payload(f.always, f.selected)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(payload)
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	jwt, _ := obj.CompactSerialize()
	f.issuers[testIssuer].Keys = append(f.issuers[testIssuer].Keys, jose.JSONWebKey{Key: secret, KeyID: "mac"})
	if _, err := Verify(token("person", f.present(credential{jwt: jwt}, nil, nil, nil)), f.expect()); err == nil ||
		!strings.Contains(err.Error(), "did not parse") {
		t.Fatalf("got %v", err)
	}
}

// The suite's MinimalCnfJwk module: a cnf key with nothing but its curve and
// coordinates still binds.
func TestAMinimalHolderKeyBinds(t *testing.T) {
	f := newFixture(t)
	pub := f.holderKey.PublicKey
	c := f.credential(func(p map[string]any) {
		full, _ := json.Marshal(jose.JSONWebKey{Key: &pub})
		var m map[string]any
		_ = json.Unmarshal(full, &m)
		p["cnf"] = map[string]any{"jwk": map[string]any{"kty": m["kty"], "crv": m["crv"], "x": m["x"], "y": m["y"]}}
	}, nil, "dc+sd-jwt")
	if _, err := Verify(token("person", f.present(c, both, nil, nil)), f.expect()); err != nil {
		t.Fatal(err)
	}
}
