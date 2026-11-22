package oid4vp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// The two requests the specification shows (specs/sdjwtvc.txt:1145-1162), a trailing
// slash, and the issuers that have no metadata address.
func TestTheMetadataAddressIsTheSpecificationsOwn(t *testing.T) {
	for iss, want := range map[string]string{
		"https://example.com":              "https://example.com/.well-known/jwt-vc-issuer",
		"https://example.com/tenant/1234":  "https://example.com/.well-known/jwt-vc-issuer/tenant/1234",
		"https://example.com/tenant/1234/": "https://example.com/.well-known/jwt-vc-issuer/tenant/1234",
		"https://example.com:8443/":        "https://example.com:8443/.well-known/jwt-vc-issuer",
	} {
		got, err := IssuerMetadataURL(iss)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", iss, got, err, want)
		}
	}
	for _, iss := range []string{"http://example.com", "https://example.com?x=1", "https://example.com/#a",
		"https://example.com?", "urn:example:issuer", "https://user@example.com", "example.com"} {
		if got, err := IssuerMetadataURL(iss); err == nil {
			t.Errorf("%s has no metadata address, and %q was made", iss, got)
		}
	}
}

// metadataHost is an issuer's web server: its metadata, and a key set at another
// address when the metadata names one.
type metadataHost struct {
	t           *testing.T
	metadata    map[string]any
	keySet      any
	contentType string
	err         error
	asked       []string
}

const testKeySetURI = "https://keys.issuer.example/jwks"

func (h *metadataHost) fetch(uri, accept string) ([]byte, string, error) {
	h.asked = append(h.asked, uri)
	if h.err != nil {
		return nil, "", h.err
	}
	ct := h.contentType
	if ct == "" {
		ct = "application/json"
	}
	switch uri {
	case "https://issuer.example/.well-known/jwt-vc-issuer":
		if accept != "application/json" {
			h.t.Errorf("the metadata was asked for as %q", accept)
		}
		b, _ := json.Marshal(h.metadata)
		return b, ct, nil
	case testKeySetURI:
		b, _ := json.Marshal(h.keySet)
		return b, "application/jwk-set+json", nil
	}
	h.t.Errorf("asked for %s", uri)
	return nil, "", errors.New("not found")
}

// byMetadata is the fixture's expectation with its issuer believed by its metadata
// and no key pinned.
func (f *fixture) byMetadata(h *metadataHost) Expect {
	e := f.expect()
	e.Issuers = nil
	e.FromMetadata = map[string]bool{testIssuer: true}
	e.Fetch = h.fetch
	return e
}

func TestAnIssuerBelievedByItsMetadataIsCheckedWithTheKeysItPublishes(t *testing.T) {
	f := newFixture(t)
	vp := token("person", f.present(f.credential(nil, nil, "dc+sd-jwt"), both, nil, nil))
	set := f.issuers[testIssuer]

	inline := &metadataHost{t: t, metadata: map[string]any{"issuer": testIssuer, "jwks": set}}
	if _, err := Verify(vp, f.byMetadata(inline)); err != nil {
		t.Fatalf("keys in the metadata: %v", err)
	}
	byURI := &metadataHost{t: t, metadata: map[string]any{"issuer": testIssuer, "jwks_uri": testKeySetURI}, keySet: set}
	if _, err := Verify(vp, f.byMetadata(byURI)); err != nil {
		t.Fatalf("keys at jwks_uri: %v", err)
	}
	if len(byURI.asked) != 2 || byURI.asked[1] != testKeySetURI {
		t.Errorf("asked for %v", byURI.asked)
	}

	// Named nowhere, an issuer is not looked up at all: what a credential says
	// about itself does not choose what this server fetches.
	stranger := &metadataHost{t: t}
	e := f.byMetadata(stranger)
	e.FromMetadata = map[string]bool{"https://another.example": true}
	if _, err := Verify(vp, e); err == nil || !strings.Contains(err.Error(), "not an issuer this verifier believes") {
		t.Fatalf("an issuer nobody named: %v", err)
	}
	if len(stranger.asked) != 0 {
		t.Errorf("an issuer nobody named was looked up: %v", stranger.asked)
	}
}

func TestMetadataThatIsNotTheIssuersOwnRefuses(t *testing.T) {
	f := newFixture(t)
	vp := token("person", f.present(f.credential(nil, nil, "dc+sd-jwt"), both, nil, nil))
	set := f.issuers[testIssuer]
	other := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: genKey(t).Public(), KeyID: "issuer-1", Algorithm: "ES256"}}}
	for _, c := range []struct {
		name string
		host *metadataHost
		want string
	}{
		{"metadata for another issuer", &metadataHost{metadata: map[string]any{"issuer": "https://issuer.example/", "jwks": set}}, "is for"},
		{"both jwks and jwks_uri", &metadataHost{metadata: map[string]any{"issuer": testIssuer, "jwks": set, "jwks_uri": testKeySetURI}}, "both"},
		{"neither", &metadataHost{metadata: map[string]any{"issuer": testIssuer}}, "neither"},
		{"served as something else", &metadataHost{metadata: map[string]any{"issuer": testIssuer, "jwks": set}, contentType: "text/html"}, "came as"},
		{"a jwks_uri in plain http", &metadataHost{metadata: map[string]any{"issuer": testIssuer, "jwks_uri": "http://keys.issuer.example/jwks"}}, "https"},
		{"another key", &metadataHost{metadata: map[string]any{"issuer": testIssuer, "jwks": other}}, "does not verify"},
		{"an empty key set", &metadataHost{metadata: map[string]any{"issuer": testIssuer, "jwks": map[string]any{"keys": []any{}}}}, "no key"},
		{"unreachable", &metadataHost{err: errors.New("connection refused")}, "could not be read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.host.t = t
			if _, err := Verify(vp, f.byMetadata(c.host)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}
