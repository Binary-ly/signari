package oid4vci

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func decodePart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Appendix A.1.1.4: the credential MUST be a JWT, and its shape is the example at
// specs/oid4vci.txt:3404, where the holder's key is the subject as a did:jwk.
func TestAJWTCredentialNamesTheHolderAsItsSubject(t *testing.T) {
	var typ string
	i := Issuer{CredentialIssuer: "https://issuer.test", Sign: func(payload []byte, t2 string) (string, error) {
		typ = t2
		return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig", nil
	}}
	cfg := Configuration{ID: "degree", Format: FormatJWTVC, VCT: "UniversityDegreeCredential",
		AlwaysClaims: []string{"email", "given_name", "id"}, Lifetime: 720 * time.Hour}
	holder := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	out, err := i.Issue(cfg, map[string]any{"email": "a@example.test", "given_name": "", "sub": "not-asked-for",
		"id": "an attempt on the id"}, holder, now)
	if err != nil {
		t.Fatal(err)
	}
	if typ != "JWT" {
		t.Errorf("signed with typ %q", typ)
	}
	parts := strings.Split(out, ".")
	if len(parts) != 3 {
		t.Fatalf("%d parts: a JWT has three, and no disclosures follow it", len(parts))
	}
	claims := decodePart(t, parts[1])
	vc, _ := claims["vc"].(map[string]any)
	if vc == nil {
		t.Fatalf("no vc claim: %v", claims)
	}
	sub, _ := claims["sub"].(string)
	did, found := strings.CutPrefix(sub, "did:jwk:")
	if !found {
		t.Fatalf("the holder is named %q", sub)
	}
	raw, err := base64.RawURLEncoding.DecodeString(did)
	if err != nil {
		t.Fatal(err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatal(err)
	}
	want, _ := holder.Thumbprint(0x5)
	got, _ := key.Thumbprint(0x5)
	if string(want) != string(got) || !key.IsPublic() {
		t.Errorf("the did is not the holder's public key: %+v", key)
	}

	if claims["iss"] != "https://issuer.test" || claims["jti"] == "" || claims["jti"] != vc["id"] {
		t.Errorf("iss, jti: %v", claims)
	}
	if nbf, _ := claims["nbf"].(float64); int64(nbf) > now.Unix() {
		t.Errorf("not valid until %v, after it was issued", nbf)
	}
	if _, has := claims["exp"]; !has || vc["expirationDate"] == nil {
		t.Errorf("a credential with a lifetime has no expiry: %v", claims)
	}
	if _, has := claims["cnf"]; has {
		t.Error("the key is bound twice, and a verifier of this format reads the subject")
	}
	types, _ := vc["type"].([]any)
	if len(types) != 2 || types[0] != "VerifiableCredential" || types[1] != "UniversityDegreeCredential" {
		t.Errorf("types %v", vc["type"])
	}
	subject, _ := vc["credentialSubject"].(map[string]any)
	if subject["id"] != sub {
		t.Errorf("a claim replaced the subject's id: %v", subject["id"])
	}
	if subject["email"] != "a@example.test" {
		t.Errorf("subject %v", subject)
	}
	if _, has := subject["given_name"]; has {
		t.Error("an empty claim was written as a statement that the person has none")
	}
	if _, has := subject["sub"]; has {
		t.Error("a claim the configuration did not ask for was written")
	}
}

func TestAJWTCredentialWithNoLifetimeHasNoExpiry(t *testing.T) {
	var payload []byte
	i := Issuer{CredentialIssuer: "https://issuer.test", Sign: func(p []byte, _ string) (string, error) {
		payload = p
		return "x", nil
	}}
	cfg := Configuration{Format: FormatJWTVC, VCT: "T", AlwaysClaims: []string{"email"}}
	if _, err := i.Issue(cfg, map[string]any{"email": "a@example.test"}, testKey(t), time.Now()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), `"exp"`) || strings.Contains(string(payload), "expirationDate") {
		t.Errorf("an expiry nobody set: %s", payload)
	}
}

func TestAJWTCredentialIsBoundLikeAnyOther(t *testing.T) {
	i := Issuer{CredentialIssuer: "https://issuer.test", Sign: func([]byte, string) (string, error) { return "x", nil }}
	cfg := Configuration{Format: FormatJWTVC, VCT: "T", AlwaysClaims: []string{"email"}}
	if _, err := i.Issue(cfg, map[string]any{"email": "a@example.test"}, nil, time.Now()); err == nil {
		t.Fatal("a credential was issued to nobody's key")
	}
}
