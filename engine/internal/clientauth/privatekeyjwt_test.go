package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	testClientID = "the-client"
	testIssuer   = "https://auth.example.com"
	testTokenURL = "https://auth.example.com/oauth2/token"
)

var testAudiences = []string{testIssuer, testTokenURL}

type key struct {
	priv *ecdsa.PrivateKey
	pub  jose.JSONWebKey
}

func newKey(t *testing.T, kid string) *key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key{priv: k, pub: jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}}
}

func (k *key) jwks(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k.pub}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (k *key) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.pub.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func goodClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": testClientID, "sub": testClientID, "aud": testTokenURL,
		"jti": "assertion-1", "exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
}

func TestValidAssertionIsAccepted(t *testing.T) {
	k := newKey(t, "k1")
	a, err := VerifyPrivateKeyJWT(k.sign(t, goodClaims()), testClientID, k.jwks(t),
		testAudiences, time.Now())
	if err != nil {
		t.Fatalf("a valid assertion was refused: %v", err)
	}
	if a.ClientID != testClientID || a.JTI != "assertion-1" {
		t.Errorf("assertion = %+v", a)
	}
}

func TestIssuerAsAudienceIsAlsoAccepted(t *testing.T) {
	k := newKey(t, "k1")
	c := goodClaims()
	c["aud"] = testIssuer
	if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
		testAudiences, time.Now()); err != nil {
		t.Errorf("the issuer as audience was refused: %v -- implementations differ "+
			"about issuer vs token endpoint and rejecting one breaks real clients", err)
	}
}

// TestAssertionAttacks. Each entry must be refused; any accepted is client
// impersonation.
func TestAssertionAttacks(t *testing.T) {
	k := newKey(t, "k1")
	other := newKey(t, "other")
	now := time.Now()

	cases := []struct {
		name      string
		assertion func() string
		clientID  string
		jwks      func() string
		why       string
	}{
		{
			name:      "signed by a key we do not know",
			assertion: func() string { return other.sign(t, goodClaims()) },
			why:       "anybody with any key could authenticate as this client",
		},
		{
			name: "audience is a DIFFERENT authorization server",
			assertion: func() string {
				c := goodClaims()
				c["aud"] = "https://other-idp.example.com/token"
				return k.sign(t, c)
			},
			why: "an assertion the client made for another server would be replayable here",
		},
		{
			name: "no audience at all",
			assertion: func() string {
				c := goodClaims()
				delete(c, "aud")
				return k.sign(t, c)
			},
			why: "the assertion would be valid at every server the client talks to",
		},
		{
			name: "iss names a different client",
			assertion: func() string {
				c := goodClaims()
				c["iss"] = "another-client"
				return k.sign(t, c)
			},
			why: "one client would assert another's identity",
		},
		{
			name: "sub names a different client",
			assertion: func() string {
				c := goodClaims()
				c["sub"] = "another-client"
				return k.sign(t, c)
			},
			why: "same, by the other claim",
		},
		{
			name: "expired",
			assertion: func() string {
				c := goodClaims()
				c["exp"] = now.Add(-time.Minute).Unix()
				return k.sign(t, c)
			},
			why: "a captured assertion would keep working",
		},
		{
			name: "no exp",
			assertion: func() string {
				c := goodClaims()
				delete(c, "exp")
				return k.sign(t, c)
			},
			why: "the assertion would be a bearer credential with no expiry -- a client secret again",
		},
		{
			name: "valid for a year",
			assertion: func() string {
				c := goodClaims()
				c["exp"] = now.Add(365 * 24 * time.Hour).Unix()
				return k.sign(t, c)
			},
			why: "a long-lived assertion is the shared secret this mechanism removes",
		},
		{
			name: "no jti",
			assertion: func() string {
				c := goodClaims()
				delete(c, "jti")
				return k.sign(t, c)
			},
			why: "a replay could not be detected",
		},
		{
			name: "not yet valid",
			assertion: func() string {
				c := goodClaims()
				c["nbf"] = now.Add(time.Hour).Unix()
				c["exp"] = now.Add(time.Hour + time.Minute).Unix()
				return k.sign(t, c)
			},
			why: "an assertion minted for later would work now",
		},
		{
			name:      "client has no registered keys",
			assertion: func() string { return k.sign(t, goodClaims()) },
			jwks:      func() string { return "" },
			why:       "there would be nothing to verify against",
		},
		{
			name:      "empty key set",
			assertion: func() string { return k.sign(t, goodClaims()) },
			jwks:      func() string { return `{"keys":[]}` },
			why:       "same",
		},
		{
			name:      "not a JWT",
			assertion: func() string { return "not-an-assertion" },
			why:       "malformed input must not reach the claim checks",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cid := c.clientID
			if cid == "" {
				cid = testClientID
			}
			jwksJSON := k.jwks(t)
			if c.jwks != nil {
				jwksJSON = c.jwks()
			}
			if _, err := VerifyPrivateKeyJWT(c.assertion(), cid, jwksJSON,
				testAudiences, now); err == nil {
				t.Fatalf("ACCEPTED: %s -- %s", c.name, c.why)
			}
		})
	}
}

// TestUnsignedAssertionIsRefused.
func TestUnsignedAssertionIsRefused(t *testing.T) {
	k := newKey(t, "k1")
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	body, _ := json.Marshal(goodClaims())
	unsigned := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(body) + "."

	if _, err := VerifyPrivateKeyJWT(unsigned, testClientID, k.jwks(t),
		testAudiences, time.Now()); err == nil {
		t.Fatal("an UNSIGNED assertion was accepted")
	}
}

// TestSymmetricAlgorithmIsRefused.
//
// An HMAC assertion is client_secret_jwt, a different mechanism: it is verified
// with a key both sides hold. Accepting it under this name means a client
// configured for private_key_jwt could be authenticated by something an
// attacker who read our database can forge.
func TestSymmetricAlgorithmIsRefused(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Skip("cannot build a symmetric signer")
	}
	payload, _ := json.Marshal(goodClaims())
	obj, _ := signer.Sign(payload)
	compact, _ := obj.CompactSerialize()

	k := newKey(t, "k1")
	if _, err := VerifyPrivateKeyJWT(compact, testClientID, k.jwks(t),
		testAudiences, time.Now()); err == nil {
		t.Fatal("an HMAC-signed assertion was accepted as private_key_jwt")
	}
}

// TestPrivateKeyInRegisteredSetIsRefused. Somebody pasted the wrong half, and
// it is now in our database.
func TestPrivateKeyInRegisteredSetIsRefused(t *testing.T) {
	k := newKey(t, "k1")
	privSet, _ := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: k.priv, KeyID: "k1", Algorithm: "ES256"}},
	})
	_, err := VerifyPrivateKeyJWT(k.sign(t, goodClaims()), testClientID,
		string(privSet), testAudiences, time.Now())
	if err == nil {
		t.Fatal("a registered key set containing PRIVATE key material was used")
	}
	if !strings.Contains(err.Error(), "PUBLIC") {
		t.Errorf("the error should tell the operator what to register; got %v", err)
	}
}

// TestAudienceArrayIsHandled -- `aud` is legally a string or an array.
func TestAudienceArrayIsHandled(t *testing.T) {
	k := newKey(t, "k1")

	c := goodClaims()
	c["aud"] = []string{"https://elsewhere.example", testTokenURL}
	if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
		testAudiences, time.Now()); err != nil {
		t.Errorf("an array containing our audience was refused: %v", err)
	}

	c["aud"] = []string{"https://elsewhere.example", "https://third.example"}
	if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
		testAudiences, time.Now()); err == nil {
		t.Error("an array NOT containing our audience was accepted")
	}
}

// TestKeyRotationWorks: a client with two registered keys can sign with either,
// which is what makes rotating one possible without downtime.
func TestKeyRotationWorks(t *testing.T) {
	oldKey := newKey(t, "old")
	newKeyPair := newKey(t, "new")
	set, _ := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{oldKey.pub, newKeyPair.pub},
	})

	for name, k := range map[string]*key{"old": oldKey, "new": newKeyPair} {
		if _, err := VerifyPrivateKeyJWT(k.sign(t, goodClaims()), testClientID,
			string(set), testAudiences, time.Now()); err != nil {
			t.Errorf("the %s key was refused during rotation: %v", name, err)
		}
	}
}
