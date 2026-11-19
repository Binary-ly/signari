package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// signedBy is an id_token signed with key under kid.
func signedBy(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
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

// A sign-in's ID token is verified against the provider's keys through the cache (E.30):
// many sign-ins are one fetch of the provider's key set, a token signed with a key the cache
// has not seen fetches it again and is believed, and with no cache every token fetches it, as
// every sign-in did. Each sign-in had waited on a round trip to the provider, and a provider
// whose key endpoint had a bad minute had failed every sign-in it would have verified.
func TestASignInsKeysAreReadThroughTheCache(t *testing.T) {
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int64
	var mu sync.Mutex
	published := []jose.JSONWebKey{{Key: &first.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: published})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	fp := &fakeProvider{Server: srv, key: first, issuer: srv.URL}
	c := fp.config()
	c.Keys = &JWKSCache{}
	signIn := func(tok, what string) {
		t.Helper()
		if _, err := c.FetchIdentity(context.Background(), srv.Client(), &TokenSet{IDToken: tok}, "the-nonce"); err != nil {
			t.Fatalf("%s was refused: %v", what, err)
		}
	}

	for range 5 {
		signIn(signedBy(t, first, "k1", goodClaims(fp)), "a sign-in under the provider's key")
	}
	if n := fetches.Load(); n != 1 {
		t.Errorf("five sign-ins fetched the provider's key set %d times; they share one", n)
	}

	mu.Lock()
	published = append(published, jose.JSONWebKey{Key: &second.PublicKey, KeyID: "k2", Algorithm: "RS256", Use: "sig"})
	mu.Unlock()
	signIn(signedBy(t, second, "k2", goodClaims(fp)), "a sign-in under a key the provider has just added")
	if n := fetches.Load(); n != 2 {
		t.Errorf("a key the cache had not seen was fetched %d times in all, want once more", n)
	}

	c.Keys = nil
	signIn(signedBy(t, first, "k1", goodClaims(fp)), "a sign-in with no cache")
	signIn(signedBy(t, first, "k1", goodClaims(fp)), "a sign-in with no cache")
	if n := fetches.Load(); n != 4 {
		t.Errorf("with no cache two sign-ins left %d fetches in all, want two more", n)
	}
}
