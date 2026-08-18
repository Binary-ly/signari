package oidfed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// federation stands up a real leaf -> intermediate -> anchor topology over HTTP,
// each entity serving its own configuration and fetch endpoint.
type federation struct {
	leaf, inter, anchor *entity
	srv                 *httptest.Server
}

// newFederation wires three entities onto one test server, each at its own path
// prefix so their Entity Identifiers differ.
func newFederation(t *testing.T) *federation {
	t.Helper()
	f := &federation{}

	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	base := f.srv.URL
	f.leaf = newEntity(t, base+"/leaf", "leaf-1")
	f.inter = newEntity(t, base+"/inter", "inter-1")
	f.anchor = newEntity(t, base+"/anchor", "anchor-1")

	exp := time.Now().Add(time.Hour)
	serve := func(path string, body func() string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", MediaType)
			_, _ = w.Write([]byte(body()))
		})
	}

	// Each entity's own configuration. The leaf and intermediate name their
	// superiors; the anchor names none, which is what a Trust Anchor looks like.
	serve("/leaf/.well-known/openid-federation", func() string {
		return signClaims(t, f.leaf, map[string]any{
			"iss": f.leaf.id, "sub": f.leaf.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks":            json.RawMessage(f.leaf.jwks(t)),
			"authority_hints": []string{f.inter.id},
		})
	})
	serve("/inter/.well-known/openid-federation", func() string {
		return signClaims(t, f.inter, map[string]any{
			"iss": f.inter.id, "sub": f.inter.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks":            json.RawMessage(f.inter.jwks(t)),
			"authority_hints": []string{f.anchor.id},
			"metadata": map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": base + "/inter/fetch",
			}},
		})
	})
	serve("/anchor/.well-known/openid-federation", func() string {
		return signClaims(t, f.anchor, map[string]any{
			"iss": f.anchor.id, "sub": f.anchor.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks": json.RawMessage(f.anchor.jwks(t)),
			"metadata": map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": base + "/anchor/fetch",
			}},
		})
	})

	// Fetch endpoints: each superior's Subordinate Statement about whoever is
	// asked for. The jwks it carries is the SUBORDINATE's key set, attested.
	mux.HandleFunc("/inter/fetch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", MediaType)
		_, _ = w.Write([]byte(signClaims(t, f.inter, map[string]any{
			"iss": f.inter.id, "sub": r.URL.Query().Get("sub"),
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks": json.RawMessage(f.leaf.jwks(t)),
		})))
	})
	mux.HandleFunc("/anchor/fetch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", MediaType)
		_, _ = w.Write([]byte(signClaims(t, f.anchor, map[string]any{
			"iss": f.anchor.id, "sub": r.URL.Query().Get("sub"),
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks": json.RawMessage(f.inter.jwks(t)),
		})))
	})
	return f
}

func (f *federation) resolver(t *testing.T) *Resolver {
	t.Helper()
	return &Resolver{
		Fetcher: &Fetcher{HTTP: f.srv.Client(), AllowLoopbackForTesting: true},
		Anchors: []TrustAnchor{{EntityID: f.anchor.id, JWKS: f.anchor.jwks(t)}},
	}
}

// The whole thing, over HTTP: fetch the leaf, walk its authority_hints to the
// intermediate, fetch the intermediate's statement about the leaf, walk to the
// anchor, fetch its statement about the intermediate, then validate.
func TestResolvingALeafToATrustAnchor(t *testing.T) {
	f := newFederation(t)
	res, err := f.resolver(t).Resolve(context.Background(), f.leaf.id, time.Now())
	if err != nil {
		t.Fatalf("a well-formed federation did not resolve: %v", err)
	}
	if res.Subject != f.leaf.id {
		t.Errorf("subject = %q, want %q", res.Subject, f.leaf.id)
	}
	if res.TrustAnchor != f.anchor.id {
		t.Errorf("anchor = %q", res.TrustAnchor)
	}
	// leaf config + intermediate's statement + anchor's statement.
	if res.Length != 3 {
		t.Errorf("chain length = %d, want 3", res.Length)
	}
}

// An anchor we do not trust must not resolve, however well-formed the chain is.
func TestAnUntrustedAnchorDoesNotResolve(t *testing.T) {
	f := newFederation(t)
	r := f.resolver(t)
	stranger := newEntity(t, "https://stranger.example", "x1")
	r.Anchors = []TrustAnchor{{EntityID: stranger.id, JWKS: stranger.jwks(t)}}

	if _, err := r.Resolve(context.Background(), f.leaf.id, time.Now()); err == nil {
		t.Fatal("a chain resolved to an anchor that was never configured")
	}
}

// The anchor's keys are held out of band. Holding the right identifier and the
// wrong keys must fail — otherwise the final step verifies nothing.
func TestTheAnchorsKeysMustBeTheRealOnes(t *testing.T) {
	f := newFederation(t)
	r := f.resolver(t)
	impostor := newEntity(t, f.anchor.id, "anchor-1")
	r.Anchors = []TrustAnchor{{EntityID: f.anchor.id, JWKS: impostor.jwks(t)}}

	if _, err := r.Resolve(context.Background(), f.leaf.id, time.Now()); err == nil {
		t.Fatal("a chain validated against the wrong anchor keys")
	}
}

// A federation whose entities name each other as superiors must terminate, and
// must say it found a cycle rather than blaming the depth limit.
func TestACycleIsDetectedRatherThanExhausted(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := newEntity(t, srv.URL+"/a", "a1")
	b := newEntity(t, srv.URL+"/b", "b1")
	exp := time.Now().Add(time.Hour)

	cfg := func(self, other *entity) string {
		return signClaims(t, self, map[string]any{
			"iss": self.id, "sub": self.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks":            json.RawMessage(self.jwks(t)),
			"authority_hints": []string{other.id},
			"metadata": map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": self.id + "/fetch",
			}},
		})
	}
	mux.HandleFunc("/a/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cfg(a, b)))
	})
	mux.HandleFunc("/b/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cfg(b, a)))
	})
	sub := func(self *entity) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(signClaims(t, self, map[string]any{
				"iss": self.id, "sub": r.URL.Query().Get("sub"),
				"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
				"jwks": json.RawMessage(self.jwks(t)),
			})))
		}
	}
	mux.HandleFunc("/a/fetch", sub(a))
	mux.HandleFunc("/b/fetch", sub(b))

	anchor := newEntity(t, "https://anchor.example", "an1")
	r := &Resolver{
		Fetcher: &Fetcher{HTTP: srv.Client(), AllowLoopbackForTesting: true},
		Anchors: []TrustAnchor{{EntityID: anchor.id, JWKS: anchor.jwks(t)}},
	}

	_, err := r.Resolve(context.Background(), a.id, time.Now())
	if err == nil {
		t.Fatal("a cyclic federation resolved")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("the error blames something other than the cycle: %v", err)
	}
}

// A superior with no federation_fetch_endpoint cannot be asked about its
// subordinates, and the error should say that rather than a transport failure.
func TestASuperiorWithoutAFetchEndpointIsReported(t *testing.T) {
	f := newFederation(t)
	st, err := f.resolver(t).Fetcher.EntityConfigurationOf(context.Background(), f.leaf.id)
	if err != nil {
		t.Fatal(err)
	}
	// The leaf publishes no federation_entity metadata.
	if _, err := FetchEndpointOf(st); err == nil {
		t.Fatal("an entity with no federation_fetch_endpoint was treated as fetchable")
	} else if !strings.Contains(err.Error(), "federation_fetch_endpoint") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// No anchors configured is a configuration error, not an empty result.
func TestNoAnchorsIsRefusedLoudly(t *testing.T) {
	f := newFederation(t)
	r := f.resolver(t)
	r.Anchors = nil
	if _, err := r.Resolve(context.Background(), f.leaf.id, time.Now()); err == nil {
		t.Fatal("resolution succeeded with no trust anchors configured")
	}
}

// §10.3: "If multiple valid Trust Chains are found... One simple rule would be
// to prefer a shorter chain over a longer one."
//
// This needs a topology with an actual choice in it. The federation above has
// one anchor and one path, so the preference is never exercised — a mutation
// that picks the LONGEST chain passes every other test in this file, which is
// how I found that this one was missing.
//
// Here the leaf has two superiors: an intermediate leading to anchor A (three
// statements), and anchor B directly (two). Both are trusted and both validate.
func TestTheShortestValidChainIsPreferred(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL
	exp := time.Now().Add(time.Hour)

	leaf := newEntity(t, base+"/leaf", "leaf-1")
	inter := newEntity(t, base+"/inter", "inter-1")
	anchorA := newEntity(t, base+"/anchorA", "a-1")
	anchorB := newEntity(t, base+"/anchorB", "b-1")

	cfg := func(self *entity, hints []string, fetch bool) string {
		claims := map[string]any{
			"iss": self.id, "sub": self.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks": json.RawMessage(self.jwks(t)),
		}
		if len(hints) > 0 {
			claims["authority_hints"] = hints
		}
		if fetch {
			claims["metadata"] = map[string]any{"federation_entity": map[string]any{
				"federation_fetch_endpoint": self.id + "/fetch",
			}}
		}
		return signClaims(t, self, claims)
	}
	serve := func(path string, body func() string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body()))
		})
	}

	// The leaf names BOTH superiors.
	serve("/leaf/.well-known/openid-federation", func() string {
		return cfg(leaf, []string{inter.id, anchorB.id}, false)
	})
	serve("/inter/.well-known/openid-federation", func() string {
		return cfg(inter, []string{anchorA.id}, true)
	})
	serve("/anchorA/.well-known/openid-federation", func() string { return cfg(anchorA, nil, true) })
	serve("/anchorB/.well-known/openid-federation", func() string { return cfg(anchorB, nil, true) })

	// Each superior vouches for whoever is asked about, publishing that
	// subordinate's real key set.
	keysOf := map[string]*entity{leaf.id: leaf, inter.id: inter}
	subHandler := func(self *entity) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			want := r.URL.Query().Get("sub")
			sub, ok := keysOf[want]
			if !ok {
				http.Error(w, "unknown", 404)
				return
			}
			_, _ = w.Write([]byte(signClaims(t, self, map[string]any{
				"iss": self.id, "sub": want,
				"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
				"jwks": json.RawMessage(sub.jwks(t)),
			})))
		}
	}
	mux.HandleFunc("/inter/fetch", subHandler(inter))
	mux.HandleFunc("/anchorA/fetch", subHandler(anchorA))
	mux.HandleFunc("/anchorB/fetch", subHandler(anchorB))

	r := &Resolver{
		Fetcher: &Fetcher{HTTP: srv.Client(), AllowLoopbackForTesting: true},
		Anchors: []TrustAnchor{
			{EntityID: anchorA.id, JWKS: anchorA.jwks(t)}, // the LONGER path, listed first
			{EntityID: anchorB.id, JWKS: anchorB.jwks(t)}, // the shorter one
		},
	}

	res, err := r.Resolve(context.Background(), leaf.id, time.Now())
	if err != nil {
		t.Fatalf("neither chain resolved: %v", err)
	}
	if res.Length != 2 {
		t.Fatalf("chain length = %d via %s, want 2 via %s. §10.3 prefers the "+
			"shorter chain, and the longer one is listed first precisely so that "+
			"'first match wins' fails this test.",
			res.Length, res.TrustAnchor, anchorB.id)
	}
	if res.TrustAnchor != anchorB.id {
		t.Errorf("resolved via %s, want the nearer anchor %s", res.TrustAnchor, anchorB.id)
	}
}
