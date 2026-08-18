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

// rpFederation is a leaf that plays openid_relying_party, under one anchor.
func rpFederation(t *testing.T, rpMetadata map[string]any, policyOnSub map[string]any) (*Resolver, string) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rp := newEntity(t, srv.URL+"/rp", "rp-1")
	anchor := newEntity(t, srv.URL+"/anchor", "an-1")
	exp := time.Now().Add(time.Hour)

	mux.HandleFunc("/rp/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss": rp.id, "sub": rp.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks":            json.RawMessage(rp.jwks(t)),
			"authority_hints": []string{anchor.id},
		}
		if rpMetadata != nil {
			claims["metadata"] = map[string]any{TypeRelyingParty: rpMetadata}
		}
		_, _ = w.Write([]byte(signClaims(t, rp, claims)))
	})
	mux.HandleFunc("/anchor/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(signClaims(t, anchor, map[string]any{
			"iss": anchor.id, "sub": anchor.id,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks": json.RawMessage(anchor.jwks(t)),
			"metadata": map[string]any{TypeFederationEntity: map[string]any{
				"federation_fetch_endpoint": anchor.id + "/fetch",
			}},
		})))
	})
	mux.HandleFunc("/anchor/fetch", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss": anchor.id, "sub": r.URL.Query().Get("sub"),
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": exp.Unix(),
			"jwks": json.RawMessage(rp.jwks(t)),
		}
		for k, v := range policyOnSub {
			claims[k] = v
		}
		_, _ = w.Write([]byte(signClaims(t, anchor, claims)))
	})

	return &Resolver{
		Fetcher: &Fetcher{HTTP: srv.Client(), AllowLoopbackForTesting: true},
		Anchors: []TrustAnchor{{EntityID: anchor.id, JWKS: anchor.jwks(t)}},
	}, rp.id
}

func goodRPMetadata(t *testing.T) map[string]any {
	t.Helper()
	rp := newEntity(t, "https://x", "proto-1")
	var jwks map[string]any
	if err := json.Unmarshal(rp.jwks(t), &jwks); err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"redirect_uris":  []any{"https://rp.example/cb"},
		"response_types": []any{"code"},
		"scope":          "openid profile",
		"jwks":           jwks,
	}
}

// The happy path: an RP in the federation is usable with no prior registration.
func TestAnRPInTheFederationRegistersAutomatically(t *testing.T) {
	r, rpID := rpFederation(t, goodRPMetadata(t), nil)

	c, err := Register(context.Background(), r, rpID, time.Now())
	if err != nil {
		t.Fatalf("a well-formed RP was refused: %v", err)
	}
	// §12.1: "the RP employs its Entity Identifier as the Client ID".
	if c.ClientID != rpID {
		t.Errorf("client id = %q, want the Entity Identifier %q", c.ClientID, rpID)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://rp.example/cb" {
		t.Errorf("redirect_uris = %v", c.RedirectURIs)
	}
	if len(c.JWKS) == 0 {
		t.Error("no jwks carried out, so the RP could not prove it sent a request")
	}
	if len(c.Scopes) != 2 {
		t.Errorf("scopes = %v", c.Scopes)
	}
}

// §6.1.4: "If a policy error or another error is encountered during the metadata
// policy resolution or its application, the Trust Chain MUST be considered
// invalid."
//
// A superior's metadata_policy constrains what the subordinate may claim.
// Resolving the chain and then using the leaf's own metadata anyway does not
// produce a slightly-wrong client — it produces the client the RP asked for
// rather than the one its federation permits.
func TestAChainCarryingAMetadataPolicyIsRefused(t *testing.T) {
	policy := map[string]any{
		"metadata_policy": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": map[string]any{
					"subset_of": []any{"https://approved.example/cb"},
				},
			},
		},
	}
	r, rpID := rpFederation(t, goodRPMetadata(t), policy)

	_, err := Register(context.Background(), r, rpID, time.Now())
	if err == nil {
		t.Fatal("a chain carrying a metadata_policy was resolved and the policy " +
			"silently ignored; the RP would be admitted with the redirect_uris it " +
			"chose rather than the ones its superior permits")
	}
	if !strings.Contains(err.Error(), "metadata_policy") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// §12.1 makes proof of key control mandatory. An RP with no published keys
// cannot provide it, so admitting it would create a client anybody could
// impersonate by knowing its public identifier.
func TestAnRPWithNoKeysIsRefused(t *testing.T) {
	md := goodRPMetadata(t)
	delete(md, "jwks")
	r, rpID := rpFederation(t, md, nil)

	_, err := Register(context.Background(), r, rpID, time.Now())
	if err == nil {
		t.Fatal("an RP publishing no jwks was admitted; it cannot demonstrate " +
			"control of any key, which §12.1 requires")
	}
	if !strings.Contains(err.Error(), "jwks") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// No redirect URIs means no way to answer, and inventing one builds an open
// redirector.
func TestAnRPWithNoRedirectURIsIsRefused(t *testing.T) {
	md := goodRPMetadata(t)
	delete(md, "redirect_uris")
	r, rpID := rpFederation(t, md, nil)

	if _, err := Register(context.Background(), r, rpID, time.Now()); err == nil {
		t.Fatal("an RP publishing no redirect_uris was admitted")
	}
}

// An entity that resolves fine but does not play the RP role must not become a
// client. Being in the federation is not the same as being a relying party.
func TestAnEntityThatIsNotAnRPIsRefused(t *testing.T) {
	r, rpID := rpFederation(t, nil, nil) // no openid_relying_party metadata

	_, err := Register(context.Background(), r, rpID, time.Now())
	if err == nil {
		t.Fatal("an entity with no openid_relying_party metadata was registered " +
			"as a relying party")
	}
	if !strings.Contains(err.Error(), TypeRelyingParty) {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Nothing about the client may come from the request. The client_id is
// attacker-supplied, and an identifier that does not resolve is not a client.
func TestAnUnresolvableClientIDIsNotAClient(t *testing.T) {
	r, _ := rpFederation(t, goodRPMetadata(t), nil)

	if _, err := Register(context.Background(), r, "https://stranger.example",
		time.Now()); err == nil {
		t.Fatal("an entity identifier that resolves to nothing became a client")
	}
}
