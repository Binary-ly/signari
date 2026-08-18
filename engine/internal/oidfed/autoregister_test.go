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
//
// `subset_of` is a value MODIFIER as well as a check (§6.1.3.1.5), so the
// permitted URI survives and the other does not. That is the behaviour that
// makes one policy usable across subordinates who publish different things —
// and it is why a test that only asserts "refused" would be testing the wrong
// property.
func TestASuperiorsPolicyTrimsWhatTheSubordinatePublishes(t *testing.T) {
	policy := map[string]any{
		"metadata_policy": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": map[string]any{
					"subset_of": []any{"https://rp.example/cb", "https://approved.example/cb"},
				},
			},
		},
	}
	md := goodRPMetadata(t)
	md["redirect_uris"] = []any{"https://rp.example/cb", "https://rp.example/sneaky"}

	r, rpID := rpFederation(t, md, policy)
	c, err := Register(context.Background(), r, rpID, time.Now())
	if err != nil {
		t.Fatalf("a chain whose policy the RP satisfies was refused: %v", err)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://rp.example/cb" {
		t.Fatalf("redirect_uris = %v; the policy permits only https://rp.example/cb, "+
			"so the RP was admitted with a callback its federation forbids",
			c.RedirectURIs)
	}
}

// And when the policy permits none of what the RP published, there is nothing
// left to register with.
func TestAnRPWhosePolicyLeavesNoRedirectURIIsRefused(t *testing.T) {
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

	if _, err := Register(context.Background(), r, rpID, time.Now()); err == nil {
		t.Fatal("an RP was admitted with a redirect_uri its superior does not permit")
	}
}

// A policy operator declared critical that we do not implement invalidates the
// chain (§6.1.3.2). The alternative -- ignoring it -- admits the RP under a
// constraint its federation believes is in force.
func TestACriticalOperatorWeDoNotImplementInvalidatesTheChain(t *testing.T) {
	policy := map[string]any{
		"metadata_policy": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": map[string]any{
					"regexp": "^https://rp\\.example/",
				},
			},
		},
		"metadata_policy_crit": []any{"regexp"},
	}
	r, rpID := rpFederation(t, goodRPMetadata(t), policy)

	_, err := Register(context.Background(), r, rpID, time.Now())
	if err == nil {
		t.Fatal("a chain declaring an operator we cannot process as critical was " +
			"resolved anyway")
	}
	if !strings.Contains(err.Error(), "regexp") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The converse of the above: a NON-critical operator we do not know is ignored,
// per §6.1.3.2's "Implementations MUST ignore additional operators that are not
// understood". Refusing it instead would make every federation that uses any
// extension operator unusable, whether or not the constraint mattered.
func TestAnUnknownOperatorThatIsNotCriticalIsIgnored(t *testing.T) {
	policy := map[string]any{
		"metadata_policy": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": map[string]any{
					"regexp": "^https://rp\\.example/",
				},
			},
		},
	}
	r, rpID := rpFederation(t, goodRPMetadata(t), policy)

	c, err := Register(context.Background(), r, rpID, time.Now())
	if err != nil {
		t.Fatalf("an unknown, non-critical operator refused the chain: %v", err)
	}
	if len(c.RedirectURIs) != 1 {
		t.Errorf("redirect_uris = %v", c.RedirectURIs)
	}
}

// §3.1.1: "Metadata parameters in a Subordinate Statement have precedence and
// override identically named parameters under the same Entity Type in the
// subject's Entity Configuration."
func TestASuperiorsMetadataOverridesTheSubjectsOwn(t *testing.T) {
	sup := map[string]any{
		"metadata": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": []any{"https://assigned-by-superior.example/cb"},
			},
		},
	}
	r, rpID := rpFederation(t, goodRPMetadata(t), sup)

	c, err := Register(context.Background(), r, rpID, time.Now())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://assigned-by-superior.example/cb" {
		t.Fatalf("redirect_uris = %v; the superior's value did not take precedence",
			c.RedirectURIs)
	}
}

// And the ordering between the two, which §3.1.1 states outright: "If both
// metadata and metadata_policy appear in a Subordinate Statement, then the
// stated metadata MUST be applied before the metadata_policy."
//
// The superior assigns a URI and then constrains the parameter to a set that
// does NOT contain it. Applied in the specified order, the assignment is judged
// by the constraint and nothing survives. Applied the other way round, the
// assignment would land after the check and escape it — which is the bug this
// test exists to catch, because both orders "work" on any policy whose
// constraint the assignment happens to satisfy.
func TestTheSuperiorsMetadataIsJudgedByItsOwnPolicy(t *testing.T) {
	both := map[string]any{
		"metadata": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": []any{"https://assigned.example/cb"},
			},
		},
		"metadata_policy": map[string]any{
			TypeRelyingParty: map[string]any{
				"redirect_uris": map[string]any{
					"subset_of": []any{"https://rp.example/cb"},
				},
			},
		},
	}
	r, rpID := rpFederation(t, goodRPMetadata(t), both)

	if _, err := Register(context.Background(), r, rpID, time.Now()); err == nil {
		t.Fatal("the superior's assigned redirect_uri was not judged by the " +
			"superior's own policy, so metadata was applied after metadata_policy")
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
