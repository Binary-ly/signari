package httpapi

import (
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"

	"signari.dev/engine/internal/authzen"
)

// The second turn on AuthZEN: attacking the pagination binding rather than
// reading it.
//
// The full extraction (142 normative uses across 43 sections) found §9, §10 and
// §11 already implemented. §8.2 is the one this engine had to change, and it
// carries the only property here that is a security property rather than a
// shape:
//
//	"every entity and pagination parameter to be identical to the request that
//	produced the token"
//
// A page token that works across requests is a cursor into somebody else's
// result set. The PDP answers "which resources may this subject reach"; a token
// accepted with the subject swapped answers it for a different subject.

func searchReq(subject, resource, action string, limit int) authzen.SearchRequest {
	return authzen.SearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: subject},
		Resource: &authzen.Resource{Type: "doc", ID: resource},
		Action:   &authzen.Action{Name: action},
		Page:     &authzen.PageRequest{Limit: limit},
	}
}

// tokenFor builds the token this PDP would issue for a request, so the attack
// below starts from a genuine one rather than a guess at its shape.
func tokenFor(req authzen.SearchRequest, cursor string) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(searchFingerprint(req) + "." + cursor))
}

func TestAPageTokenIsAcceptedOnlyByTheRequestThatProducedIt(t *testing.T) {
	base := searchReq("alice", "doc-1", "read", 10)
	tok := tokenFor(base, "cursor-42")

	// The control: the identical request must accept it and recover the cursor.
	same := base
	same.Page = &authzen.PageRequest{Limit: 10, Token: tok}
	_, after, err := pageOf(same)
	if err != nil {
		t.Fatalf("the request that produced the token was refused: %v", err)
	}
	if after != "cursor-42" {
		t.Fatalf("cursor = %q, want cursor-42", after)
	}

	// Every fingerprinted field, changed one at a time.
	for name, alter := range map[string]func(*authzen.SearchRequest){
		"a different subject":      func(r *authzen.SearchRequest) { r.Subject.ID = "mallory" },
		"a different subject type": func(r *authzen.SearchRequest) { r.Subject.Type = "service" },
		"a different resource":     func(r *authzen.SearchRequest) { r.Resource.ID = "doc-2" },
		"a different action":       func(r *authzen.SearchRequest) { r.Action.Name = "write" },
		"a different limit":        func(r *authzen.SearchRequest) { r.Page.Limit = 25 },
		"added context":            func(r *authzen.SearchRequest) { r.Context = map[string]any{"ip": "10.0.0.1"} },
		"a dropped subject":        func(r *authzen.SearchRequest) { r.Subject = nil },
		"a dropped action":         func(r *authzen.SearchRequest) { r.Action = nil },
	} {
		t.Run(name, func(t *testing.T) {
			// Rebuilt from scratch so one case cannot leak into the next.
			r := searchReq("alice", "doc-1", "read", 10)
			r.Page.Token = tok
			alter(&r)

			_, _, err := pageOf(r)
			if err == nil {
				t.Fatalf("a page token issued for a different search was accepted with "+
					"%s; the cursor walks a result set computed for the original "+
					"request", name)
			}
			if !strings.Contains(err.Error(), "different search") {
				t.Errorf("refused, but not as a mismatched token: %v", err)
			}
		})
	}
}

// The property over generated pairs: a token is accepted by another request if
// and only if every fingerprinted field matches.
func TestPageTokenAcceptanceMatchesFingerprintEquality(t *testing.T) {
	rng := rand.New(rand.NewSource(20260821))
	subjects := []string{"alice", "bob", ""}
	resources := []string{"doc-1", "doc-2", ""}
	actions := []string{"read", "write", ""}
	limits := []int{0, 10, 25}

	var accepted, refused int
	for i := 0; i < 2000; i++ {
		a := searchReq(subjects[rng.Intn(3)], resources[rng.Intn(3)], actions[rng.Intn(3)], limits[rng.Intn(3)])

		// Half the pairs are deliberately identical. Drawing both at random from
		// 81 combinations makes them match about one time in eighty, so the
		// accepted branch would be sampled a handful of times in two thousand and
		// the "if and only if" would be proved mostly in one direction.
		var b authzen.SearchRequest
		if rng.Intn(2) == 0 {
			b = searchReq(a.Subject.ID, a.Resource.ID, a.Action.Name, a.Page.Limit)
		} else {
			b = searchReq(subjects[rng.Intn(3)], resources[rng.Intn(3)], actions[rng.Intn(3)], limits[rng.Intn(3)])
		}

		tok := tokenFor(a, "c")
		b.Page.Token = tok

		_, _, err := pageOf(b)
		sameFingerprint := searchFingerprint(a) == searchFingerprint(b)

		if err == nil && !sameFingerprint {
			t.Fatalf("a token from %+v was accepted by %+v", a.Subject, b.Subject)
		}
		if err != nil && sameFingerprint {
			t.Fatalf("a token was refused by a request with an identical "+
				"fingerprint: %v", err)
		}
		if err == nil {
			accepted++
		} else {
			refused++
		}
	}
	if accepted < 50 || refused < 50 {
		t.Fatalf("the generator is lopsided: %d accepted, %d refused", accepted, refused)
	}
	t.Logf("%d accepted, %d refused", accepted, refused)
}

// Tokens this PDP did not issue must not be mistaken for ones it did.
func TestMalformedPageTokensAreRefused(t *testing.T) {
	for name, tok := range map[string]string{
		"not base64":        "!!!not-base64!!!",
		"no separator":      base64.RawURLEncoding.EncodeToString([]byte("nodotshere")),
		"empty fingerprint": base64.RawURLEncoding.EncodeToString([]byte(".cursor")),
		"only a dot":        base64.RawURLEncoding.EncodeToString([]byte(".")),
	} {
		t.Run(name, func(t *testing.T) {
			r := searchReq("alice", "doc-1", "read", 10)
			r.Page.Token = tok
			if _, _, err := pageOf(r); err == nil {
				t.Errorf("a %s token was accepted", name)
			}
		})
	}
}
