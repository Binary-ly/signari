package oidfed

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

// The second turn on OpenID Federation: attacking a real signed chain rather
// than reading ValidateChain.
//
// The result is mostly a negative one, and it is worth recording as such. The
// tamperings a chain walk has to survive — a broken link, a leaf signed with a
// key its superior does not attest, a statement expired or issued in the future,
// a chain terminating at the wrong anchor, anchor keys taken from the chain
// instead of out of band, a chain of one, a missing `kid`, a link whose
// signatures all verify but which does not join — are **already covered** in
// chain_test.go, case by case.
//
// Three were not, and they are here. The rest of the planned attack was deleted
// rather than duplicated: a second test asserting what an existing one already
// asserts adds a maintenance cost and no evidence.

// A statement with no keys cannot vouch for anything below it, and the check
// must not depend on the signature failing by accident.
func TestAStatementCarryingNoKeysIsRefused(t *testing.T) {
	for i := 0; i < 3; i++ {
		_, _, anchor, chain := chainFor(t)
		if _, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now()); err != nil {
			t.Fatalf("the fixture chain does not validate: %v", err)
		}
		chain[i].JWKS = nil
		_, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
		if err == nil {
			t.Errorf("statement %d carried no jwks and the chain was accepted", i)
			continue
		}
		// The REASON matters. Deleting the explicit check still leaves the chain
		// refused -- a nil key set fails the signature step a few lines later --
		// so a test asserting only "refused" passes with the guard removed. It
		// did, until this assertion was added.
		if !strings.Contains(err.Error(), "carries no jwks") {
			t.Errorf("statement %d with no jwks was refused for another reason, so "+
				"the explicit check is untested: %v", i, err)
		}
	}
}

// §3.1.1 makes iss, sub, iat and exp REQUIRED. Each absence must be refused on
// its own, not caught downstream by a comparison that happens to fail.
func TestEveryRequiredClaimIsRequiredIndividually(t *testing.T) {
	for name, blank := range map[string]func(*Statement){
		"iss": func(s *Statement) { s.Issuer = "" },
		"sub": func(s *Statement) { s.Subject = "" },
		"iat": func(s *Statement) { s.IssuedAt = 0 },
		"exp": func(s *Statement) { s.Expiry = 0 },
	} {
		for i := 0; i < 3; i++ {
			_, _, anchor, chain := chainFor(t)
			blank(&chain[i])
			_, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
			if err == nil {
				t.Errorf("statement %d with no %s was accepted", i, name)
				continue
			}
			// Same trap: a missing `exp` is also caught by the expiry comparison
			// (time.Unix(0,0) is 1970), and a missing `iss` by the link check. The
			// explicit REQUIRED-claim guard is only tested if the refusal names it.
			if !strings.Contains(err.Error(), "missing a required claim") {
				t.Errorf("statement %d with no %s was refused for another reason, so "+
					"the section 3.1.1 check is untested: %v", i, name, err)
			}
		}
	}
}

// §10.4 over generated values rather than one example.
//
// chain_test.go asserts the minimum is taken using a fixed early/late pair. That
// proves the minimum is not the LAST value; it does not prove it is not the
// first, or the subject's, since in that arrangement they differ from the answer
// in only one way. Randomising which member is earliest distinguishes all of them.
func TestTheChainExpiryIsTheMinimumWhicheverMemberHoldsIt(t *testing.T) {
	rng := rand.New(rand.NewSource(20260821))

	for i := 0; i < 300; i++ {
		leaf := newEntity(t, "https://leaf.example", "l")
		inter := newEntity(t, "https://inter.example", "i")
		anchor := newEntity(t, "https://anchor.example", "a")

		exps := make([]time.Time, 3)
		for j := range exps {
			exps[j] = time.Now().Add(time.Duration(30+rng.Intn(3000)) * time.Second)
		}
		chain := []Statement{
			leaf.sign(t, leaf.id, leaf.jwks(t), exps[0]),
			inter.sign(t, leaf.id, leaf.jwks(t), exps[1]),
			anchor.sign(t, inter.id, inter.jwks(t), exps[2]),
		}

		res, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
		if err != nil {
			t.Fatalf("a valid chain was refused: %v", err)
		}

		want := exps[0]
		earliest := 0
		for j, e := range exps {
			if e.Before(want) {
				want, earliest = e, j
			}
		}
		if res.Expiry.Unix() != want.Unix() {
			t.Fatalf("chain expiry = %d, want %d (the minimum, held by statement %d; "+
				"members %d %d %d)", res.Expiry.Unix(), want.Unix(), earliest,
				exps[0].Unix(), exps[1].Unix(), exps[2].Unix())
		}
	}
}
