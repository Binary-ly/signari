package oidfed

import (
	"strings"
	"testing"
	"time"
)

// OpenID Federation 1.0 §3.2:
//
//	"If the crit Claim is present, then each array element in this Claim's value
//	MUST be a string representing an Entity Statement Claim that is not defined
//	by this specification and that Claim MUST be understood and be able to be
//	processed by the implementation."
//
//	"If any of these validation steps fail, the Entity Statement MUST be
//	rejected."
//
// Found on a full extraction of the specification — 786 normative uses across
// 125 sections. §3.2 alone carries 39, and this engine's earlier passes had read
// §6.2 and §12.1.
//
// `crit` is the issuer saying: this statement means something other than it
// appears to, and if you cannot process the named claim you must not use it.
// Reading it anyway is not partial understanding — it is acting on a document
// whose author warned you in advance that you would misread it.
//
// The same package already enforces `metadata_policy_crit`, which marks critical
// policy OPERATORS. This marks critical CLAIMS, and was not read at all.
func TestACriticalClaimWeDoNotUnderstandIsRefused(t *testing.T) {
	es := Statement{
		Issuer: "https://op.example", Subject: "https://op.example",
		Crit: []string{"https://example.org/some_extension"},
	}
	err := checkCrit(es)
	if err == nil {
		t.Fatal("a statement marking an unknown claim critical was accepted; its " +
			"issuer said not to act on it without processing that claim")
	}
	if !strings.Contains(err.Error(), "some_extension") {
		t.Errorf("the refusal does not name the claim, so an operator cannot tell "+
			"which extension their federation needs: %v", err)
	}
}

// §3.2 requires each entry to name a claim the specification does NOT define.
// `crit: ["iss"]` is malformed rather than a stricter request, and treating it as
// merely unknown would report the wrong problem.
func TestCritMayNotNameASpecifiedClaim(t *testing.T) {
	for _, name := range []string{"iss", "sub", "jwks", "metadata_policy", "constraints"} {
		err := checkCrit(Statement{Crit: []string{name}})
		if err == nil {
			t.Errorf("crit naming the defined claim %q was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "defines") {
			t.Errorf("crit naming %q was refused as unknown rather than as malformed: %v",
				name, err)
		}
	}
}

// An empty entry is not a claim name.
func TestCritRejectsAnEmptyEntry(t *testing.T) {
	if err := checkCrit(Statement{Crit: []string{""}}); err == nil {
		t.Error("an empty crit entry was accepted")
	}
}

// A statement with no crit claim must be unaffected, or every federation stops
// working.
func TestAStatementWithoutCritIsUnaffected(t *testing.T) {
	if err := checkCrit(Statement{Issuer: "https://a.example"}); err != nil {
		t.Errorf("a statement carrying no crit claim was refused: %v", err)
	}
	if err := checkCrit(Statement{Crit: []string{}}); err != nil {
		t.Errorf("a statement carrying an empty crit array was refused: %v", err)
	}
}

// The helper being correct and the helper being REACHED are different claims.
// This drives a real chain through ValidateChain, which is what every caller
// uses, rather than calling checkCrit directly.
func TestValidateChainRefusesAChainCarryingAnUnknownCriticalClaim(t *testing.T) {
	_, inter, anchor, chain := chainFor(t)

	// Baseline: the chain is good before it is spoiled, or the assertion below
	// would pass for whatever other reason the chain was already broken.
	if _, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now()); err != nil {
		t.Fatalf("the fixture chain does not validate, so this test proves nothing: %v", err)
	}
	_ = inter

	// The INTERMEDIATE marks an extension claim critical in its Subordinate
	// Statement about the leaf. A superior saying "do not act on this unless you
	// understand X" is exactly the case that matters: it governs whether the leaf
	// may sign anybody in.
	chain[1].Crit = []string{"https://example.org/assurance_level"}

	_, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
	if err == nil {
		t.Fatal("a chain whose intermediate marked an unprocessed claim critical " +
			"was accepted; the superior's instruction not to act on the statement " +
			"was read as no instruction at all")
	}
	if !strings.Contains(err.Error(), "assurance_level") {
		t.Errorf("the refusal does not name the claim: %v", err)
	}
	// And it must be attributed to the right statement.
	if !strings.Contains(err.Error(), "statement 1") {
		t.Errorf("the refusal does not say which statement carried it: %v", err)
	}
}
