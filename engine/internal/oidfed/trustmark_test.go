package oidfed

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// signAs produces an arbitrary signed JWT from this entity's key.
//
// Takes the claims as a map rather than a struct so a test can build a document
// the Go types cannot express -- a mark carrying `id`, a mark with no `typ`, one
// with an `exp` of zero. Every one of those is a thing an implementation might
// be sent, and none of them is constructible through BuildTrustMark, which is
// the point.
func (e *entity) signAs(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithHeader("kid", e.kid)
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: e.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// markClaims is a well-formed Trust Mark claim set, for a test to spoil one
// member of.
func markClaims(iss, sub, markType string) map[string]any {
	return map[string]any{
		"iss": iss, "sub": sub, "trust_mark_type": markType,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

// A Trust Mark validates when every one of §7.3's steps is satisfied, and this
// is the control the rest of the file spoils one member of at a time.
func TestAWellFormedTrustMarkValidates(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://rp.example", "https://fed.example/profile"))

	tm, err := ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://rp.example",
		IssuerJWKS:       issuer.jwks(t),
	})
	if err != nil {
		t.Fatalf("a correct trust mark did not validate: %v", err)
	}
	if tm.Type != "https://fed.example/profile" {
		t.Errorf("trust_mark_type = %q", tm.Type)
	}
}

// §7.3 step 4: the mark must have been issued to the entity publishing it.
//
// This is the cheapest forgery in the specification and it needs no keys: copy a
// genuine, unexpired, correctly signed mark out of one entity's configuration
// into your own. The test therefore uses a mark that is valid in every other
// respect -- if the check is removed, nothing else here catches it.
func TestATrustMarkIssuedToSomebodyElseIsRefused(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://victim.example", "https://fed.example/profile"))

	// Proof the mark itself is good: it validates for the entity it names.
	if _, err := ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://victim.example",
		IssuerJWKS:       issuer.jwks(t),
	}); err != nil {
		t.Fatalf("the control case failed, so this test proves nothing: %v", err)
	}

	_, err := ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://thief.example",
		IssuerJWKS:       issuer.jwks(t),
	})
	if err == nil {
		t.Fatal("a trust mark issued to victim.example was accepted from " +
			"thief.example's configuration")
	}
	if !strings.Contains(err.Error(), "victim.example") ||
		!strings.Contains(err.Error(), "thief.example") {
		t.Errorf("the refusal should name both entities so an operator can see "+
			"which mark landed in whose document; got %q", err)
	}
}

// Skipping the containing entity must not be possible by omission.
func TestValidationRefusesToRunWithoutTheContainingEntity(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://rp.example", "https://fed.example/profile"))

	_, err := ValidateTrustMark(raw, TrustMarkOptions{IssuerJWKS: issuer.jwks(t)})
	if err == nil {
		t.Fatal("validation ran with no containing entity, which silently skips " +
			"section 7.3 step 4")
	}
	// Without the explicit guard the mark is still refused -- step 4 compares
	// against the empty string and fails -- so asserting only `err != nil`
	// proves nothing. What the guard buys is that the message describes the
	// CALLER's mistake. Told "this mark is issued to rp.example but appears in
	// the configuration of \"\"", an operator goes looking at the mark, which is
	// fine; the fault is in their own call.
	if !strings.Contains(err.Error(), "containing entity is required") {
		t.Errorf("the refusal should say the caller omitted the containing "+
			"entity, not that the mark is for the wrong subject; got %q", err)
	}
}

// §7.3 preamble: the issuer's keys come from a completed chain, never from the
// mark. A caller that passes nothing must be refused rather than defaulted.
func TestValidationRefusesToRunWithoutIssuerKeys(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://rp.example", "https://fed.example/profile"))

	_, err := ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://rp.example",
	})
	if err == nil {
		t.Fatal("validation ran with no issuer keys")
	}
	// Same shape as the test above: an empty key set fails to parse further
	// down, so the mark is refused either way and only the message differs.
	if !strings.Contains(err.Error(), "completed trust chain") {
		t.Errorf("the refusal should point at section 7.3's ordering -- trust in "+
			"the issuer comes first -- rather than at a parse failure; got %q", err)
	}
}

// §7.3 step 7: the signature must verify against the ISSUER's key set.
func TestATrustMarkSignedByTheWrongEntityIsRefused(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	impostor := newEntity(t, "https://ta.example", "k1") // same id AND same kid
	raw := impostor.signAs(t, TrustMarkTyp,
		markClaims("https://ta.example", "https://rp.example", "https://fed.example/profile"))

	_, err := ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://rp.example",
		IssuerJWKS:       issuer.jwks(t),
	})
	if err == nil {
		t.Fatal("a mark signed by a different key with a matching kid was accepted")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("the refusal should be about the signature, got %q", err)
	}
}

// §7: "Trust Marks without a typ header parameter or an unrecognized typ value
// MUST be rejected."
func TestTheTypHeaderIsRequiredAndExact(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	claims := markClaims(issuer.id, "https://rp.example", "https://fed.example/profile")

	for _, typ := range []string{
		"",                     // absent
		"JWT",                  // the default a naive signer emits
		"entity-statement+jwt", // the other typ in this very specification
		"Trust-Mark+JWT",       // a case variation
		"trust-mark-delegation+jwt",
	} {
		t.Run("typ="+typ, func(t *testing.T) {
			raw := issuer.signAs(t, typ, claims)
			if _, err := ValidateTrustMark(raw, TrustMarkOptions{
				ContainingEntity: "https://rp.example",
				IssuerJWKS:       issuer.jwks(t),
			}); err == nil {
				t.Fatalf("a document with typ %q was accepted as a Trust Mark", typ)
			}
		})
	}
}

// §7: "Trust Mark JWTs MUST include the kid (Key ID) header parameter".
func TestATrustMarkWithNoKidIsRefused(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	payload, err := json.Marshal(markClaims(issuer.id, "https://rp.example",
		"https://fed.example/profile"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuer.priv},
		(&jose.SignerOptions{}).WithType(jose.ContentType(TrustMarkTyp)))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://rp.example",
		IssuerJWKS:       issuer.jwks(t),
	}); err == nil {
		t.Fatal("a Trust Mark with no kid header was accepted")
	}
}

// The pre-Final `id` claim is refused, whether alone or alongside the current
// one.
//
// A document carrying both is the dangerous case: it validates under either
// reading, and two implementations disagree about what it asserted while each
// believes it checked.
func TestTheDraftEraIDClaimIsRefused(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")

	t.Run("id alone", func(t *testing.T) {
		claims := markClaims(issuer.id, "https://rp.example", "")
		delete(claims, "trust_mark_type")
		claims["id"] = "https://fed.example/profile"
		raw := issuer.signAs(t, TrustMarkTyp, claims)
		if _, err := ValidateTrustMark(raw, TrustMarkOptions{
			ContainingEntity: "https://rp.example",
			IssuerJWKS:       issuer.jwks(t),
		}); err == nil {
			t.Fatal("a draft-era Trust Mark carrying `id` was accepted")
		}
	})

	t.Run("both, disagreeing", func(t *testing.T) {
		claims := markClaims(issuer.id, "https://rp.example", "https://fed.example/real")
		claims["id"] = "https://fed.example/other"
		raw := issuer.signAs(t, TrustMarkTyp, claims)
		_, err := ValidateTrustMark(raw, TrustMarkOptions{
			ContainingEntity: "https://rp.example",
			IssuerJWKS:       issuer.jwks(t),
		})
		if err == nil {
			t.Fatal("a Trust Mark asserting two different type identifiers was accepted")
		}
		if !strings.Contains(err.Error(), "id") {
			t.Errorf("the refusal should name the offending claim, got %q", err)
		}
	})
}

// §7.3 steps 5 and 6, and §7.1's rule that an absent exp means no expiry.
func TestTrustMarkTimes(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	opts := TrustMarkOptions{
		ContainingEntity: "https://rp.example",
		IssuerJWKS:       issuer.jwks(t),
	}

	t.Run("an expired mark is refused", func(t *testing.T) {
		claims := markClaims(issuer.id, "https://rp.example", "https://fed.example/p")
		claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		if _, err := ValidateTrustMark(issuer.signAs(t, TrustMarkTyp, claims), opts); err == nil {
			t.Fatal("an expired Trust Mark validated")
		}
	})

	t.Run("an iat in the future is refused", func(t *testing.T) {
		claims := markClaims(issuer.id, "https://rp.example", "https://fed.example/p")
		claims["iat"] = time.Now().Add(time.Hour).Unix()
		if _, err := ValidateTrustMark(issuer.signAs(t, TrustMarkTyp, claims), opts); err == nil {
			t.Fatal("a Trust Mark issued an hour from now validated")
		}
	})

	// §7.1: "If not present, it means that the Trust Mark does not expire."
	// §7.3 then states the exp check unconditionally, and the two are reconciled
	// by the check being vacuous when the claim is absent -- which is exactly the
	// case §7.3 recommends the status endpoint for.
	t.Run("an absent exp is accepted", func(t *testing.T) {
		claims := markClaims(issuer.id, "https://rp.example", "https://fed.example/p")
		delete(claims, "exp")
		if _, err := ValidateTrustMark(issuer.signAs(t, TrustMarkTyp, claims), opts); err != nil {
			t.Fatalf("a Trust Mark with no exp was refused: %v", err)
		}
	})

	// An `exp` of literally zero is a mark that expired in 1970, not one with no
	// expiry. It matters because omitempty on a Go struct produces exactly this
	// distinction, and getting it backwards makes every non-expiring mark
	// unusable -- or worse, makes an expired one look eternal.
	t.Run("exp of zero is treated as absent, and Build never emits it", func(t *testing.T) {
		tm, err := BuildTrustMark(TrustMarkParams{
			Issuer: issuer.id, Subject: "https://rp.example",
			Type: "https://fed.example/p", Lifetime: 0,
		}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(tm)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"exp"`) {
			t.Errorf("a mark with no lifetime serialised an exp member: %s", b)
		}
	})
}

// §3.1.2: the outer trust_mark_type must equal the one inside the JWT.
func TestTheTrustMarksClaimMembersMustAgree(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://rp.example", "https://fed.example/inner"))

	if err := ValidateTrustMarksClaim([]TrustMarkEntry{
		{Type: "https://fed.example/inner", JWT: raw},
	}); err != nil {
		t.Fatalf("a matching pair was refused: %v", err)
	}

	err := ValidateTrustMarksClaim([]TrustMarkEntry{
		{Type: "https://fed.example/outer", JWT: raw},
	})
	if err == nil {
		t.Fatal("a trust_marks entry advertising one type and carrying another " +
			"was accepted")
	}
	if !strings.Contains(err.Error(), "outer") || !strings.Contains(err.Error(), "inner") {
		t.Errorf("the refusal should name both, got %q", err)
	}
}

// Building an Entity Configuration applies the same syntactic rule, so a
// mis-recorded mark cannot become a signed document.
func TestBuildRefusesAnEntityConfigurationWithMismatchedTrustMarks(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://rp.example", "https://fed.example/inner"))

	_, err := Build(Params{
		EntityID:       "https://rp.example",
		FederationJWKS: issuer.jwks(t),
		Lifetime:       time.Hour,
		TrustMarks:     []TrustMarkEntry{{Type: "https://fed.example/other", JWT: raw}},
	}, time.Now())
	if err == nil {
		t.Fatal("an Entity Configuration was built carrying a self-contradictory " +
			"trust mark, which every conformant reader rejects")
	}
}

// §3.1.2: trust_mark_issuers and trust_mark_owners are meaningless anywhere but
// a Trust Anchor, and a reader MUST ignore them -- so emitting them from a
// subordinate publishes a policy nothing applies.
func TestTheTrustAnchorClaimsAreRefusedFromASubordinate(t *testing.T) {
	e := newEntity(t, "https://sub.example", "k1")
	base := Params{
		EntityID:       "https://sub.example",
		FederationJWKS: e.jwks(t),
		Lifetime:       time.Hour,
		AuthorityHints: []string{"https://ta.example"},
	}

	t.Run("issuers", func(t *testing.T) {
		p := base
		p.TrustMarkIssuers = TrustMarkIssuers{"https://fed.example/p": {}}
		if _, err := Build(p, time.Now()); err == nil {
			t.Fatal("trust_mark_issuers was published by an entity with a Superior")
		}
	})
	t.Run("owners", func(t *testing.T) {
		p := base
		p.TrustMarkOwners = TrustMarkOwners{
			"https://fed.example/p": {Subject: "https://owner.example", JWKS: e.jwks(t)},
		}
		if _, err := Build(p, time.Now()); err == nil {
			t.Fatal("trust_mark_owners was published by an entity with a Superior")
		}
	})
	t.Run("and permitted from an anchor", func(t *testing.T) {
		p := base
		p.AuthorityHints = nil
		p.TrustMarkIssuers = TrustMarkIssuers{"https://fed.example/p": {}}
		if _, err := Build(p, time.Now()); err != nil {
			t.Fatalf("a Trust Anchor could not publish trust_mark_issuers: %v", err)
		}
	})
}

// §3.1.2's empty array, which reverses this codebase's usual fail-closed rule.
//
// Three states, three answers. A test per state, because the bug is always a
// collapse of two of them into one.
func TestTrustMarkIssuersDistinguishesThreeStates(t *testing.T) {
	const typ = "https://fed.example/p"

	t.Run("the claim is absent: this is not the gate", func(t *testing.T) {
		var ti TrustMarkIssuers
		permitted, known := ti.IssuerPermitted(typ, "https://anyone.example")
		if known {
			t.Error("an absent claim reported a decision it cannot make")
		}
		if permitted {
			t.Error("an absent claim permitted an issuer")
		}
		if ti.Governs(typ) {
			t.Error("an absent claim reported that it governs a type")
		}
	})

	t.Run("the type is absent from a present claim", func(t *testing.T) {
		ti := TrustMarkIssuers{"https://fed.example/other": {"https://a.example"}}
		permitted, known := ti.IssuerPermitted(typ, "https://a.example")
		if known {
			t.Error("a claim silent about this type reported a decision")
		}
		if permitted {
			t.Error("a claim silent about this type permitted an issuer")
		}
	})

	t.Run("an empty array means ANYONE, per section 3.1.2", func(t *testing.T) {
		ti := TrustMarkIssuers{typ: {}}
		permitted, known := ti.IssuerPermitted(typ, "https://a-total-stranger.example")
		if !known {
			t.Error("an enumerated type was reported as ungoverned")
		}
		if !permitted {
			t.Error("an empty array denied an issuer; section 3.1.2 says an empty " +
				"array means anyone MAY issue, which is the opposite of the " +
				"fail-closed reading used elsewhere in this codebase")
		}
	})

	t.Run("a populated array is an allow-list", func(t *testing.T) {
		ti := TrustMarkIssuers{typ: {"https://a.example"}}
		if p, _ := ti.IssuerPermitted(typ, "https://a.example"); !p {
			t.Error("a listed issuer was denied")
		}
		if p, _ := ti.IssuerPermitted(typ, "https://b.example"); p {
			t.Error("an unlisted issuer was permitted")
		}
	})
}

// §7.2.2, the delegation rules.
func TestDelegation(t *testing.T) {
	owner := newEntity(t, "https://owner.example", "ow1")
	delegate := newEntity(t, "https://inspector.example", "in1")
	const typ = "https://gov.example/inspection"

	ownerDecl := TrustMarkOwner{Subject: owner.id, JWKS: owner.jwks(t)}

	goodDelegation := owner.signAs(t, DelegationTyp, map[string]any{
		"iss": owner.id, "sub": delegate.id, "trust_mark_type": typ,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	markWith := func(delegation string) string {
		c := markClaims(delegate.id, "https://garage.example", typ)
		if delegation != "" {
			c["delegation"] = delegation
		}
		return delegate.signAs(t, TrustMarkTyp, c)
	}
	opts := func() TrustMarkOptions {
		return TrustMarkOptions{
			ContainingEntity: "https://garage.example",
			IssuerJWKS:       delegate.jwks(t),
			Owners:           TrustMarkOwners{typ: ownerDecl},
		}
	}

	t.Run("a delegated mark validates", func(t *testing.T) {
		if _, err := ValidateTrustMark(markWith(goodDelegation), opts()); err != nil {
			t.Fatalf("a correctly delegated Trust Mark was refused: %v", err)
		}
	})

	// §7.3 step 8.
	t.Run("a declared-owner type without a delegation is refused", func(t *testing.T) {
		_, err := ValidateTrustMark(markWith(""), opts())
		if err == nil {
			t.Fatal("a mark of an owned type carried no delegation and was accepted")
		}
		if !strings.Contains(err.Error(), "delegation") {
			t.Errorf("the refusal should say a delegation is required, got %q", err)
		}
	})

	// The direction check, which is the one that gets written backwards.
	//
	// Two tests, each spoiling ONE member, because a delegation with both
	// swapped is caught by either check alone -- so a single swapped-pair test
	// passes with either one deleted, which is the shape of a test that proves
	// nothing. (It was written that way first. Mutation found it.)
	t.Run("a delegation authorising a third party is refused", func(t *testing.T) {
		// iss is the owner and the signature is the owner's, both correct. Only
		// `sub` is wrong, so only the sub check can refuse this.
		elsewhere := owner.signAs(t, DelegationTyp, map[string]any{
			"iss": owner.id, "sub": "https://someone-else.example",
			"trust_mark_type": typ,
			"iat":             time.Now().Add(-time.Minute).Unix(),
		})
		_, err := ValidateTrustMark(markWith(elsewhere), opts())
		if err == nil {
			t.Fatal("a delegation authorising someone-else.example was used by " +
				"inspector.example to issue a mark")
		}
		if !strings.Contains(err.Error(), "someone-else.example") {
			t.Errorf("the refusal should name who the delegation actually "+
				"authorises, got %q", err)
		}
	})

	t.Run("a delegation claiming a different owner is refused", func(t *testing.T) {
		// Signed by the owner's key, so the signature verifies; `sub` is the
		// delegate, so that check passes. Only `iss` is wrong.
		misattributed := owner.signAs(t, DelegationTyp, map[string]any{
			"iss": "https://not-the-owner.example", "sub": delegate.id,
			"trust_mark_type": typ,
			"iat":             time.Now().Add(-time.Minute).Unix(),
		})
		_, err := ValidateTrustMark(markWith(misattributed), opts())
		if err == nil {
			t.Fatal("a delegation issued by a party the Trust Anchor does not " +
				"name as the owner was accepted")
		}
		if !strings.Contains(err.Error(), "not-the-owner.example") {
			t.Errorf("the refusal should name the claimed issuer, got %q", err)
		}
	})

	t.Run("a delegation for a different type is refused", func(t *testing.T) {
		other := owner.signAs(t, DelegationTyp, map[string]any{
			"iss": owner.id, "sub": delegate.id,
			"trust_mark_type": "https://gov.example/something-else",
			"iat":             time.Now().Add(-time.Minute).Unix(),
		})
		if _, err := ValidateTrustMark(markWith(other), opts()); err == nil {
			t.Fatal("a delegation for a different Trust Mark type was accepted")
		}
	})

	// §7.2.2: the signature verifies against the OWNER's keys, taken from the
	// Trust Anchor -- not against the delegate's, and not against anything the
	// delegation carries.
	t.Run("a delegation signed by the delegate itself is refused", func(t *testing.T) {
		self := delegate.signAs(t, DelegationTyp, map[string]any{
			"iss": owner.id, "sub": delegate.id, "trust_mark_type": typ,
			"iat": time.Now().Add(-time.Minute).Unix(),
		})
		if _, err := ValidateTrustMark(markWith(self), opts()); err == nil {
			t.Fatal("an entity signed its own authority to issue and was accepted")
		}
	})

	t.Run("the delegation typ is checked", func(t *testing.T) {
		wrongTyp := owner.signAs(t, TrustMarkTyp, map[string]any{
			"iss": owner.id, "sub": delegate.id, "trust_mark_type": typ,
			"iat": time.Now().Add(-time.Minute).Unix(),
		})
		if _, err := ValidateTrustMark(markWith(wrongTyp), opts()); err == nil {
			t.Fatal("a trust-mark+jwt was accepted where a delegation was required")
		}
	})

	t.Run("an expired delegation is refused", func(t *testing.T) {
		stale := owner.signAs(t, DelegationTyp, map[string]any{
			"iss": owner.id, "sub": delegate.id, "trust_mark_type": typ,
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-time.Hour).Unix(),
		})
		if _, err := ValidateTrustMark(markWith(stale), opts()); err == nil {
			t.Fatal("an expired delegation was accepted")
		}
	})

	// §7.3 step 9 has no condition on the owner having been declared, so a mark
	// carrying a delegation the Trust Anchor never authorised must not simply
	// have that claim ignored.
	t.Run("an undeclared delegation is refused rather than ignored", func(t *testing.T) {
		o := opts()
		o.Owners = nil
		_, err := ValidateTrustMark(markWith(goodDelegation), o)
		if err == nil {
			t.Fatal("a mark carrying a delegation from a party the Trust Anchor " +
				"never named was accepted, with the delegation unchecked")
		}
		// The delegation itself is perfectly valid -- same bytes as the passing
		// case above. What is missing is anybody authoritative saying the owner
		// exists.
		//
		// The message is asserted to name the TYPE, not merely the claim. Without
		// the explicit guard the mark is still refused, by ValidateDelegation
		// finding it has been handed a zero-valued owner -- so a test asserting
		// only "err mentions trust_mark_owners" passes with the guard deleted.
		// What the guard buys is telling an operator WHICH of the types their
		// anchor governs is unaccounted for, which on an anchor with twenty of
		// them is the difference between a fix and a search.
		if !strings.Contains(err.Error(), typ) {
			t.Errorf("the refusal should name the Trust Mark type the anchor has "+
				"nothing to say about, got %q", err)
		}
	})
}

// §7.1 requires a collision-resistant identifier; we require a URL.
func TestTrustMarkTypeMustBeAURL(t *testing.T) {
	for _, bad := range []string{"", "certified", "urn:example:certified", "/profile"} {
		if err := ValidateTrustMarkType(bad); err == nil {
			t.Errorf("%q was accepted as a Trust Mark type identifier", bad)
		}
	}
	if err := ValidateTrustMarkType("https://fed.example/profile"); err != nil {
		t.Errorf("a URL identifier was refused: %v", err)
	}
}

// BuildDelegation refuses a self-delegation, which says nothing §7.2 asks for.
func TestASelfDelegationIsRefused(t *testing.T) {
	if _, err := BuildDelegation(DelegationParams{
		Owner: "https://a.example", Delegate: "https://a.example",
		Type: "https://fed.example/p",
	}, time.Now()); err == nil {
		t.Fatal("an entity delegated to itself")
	}
}

// A key set carrying private material must not be used to verify.
//
// It would work, which is the problem: a private JWK verifies happily, so the
// operator's only signal that they had published a signing key would be that
// nothing complained.
func TestVerificationRefusesAPrivateKeyInAPublishedSet(t *testing.T) {
	issuer := newEntity(t, "https://ta.example", "k1")
	raw := issuer.signAs(t, TrustMarkTyp,
		markClaims(issuer.id, "https://rp.example", "https://fed.example/p"))

	privateSet, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: issuer.priv, KeyID: issuer.kid, Algorithm: "ES256", Use: "sig"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateTrustMark(raw, TrustMarkOptions{
		ContainingEntity: "https://rp.example",
		IssuerJWKS:       privateSet,
	})
	if err == nil {
		t.Fatal("a private key in a published key set was used to verify a mark")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Errorf("the refusal should name the problem, got %q", err)
	}
}
