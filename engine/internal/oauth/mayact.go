package oauth

import (
	"fmt"
	"sort"
	"strings"
)

// CheckMayAct enforces RFC 8693 §4.4 when a subject token carries the claim.
//
// # Why this is enforced despite being a MAY
//
// §4.4 says may_act "can be used by the authorization server to determine
// whether the client ... is authorized to engage in the requested delegation".
// Using it is optional. IGNORING IT WHEN PRESENT IS NOT THE SAME CHOICE.
//
// An absent claim means the issuer expressed no opinion, and our per-client
// exchange permission and audience allow-list bound the exchange instead. A
// PRESENT claim means the issuer named who may act — and an operator who sets it
// believes they have constrained delegation. Parsing that away and exchanging
// anyway grants exactly the delegation they wrote the claim to prevent.
//
// That is the same shape as OpenID Federation's `constraints`, fixed earlier:
// a restriction the sender placed in a signed statement, silently discarded by
// the receiver.
//
// # Matching, and why unknown members refuse
//
// §4.4 fixes no matching algorithm and no member set. So this requires every
// member it understands to match, and REFUSES on any member it does not:
//
//	"claims within the "may_act" claim pertain only to the identity of that
//	party" — so each one narrows who may act, and a member we cannot evaluate is
//	a narrowing we cannot honour.
//
// Treating an unrecognised member as satisfied would let an issuer write
// `{"sub": "admin", "department": "finance"}` and have us check half of it.
// Fail closed: the exchange is refused with a message naming the member, so the
// operator learns their constraint is not enforceable here rather than assuming
// it held.
//
// exp, nbf and aud are explicitly not meaningful inside may_act (§4.4 says so),
// so they are refused too rather than quietly skipped — their presence means the
// claim was built by something that misunderstood it.
func CheckMayAct(mayAct map[string]any, actorClientID, actorSubject, issuer string) error {
	if len(mayAct) == 0 {
		return nil // the issuer expressed no opinion
	}

	known := map[string]string{
		"client_id": actorClientID,
		"iss":       issuer,
	}
	// `sub` names the ACTOR, and there is only an actor subject to compare against
	// when the request presented an `actor_token`.
	//
	// §4.4: the claim identifies "some party that is authorized to become the
	// actor and act on behalf of the subject", and "the claims within the may_act
	// claim pertain only to the identity of that party."
	//
	// This used to receive the SUBJECT token's own `sub` -- the user being acted
	// FOR, not the party doing the acting -- which made the comparison compare a
	// value against itself. `may_act: {"sub": "<the subject>"}`, meaning "only
	// this person may act", matched and passed, so a restriction naming one human
	// was honoured by any client with `may_exchange`. A false pass on a real
	// constraint, which is the failure this whole function exists to prevent.
	//
	// With no actor token the acting party is a client and has no user subject, so
	// `sub` is left out of the map and falls through to the unevaluable-member
	// branch below: refused, and named, rather than compared against the wrong
	// identity.
	if actorSubject != "" {
		known["sub"] = actorSubject
	}

	var unknown []string
	for member, want := range mayAct {
		got, understood := known[member]
		if !understood {
			unknown = append(unknown, member)
			continue
		}
		s, ok := want.(string)
		if !ok {
			return fmt.Errorf("the subject token's may_act.%s is not a string, so "+
				"it cannot be matched against the party requesting this exchange",
				member)
		}
		if s != got {
			return fmt.Errorf("the subject token's may_act names %s %q and this "+
				"exchange is requested by %q", member, s, got)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		hint := ""
		for _, u := range unknown {
			if u == "sub" {
				hint = " (may_act.sub names the party that may act; present an " +
					"actor_token identifying that party)"
			}
		}
		return fmt.Errorf("the subject token's may_act constrains the actor by %s, "+
			"which this server cannot evaluate; refusing rather than honouring "+
			"part of a restriction (RFC 8693 section 4.4)%s",
			strings.Join(unknown, ", "), hint)
	}
	return nil
}
