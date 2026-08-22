package oidfed

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Trust Mark validation: §7.3 for an instance, §7.2.2 for a delegation.
//
// # Two rules that look like one
//
// §3.1.2 requires that the `trust_mark_type` member of a `trust_marks` array
// element match the `trust_mark_type` CLAIM inside the JWT it carries. §10.2
// then says, of that check:
//
//	"Validating the syntax is separate from evaluating whether particular Trust
//	Marks are issued by a trusted party and are trusted; that process is
//	described in Section 7.3 and MAY be performed as a separate step from
//	syntactic validation."
//
// They are separate functions here for that reason. A chain can be structurally
// valid while carrying a Trust Mark from somebody nobody trusts, and conflating
// the two produces an implementation that either rejects good chains or accepts
// bad marks -- both from one merged code path that appears to check everything.

// Leeway is the clock skew allowed on iat and exp.
//
// §7.3 permits "some small leeway to account for clock skew" on both. Sixty
// seconds: large enough for hosts whose NTP has drifted, small enough that a
// mark revoked a minute ago is not still being honoured an hour later.
const Leeway = 60 * time.Second

// TrustMarkOwner is one entry of the `trust_mark_owners` claim, §3.1.2.
type TrustMarkOwner struct {
	// Subject is the Entity Identifier of the owner. REQUIRED.
	Subject string `json:"sub"`
	// JWKS is the owner's Federation Entity Keys. REQUIRED.
	JWKS json.RawMessage `json:"jwks"`
}

// TrustMarkOwners maps a Trust Mark type identifier to its owner.
type TrustMarkOwners map[string]TrustMarkOwner

// TrustMarkIssuers maps a Trust Mark type identifier to the entities a Trust
// Anchor accepts as its accreditation authorities, §3.1.2.
type TrustMarkIssuers map[string][]string

// IssuerPermitted answers whether a Trust Anchor's `trust_mark_issuers` claim
// admits this issuer for this type.
//
// # The empty array
//
// §3.1.2: "If the array following a Trust Mark type identifier is empty, anyone
// MAY issue Trust Marks with that identifier."
//
// That is the OPPOSITE of the fail-closed reading this codebase applies almost
// everywhere else, where an empty list permits nothing. It is written into the
// specification, so it is implemented as written -- but the three states are
// kept genuinely distinct, because collapsing any two of them is where the bugs
// live:
//
//   - the whole claim absent: the Trust Anchor has not constrained issuers at
//     all, and this function is not the gate. `known` is false.
//   - the claim present, this type absent from it: the Trust Anchor has
//     enumerated the types it governs and this is not one of them. A caller must
//     decide; see TrustMarkIssuers.Governs.
//   - the type present with an empty array: anyone may issue.
//
// A naive `len(list) == 0 -> deny` turns the specification's "anyone" into
// "nobody" and a federation's marks all stop validating. A naive
// `len(list) == 0 -> allow` applied to the absent-type case turns an
// unenumerated type into an unguarded one.
func (ti TrustMarkIssuers) IssuerPermitted(markType, issuer string) (permitted, known bool) {
	if ti == nil {
		return false, false
	}
	list, ok := ti[markType]
	if !ok {
		return false, false
	}
	if len(list) == 0 {
		// The specification's "anyone MAY issue".
		return true, true
	}
	for _, e := range list {
		if e == issuer {
			return true, true
		}
	}
	return false, true
}

// Governs reports whether a Trust Anchor has said anything about this type.
func (ti TrustMarkIssuers) Governs(markType string) bool {
	if ti == nil {
		return false
	}
	_, ok := ti[markType]
	return ok
}

// TrustMarkOptions is what §7.3 needs beyond the mark itself.
type TrustMarkOptions struct {
	// ContainingEntity is the Entity Identifier of the entity whose Entity
	// Configuration carried this mark.
	//
	// §7.3: "The Entity Identifier of the Entity whose Entity Configuration
	// contains the instance MUST match the value of the Claim sub in the Trust
	// Mark." Required, and there is no default: an implementation that skips
	// this step accepts a genuine, unexpired, correctly signed Trust Mark issued
	// to SOMEBODY ELSE, copied into this entity's configuration by whoever
	// controls it. That is the cheapest forgery in the specification and it
	// needs no keys at all.
	ContainingEntity string

	// IssuerJWKS is the Trust Mark Issuer's Federation Entity Keys, obtained by
	// establishing trust in the issuer first (§7.3's preamble, §10).
	IssuerJWKS json.RawMessage

	// Owners is the Trust Anchor's `trust_mark_owners` claim, if it has one.
	//
	// Nil is meaningful: the Trust Anchor has not declared any type to be owned
	// by an entity other than its issuer, so §7.3's delegation requirement does
	// not fire. It is NOT a reason to skip validating a delegation that is
	// present -- the last step of §7.3 applies to any delegation claim, declared
	// or not.
	Owners TrustMarkOwners

	// Now is the evaluation time. Zero uses time.Now.
	Now time.Time
}

// ValidateTrustMark applies §7.3 to one Trust Mark instance.
//
// Returns the parsed claim set on success. Every failure is fatal to the mark:
// "if any of these validation checks fail, the entire validation process fails
// and the instance is considered invalid."
func ValidateTrustMark(raw string, opts TrustMarkOptions) (*TrustMark, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if opts.ContainingEntity == "" {
		return nil, fmt.Errorf("the containing entity is required: section 7.3 " +
			"compares it with the mark's sub, and skipping that step accepts a " +
			"genuine Trust Mark issued to somebody else")
	}
	if len(opts.IssuerJWKS) == 0 {
		return nil, fmt.Errorf("the Trust Mark issuer's keys must be supplied " +
			"from a completed trust chain (section 7.3): trust in the issuer comes " +
			"before trust in the mark")
	}

	// Steps 1-3: a signed JWT, the right typ, an acceptable alg that is not none.
	//
	// `none` is refused by construction rather than by comparison: jose.ParseSigned
	// takes an allow-list of algorithms and "none" is not in it, so a mark
	// claiming it fails to parse. A string comparison against "none" is the
	// version of this check that gets bypassed by "NONE" or "nOnE".
	tok, err := parseTrustMarkJWS(raw)
	if err != nil {
		return nil, err
	}
	if err := requireTyp(tok, TrustMarkTyp); err != nil {
		return nil, err
	}

	payload, err := verifyAgainstJWKS(tok, raw, opts.IssuerJWKS)
	if err != nil {
		return nil, fmt.Errorf("the Trust Mark's signature: %w", err)
	}

	tm, err := parseTrustMarkClaims(payload)
	if err != nil {
		return nil, err
	}

	// Step 4: sub must be the entity whose configuration carried the mark.
	if tm.Subject != opts.ContainingEntity {
		return nil, fmt.Errorf("the Trust Mark is issued to %q but appears in the "+
			"Entity Configuration of %q (section 7.3)", tm.Subject, opts.ContainingEntity)
	}

	// Steps 5 and 6: iat in the past, exp in the future.
	if err := checkTrustMarkTimes(tm.IssuedAt, tm.Expiry, now, "Trust Mark"); err != nil {
		return nil, err
	}

	// Step 8: a type the Trust Anchor says is owned elsewhere MUST carry a
	// delegation.
	owner, owned := opts.Owners[tm.Type]
	if owned && tm.Delegation == "" {
		return nil, fmt.Errorf("the Trust Anchor declares %q to be owned by %q, so "+
			"a Trust Mark of that type must carry a delegation claim (section 7.3)",
			tm.Type, owner.Subject)
	}

	// Step 9: any delegation present is validated, declared or not.
	//
	// "If there is a delegation Claim in the instance, the value of that Claim
	// MUST be validated" -- with no condition on the owner having been declared.
	// A mark carrying an undeclared delegation is one whose issuer is claiming
	// authority from a party the Trust Anchor never named, and the honest
	// outcome is a refusal that says which party.
	if tm.Delegation != "" {
		if !owned {
			return nil, fmt.Errorf("the Trust Mark carries a delegation for type %q, "+
				"but the Trust Anchor's trust_mark_owners names no owner for that "+
				"type, so there is no key to validate the delegation against "+
				"(section 7.2.2)", tm.Type)
		}
		if err := ValidateDelegation(tm.Delegation, DelegationOptions{
			MarkIssuer: tm.Issuer,
			MarkType:   tm.Type,
			Owner:      owner,
			Now:        now,
		}); err != nil {
			return nil, fmt.Errorf("the Trust Mark's delegation: %w", err)
		}
	}

	return tm, nil
}

// DelegationOptions is what §7.2.2 needs.
type DelegationOptions struct {
	// MarkIssuer is the Entity Identifier of the Trust Mark Issuer, which must
	// equal the delegation's `sub`.
	MarkIssuer string
	// MarkType is the Trust Mark's own type identifier, which must equal the
	// delegation's.
	MarkType string
	// Owner is the Trust Anchor's declaration of who owns this type, carrying
	// both the expected `iss` and the keys the signature must verify against.
	Owner TrustMarkOwner
	Now   time.Time
}

// ValidateDelegation applies §7.2.2 to a Trust Mark Delegation JWT.
func ValidateDelegation(raw string, opts DelegationOptions) error {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if opts.Owner.Subject == "" || len(opts.Owner.JWKS) == 0 {
		return fmt.Errorf("the Trust Mark owner's identifier and keys are required; " +
			"section 7.2.2 takes both from the Trust Anchor's trust_mark_owners claim")
	}

	tok, err := parseTrustMarkJWS(raw)
	if err != nil {
		return err
	}
	if err := requireTyp(tok, DelegationTyp); err != nil {
		return err
	}

	payload, err := verifyAgainstJWKS(tok, raw, opts.Owner.JWKS)
	if err != nil {
		return fmt.Errorf("the delegation's signature did not verify against the "+
			"Trust Mark Owner's keys: %w", err)
	}

	var d Delegation
	if err := json.Unmarshal(payload, &d); err != nil {
		return fmt.Errorf("the delegation's claims did not parse: %w", err)
	}
	if err := rejectLegacyID(payload, "delegation"); err != nil {
		return err
	}
	if d.Issuer == "" || d.Subject == "" || d.Type == "" || d.IssuedAt == 0 {
		return fmt.Errorf("a delegation requires iss, sub, trust_mark_type and iat " +
			"(section 7.2.1)")
	}

	// The two identity checks. Direction matters: the OWNER issues, the ISSUER
	// is the subject.
	if d.Subject != opts.MarkIssuer {
		return fmt.Errorf("the delegation authorises %q to issue, but the Trust "+
			"Mark was issued by %q (section 7.2.2)", d.Subject, opts.MarkIssuer)
	}
	if d.Issuer != opts.Owner.Subject {
		return fmt.Errorf("the delegation is issued by %q, but the Trust Anchor "+
			"names %q as the owner of this Trust Mark type (section 7.2.2)",
			d.Issuer, opts.Owner.Subject)
	}
	if d.Type != opts.MarkType {
		return fmt.Errorf("the delegation is for type %q and the Trust Mark is of "+
			"type %q (section 7.2.2)", d.Type, opts.MarkType)
	}
	return checkTrustMarkTimes(d.IssuedAt, d.Expiry, now, "delegation")
}

// checkTrustMarkTimes applies the iat and exp steps.
//
// The exp step is worded as an unconditional MUST in §7.3 -- "The current time
// MUST be before the time represented by the exp (expiration) Claim" -- while
// §7.1 makes `exp` OPTIONAL and says its absence means the mark does not expire.
// Read together, the check is vacuous when the claim is absent; §7.3 then adds
// that where marks are issued without an expiry "it is RECOMMENDED that a
// mechanism be provided to validate them, such as the Trust Mark Status
// endpoint".
//
// So an absent exp is accepted here and is not the end of the story: a caller
// that cares whether a non-expiring mark is still live has to ask the issuer,
// which is what the status endpoint is for.
func checkTrustMarkTimes(iat, exp int64, now time.Time, what string) error {
	if iat == 0 {
		return fmt.Errorf("the %s has no iat, which is REQUIRED", what)
	}
	if time.Unix(iat, 0).After(now.Add(Leeway)) {
		return fmt.Errorf("the %s has an iat of %s, which is in the future", what,
			time.Unix(iat, 0).UTC().Format(time.RFC3339))
	}
	if exp != 0 && !time.Unix(exp, 0).After(now.Add(-Leeway)) {
		return fmt.Errorf("the %s expired at %s", what,
			time.Unix(exp, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// ValidateTrustMarksClaim applies §3.1.2's syntactic rule to a `trust_marks`
// array.
//
// This is the check §10.2 calls out as separate from trust evaluation: each
// element's `trust_mark_type` member must equal the `trust_mark_type` claim
// inside the JWT it carries. Nothing here verifies a signature or consults a
// Trust Anchor.
//
// Why it matters on its own: a reader that indexes marks by the OUTER member and
// acts on the INNER claim -- or the reverse -- can be handed a mark that
// advertises itself as one type and asserts another. The rule closes that by
// making the two representations agree before anybody reads either.
func ValidateTrustMarksClaim(entries []TrustMarkEntry) error {
	for i, e := range entries {
		if e.Type == "" {
			return fmt.Errorf("trust_marks[%d] has no trust_mark_type member "+
				"(section 3.1.2 makes it REQUIRED)", i)
		}
		if e.JWT == "" {
			return fmt.Errorf("trust_marks[%d] has no trust_mark member "+
				"(section 3.1.2 makes it REQUIRED)", i)
		}
		// Parsed, NOT verified. This is a syntax check by construction, and doing
		// it without keys is what makes it usable at the point a statement is
		// read rather than at the point trust is established.
		inner, err := ParseTrustMarkUnverified(e.JWT)
		if err != nil {
			return fmt.Errorf("trust_marks[%d]: %w", i, err)
		}
		if inner.Type != e.Type {
			return fmt.Errorf("trust_marks[%d] declares type %q and the Trust Mark "+
				"it carries claims %q (section 3.1.2 requires them to match)",
				i, e.Type, inner.Type)
		}
	}
	return nil
}

// ParseTrustMarkUnverified reads a Trust Mark's claims WITHOUT checking its
// signature.
//
// Named at this length because that is what it is. There are two honest uses:
// the syntactic check above, and the status endpoint, which must read `sub` and
// `trust_mark_type` out of a stranger's submission before it can look up
// whether it ever issued such a thing. Anything that acts on the CONTENT of a
// mark must go through ValidateTrustMark.
func ParseTrustMarkUnverified(raw string) (*TrustMark, error) {
	tok, err := parseTrustMarkJWS(raw)
	if err != nil {
		return nil, err
	}
	if err := requireTyp(tok, TrustMarkTyp); err != nil {
		return nil, err
	}
	return parseTrustMarkClaims(tok.UnsafePayloadWithoutVerification())
}

func parseTrustMarkClaims(payload []byte) (*TrustMark, error) {
	var tm TrustMark
	if err := json.Unmarshal(payload, &tm); err != nil {
		return nil, fmt.Errorf("the Trust Mark's claims did not parse: %w", err)
	}
	if err := rejectLegacyID(payload, "Trust Mark"); err != nil {
		return nil, err
	}
	if tm.Issuer == "" || tm.Subject == "" || tm.Type == "" || tm.IssuedAt == 0 {
		return nil, fmt.Errorf("a Trust Mark requires iss, sub, trust_mark_type " +
			"and iat (section 7.1)")
	}
	return &tm, nil
}

// rejectLegacyID refuses a document carrying the pre-Final `id` claim.
//
// Drafts of this specification named the type identifier `id`; the Final version
// names it `trust_mark_type`. A document carrying `id` was written against a
// different specification, and one carrying BOTH means two things at once --
// which is worse, because a reader that prefers one member and a reader that
// prefers the other disagree about what was asserted while both believe they
// validated it.
//
// Refusing is a compatibility break with draft-era issuers, deliberately: the
// alternative is accepting `id` as a fallback, which quietly makes this server
// the reader that prefers the wrong member.
func rejectLegacyID(payload []byte, what string) error {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil // Already reported by the caller's own unmarshal.
	}
	if len(probe.ID) > 0 {
		return fmt.Errorf("this %s carries an `id` claim; drafts of OpenID "+
			"Federation named the type identifier `id` and the Final specification "+
			"names it `trust_mark_type`, so a document carrying `id` was written "+
			"against a different specification (section 7.1)", what)
	}
	return nil
}

// trustMarkAlgorithms is the signature allow-list.
//
// Asymmetric only, and `none` absent by construction. §7 requires the signing
// key to be one of the issuer's Federation Entity Keys, which are published; a
// symmetric algorithm over a published key would let any holder re-sign.
var trustMarkAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

func parseTrustMarkJWS(raw string) (*jose.JSONWebSignature, error) {
	if raw == "" {
		return nil, fmt.Errorf("the Trust Mark is empty")
	}
	tok, err := jose.ParseSigned(raw, trustMarkAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("this did not parse as a signed JWT with an "+
			"acceptable algorithm: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one signature, got %d",
			len(tok.Signatures))
	}
	h := tok.Signatures[0].Header
	// Key material carried by the document itself, refused for the same reason
	// it is refused on every other inbound JWT in this engine: a token that
	// supplies the key that verifies it verifies nothing.
	if h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil ||
		h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return nil, fmt.Errorf("the document carries its own key material in its " +
			"header, which would make its signature self-referential")
	}
	// §7: "Trust Mark JWTs MUST include the kid (Key ID) header parameter".
	if h.KeyID == "" {
		return nil, fmt.Errorf("there is no kid header, which section 7 requires")
	}
	return tok, nil
}

// requireTyp applies the explicit-typing MUST.
//
// §7: "Trust Marks without a typ header parameter or an unrecognized typ value
// MUST be rejected." An exact, case-sensitive comparison: media types are
// case-insensitive in general, and accepting `Trust-Mark+JWT` here would mean
// two spellings of the same document, which is the ambiguity explicit typing
// exists to remove.
func requireTyp(tok *jose.JSONWebSignature, want string) error {
	typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if typ == "" {
		return fmt.Errorf("there is no typ header; %q is required (section 3.11 of "+
			"RFC 8725, and this specification makes it a MUST)", want)
	}
	if typ != want {
		return fmt.Errorf("the typ header is %q, and %q is required", typ, want)
	}
	return nil
}

// verifyAgainstJWKS checks a signature against a JWK Set, by kid.
func verifyAgainstJWKS(tok *jose.JSONWebSignature, raw string, rawJWKS json.RawMessage) ([]byte, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rawJWKS, &set); err != nil {
		return nil, fmt.Errorf("the key set did not parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("the key set is empty")
	}
	kid := tok.Signatures[0].Header.KeyID
	for _, k := range set.Keys {
		if k.KeyID != kid {
			continue
		}
		// A private key in a published set is a configuration error somewhere
		// upstream, and verifying against it would succeed. Refused so the
		// mistake surfaces here rather than being silently tolerated.
		if !k.IsPublic() {
			return nil, fmt.Errorf("the key with kid %q carries private material "+
				"and must not appear in a published key set", kid)
		}
		payload, err := tok.Verify(k)
		if err != nil {
			return nil, fmt.Errorf("the signature did not verify against key %q: %w",
				kid, err)
		}
		return payload, nil
	}
	return nil, fmt.Errorf("no key with kid %q in the key set", kid)
}
