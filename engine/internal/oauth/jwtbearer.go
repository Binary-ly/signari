package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RFC 7523 §2.1: a JWT issued by a trusted party, presented as an authorization
// grant and exchanged for an access token.
//
// # What this is for in 2026
//
// It is the mechanism underneath workload identity federation. A CI job, a
// Kubernetes pod or a cloud service account holds a short-lived JWT signed by its
// platform, and trades it here for our token -- so nothing has to store a
// long-lived client secret. That is the reason this grant is worth having and the
// reason it is dangerous: it converts "can obtain a JWT from that platform" into
// "can act as this account here".
//
// # The failure modes, from a competitor's 2026 CVEs rather than from imagination
//
// The most deployed implementation of this grant shipped three vulnerabilities in
// 2026, all in the same feature, and each one is a rule below:
//
//   - Trust that had been withdrawn still worked: the issuer lookup did not
//     filter providers an administrator had disabled, so decommissioning a
//     provider did not decommission it (a published advisory, and the lookup this file
//     hands off to is the answer).
//   - A disabled user could still be impersonated, because the grant resolved the
//     account without checking whether it was still allowed to sign in
//     (a published advisory).
//   - Signature verification could be bypassed by algorithm confusion, which let
//     anyone with client credentials impersonate any federated user of that
//     provider (a published advisory, CVSS 8.1).
//
// None of the three is a subtle protocol point. All three are checks that a
// reasonable reading of the RFC does not require you to write down, which is
// exactly why they are written down here.
const GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// MaxAssertionLifetime bounds how far ahead an assertion's `exp` may sit.
//
// RFC 7523 §3 item 4 makes this a MUST -- "The authorization server MUST reject
// JWTs with an `exp` claim value that is unreasonably far in the future" -- and
// then declines to say what unreasonable means, because it depends on the
// deployment.
//
// One hour is the largest value any major platform actually needs: Google caps a
// service-account assertion at an hour, and CI-issued workload tokens are minutes.
// It is picked as a ceiling on the blast radius of a leaked assertion, not as a
// guess at what issuers do -- an assertion valid for a year is a bearer credential
// valid for a year, whatever the issuer intended.
const MaxAssertionLifetime = time.Hour

// AssertionSkew is the clock tolerance for `nbf` and `iat`.
//
// Deliberately the same small value used elsewhere in this engine. Generous skew
// on an assertion extends the life of one that should have expired.
const AssertionSkew = 60 * time.Second

// Audience decodes RFC 7519 §4.1.3's two spellings: "In the general case, the
// "aud" value is an array of case-sensitive strings... In the special case when
// the JWT has one audience, the "aud" value MAY be a single case-sensitive
// string."
//
// Parsed as []string alone, the string form does not fail the audience check --
// the whole claim set fails to unmarshal, and the caller reports a malformed
// assertion with nothing pointing at the audience.
//
// NOTE, and it is a real one: this is the THIRD implementation of that rule in
// this engine. `ssf.audience` does it as an unexported type with the same
// array-first ordering, and `federation.audienceContains` does it against a
// json.RawMessage without a type at all. Three copies of a parsing rule is two
// copies that can drift, and this package cannot import either without a
// dependency it should not have. Converging them belongs in its own change, with
// its own tests, rather than smuggled into a new grant.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	// Array first: it is the general case, so the common path does not pay for a
	// failed decode.
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*a = list
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return fmt.Errorf("aud is neither a string nor an array of strings")
	}
	*a = Audience{one}
	return nil
}

// AssertionClaims is the part of RFC 7523 §3 this server validates.
type AssertionClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
}

// ValidateAssertionClaims applies RFC 7523 §3 to a signature-verified assertion.
//
// The signature is NOT checked here: that needs the provider's key set and
// belongs with the code that can reach it. What this function owns is every claim
// rule, so they live in one readable place and can be tested without a network or
// a database.
//
// `audiences` is this deployment's issuer plus any registered aliases -- the same
// set the rest of the engine accepts as naming us.
func ValidateAssertionClaims(c AssertionClaims, audiences []string, now time.Time) *TokenError {
	// §3 item 1. The issuer is what selects the trusted provider, so an absent
	// one has nothing to select and must not fall through to a default.
	if c.Issuer == "" {
		return tokenErr("invalid_grant", "the assertion has no iss claim")
	}
	// §3 item 2.
	if c.Subject == "" {
		return tokenErr("invalid_grant", "the assertion has no sub claim")
	}

	// §3 item 3 and §3.1: "The authorization server MUST reject any JWT that does
	// not contain its own identity as the intended audience."
	//
	// This is the check that stops an assertion minted for a DIFFERENT relying
	// party being replayed at us. Without it, any service that receives assertions
	// from the same issuer can forward one here and act as its subject -- and the
	// issuer, having done nothing wrong, cannot tell.
	if len(c.Audience) == 0 {
		return tokenErr("invalid_grant", "the assertion has no aud claim")
	}
	if !audienceNamesUs(c.Audience, audiences) {
		return tokenErr("invalid_grant",
			"the assertion's audience does not name this issuer, so it was not issued for us")
	}
	// Exactly one audience, which is STRICTER than the specification.
	//
	// RFC 7519 §4.1.3 allows an array, and RFC 7523 §3 asks only that one value
	// identify us -- so an assertion naming several parties is conformant and an
	// earlier version of this function accepted it.
	//
	// It is refused because of what the other names can do. If an issuer mints
	// `aud: ["https://us", "https://partner"]`, that assertion is a valid
	// credential at BOTH, and the partner can present it here and act as its
	// subject. Replay protection does not help: the partner spending it at their
	// own endpoint leaves no trace in our table, so ours is still the first use we
	// have seen. It is the confused-deputy version of the exact attack the
	// audience check exists to stop.
	//
	// The most deployed implementation of this grant reached the same conclusion
	// and passes `multipleAudienceAllowed = false` for it, while allowing multiple
	// elsewhere. Matching that, and saying why, beats being conformant and
	// exploitable.
	if len(c.Audience) > 1 {
		return tokenErr("invalid_grant",
			"the assertion names more than one audience; an assertion addressed to "+
				"several parties can be replayed here by any of them")
	}

	// §3 item 4. Required, and bounded in both directions.
	if c.Expiry == 0 {
		return tokenErr("invalid_grant", "the assertion has no exp claim")
	}
	exp := time.Unix(c.Expiry, 0)
	if now.After(exp.Add(AssertionSkew)) {
		return tokenErr("invalid_grant", "the assertion has expired")
	}
	if exp.After(now.Add(MaxAssertionLifetime)) {
		return tokenErr("invalid_grant", fmt.Sprintf(
			"the assertion expires more than %s from now; an assertion valid that long "+
				"is a long-lived bearer credential", MaxAssertionLifetime))
	}

	// §3 item 5: nbf is a MAY, and when present "identifies the time before which
	// the token MUST NOT be accepted".
	if c.NotBefore != 0 && time.Unix(c.NotBefore, 0).After(now.Add(AssertionSkew)) {
		return tokenErr("invalid_grant", "the assertion is not valid yet")
	}
	// §3 item 6: iat is a MAY. Checked only when present, because requiring it
	// would refuse conformant assertions -- but an iat in the future is a clock
	// problem or a forgery, and either way the exp derived from it is not to be
	// trusted.
	if c.IssuedAt != 0 {
		iat := time.Unix(c.IssuedAt, 0)
		if iat.After(now.Add(AssertionSkew)) {
			return tokenErr("invalid_grant", "the assertion says it was issued in the future")
		}
		// And an upper bound on AGE, not just on remaining life.
		//
		// The exp ceiling above bounds how far into the future an assertion may
		// reach. It says nothing about how long one may sit around before being
		// spent: an assertion issued ninety minutes ago whose exp is five minutes
		// away passes it, because only five minutes remain.
		//
		// That is the leaked-assertion case. Something that has been in a log, a
		// crash report or a proxy trace for an hour should not still mint tokens
		// merely because its issuer refreshed the window. Bounding from `iat`
		// closes it, and this check was taken from reading a competitor's
		// implementation, which does exactly this and which ours did not.
		if now.After(iat.Add(MaxAssertionLifetime)) {
			return tokenErr("invalid_grant", fmt.Sprintf(
				"the assertion was issued more than %s ago; an assertion must be "+
					"used near the time it was minted, not merely before it expires",
				MaxAssertionLifetime))
		}
	}

	// §3 item 7 makes `jti` a MAY, and this REQUIRES it.
	//
	// The first version accepted an assertion without one and simply skipped
	// replay protection -- documented as a known limit. That is the defect this
	// review keeps finding in other people's code: a protection the documentation
	// claims, silently absent for some inputs, with nothing to tell the operator
	// which issuers are unprotected.
	//
	// Failing closed is the only version of "replay protected" that is true. Every
	// issuer this grant is for -- GitHub Actions, Kubernetes, cloud service
	// accounts -- emits `jti`, so the practical cost is nil, and an issuer that
	// does not gets a specific error rather than silent exposure.
	if c.JTI == "" {
		return tokenErr("invalid_grant",
			"the assertion has no jti claim; it is required here so that a replayed "+
				"assertion can be detected")
	}

	return nil
}

// audienceNamesUs reports whether any audience value identifies this deployment.
func audienceNamesUs(aud Audience, ours []string) bool {
	for _, a := range aud {
		for _, o := range ours {
			// The empty string is never an identity. Without this guard a
			// deployment with an unset alias would accept an assertion carrying
			// an empty `aud` entry, which is the audience check disabling itself
			// on a configuration mistake.
			if o != "" && a == o {
				return true
			}
		}
	}
	return false
}

// PeekAssertionIssuer reads `iss` from an UNVERIFIED assertion.
//
// # Read the name of this function before using it
//
// Nothing it returns has been authenticated. It exists for exactly one purpose:
// an assertion's issuer is what selects the key that verifies the assertion, so
// the issuer has to be read before verification is possible. That is a chicken
// and egg the protocol builds in, not a shortcut.
//
// The value is therefore safe to use as a LOOKUP KEY -- to find a trust anchor,
// which then either verifies the signature or does not -- and safe for nothing
// else. Every claim that decides anything, including the issuer itself, must be
// re-read from the verified payload.
func PeekAssertionIssuer(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("an assertion must be a three-part compact JWS")
	}
	// RawURLEncoding: JWS uses base64url with no padding (RFC 7515 §2). Decoding
	// with padding tolerated would accept tokens a conformant parser rejects,
	// and this is the first thing that touches attacker input.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("the assertion's payload is not base64url")
	}
	// Bounded before unmarshalling. This runs before anything has been
	// authenticated, so the input size is entirely the caller's choice.
	if len(raw) > maxAssertionPayload {
		return "", fmt.Errorf("the assertion's payload is implausibly large")
	}
	var probe struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("the assertion's payload is not JSON")
	}
	if probe.Issuer == "" {
		return "", fmt.Errorf("the assertion names no issuer")
	}
	return probe.Issuer, nil
}

// maxAssertionPayload bounds an unauthenticated claim set. Generous enough for
// any real assertion -- they carry a handful of claims -- and small enough that
// the JSON parser is never handed a megabyte by an anonymous caller.
const maxAssertionPayload = 64 << 10
