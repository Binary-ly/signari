package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
)

// The token verifier is the single most security-critical function in the engine:
// everything downstream trusts whatever it returns. Each test here is a published
// attack against JWT verifiers, not a hypothetical.
//
// No database and no server -- keys are generated in memory, so these run in
// milliseconds and can be exhaustive.

func testSet(t *testing.T) (*keys.Set, keys.Key) {
	t.Helper()
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, err := keys.WithState(k, keys.StateActive)
	if err != nil {
		t.Fatal(err)
	}
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	return set, active
}

const testIssuer = "https://id.example.test"

func validClaims() AccessTokenClaims {
	now := time.Now()
	return AccessTokenClaims{
		Issuer:    testIssuer,
		Subject:   "11111111-1111-1111-1111-111111111111",
		Audience:  []string{"webapp"},
		Expiry:    now.Add(5 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		JTI:       "jti-1",
		ClientID:  "webapp",
		Scope:     "openid email",
		SessionID: "sid-1",
	}
}

// forge builds a JWT from an arbitrary header and payload with an attacker-chosen
// signature. This is what an attacker actually sends, and it is the only way to
// test header-level defences -- a legitimate signer will never produce these.
func forge(t *testing.T, header map[string]any, payload any, sig string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload) + "." + sig
}

func TestValidTokenRoundTrips(t *testing.T) {
	set, key := testSet(t)
	raw, err := NewSigner(key).SignJSON(validClaims(), TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyAccessToken(set, testIssuer, raw)
	if err != nil {
		t.Fatalf("a token we just signed was rejected: %v", err)
	}
	if claims.Subject != "11111111-1111-1111-1111-111111111111" || claims.ClientID != "webapp" {
		t.Errorf("claims came back wrong: %+v", claims)
	}
}

// THE canonical JWT attack: strip the signature and set alg to "none". A verifier
// that honours the header's algorithm choice accepts a token anyone can mint.
func TestAlgNoneIsRejected(t *testing.T) {
	set, key := testSet(t)
	for _, alg := range []string{"none", "None", "NONE"} {
		raw := forge(t, map[string]any{"alg": alg, "typ": TypAccessToken, "kid": key.KID()},
			validClaims(), "")
		if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
			t.Fatalf("alg=%q was ACCEPTED -- anyone can now mint tokens", alg)
		}
	}
}

// Algorithm confusion: claim an algorithm the key is not. Verifiers that pick the
// algorithm from the header rather than from the key can be tricked into
// verifying an RSA public key as an HMAC secret.
func TestAlgConfusionIsRejected(t *testing.T) {
	set, key := testSet(t) // an ES256 key
	for _, alg := range []string{"HS256", "RS256", "PS256", "EdDSA"} {
		raw := forge(t, map[string]any{"alg": alg, "typ": TypAccessToken, "kid": key.KID()},
			validClaims(), "AAAA")
		_, err := VerifyAccessToken(set, testIssuer, raw)
		if err == nil {
			t.Fatalf("alg=%q against an ES256 key was ACCEPTED", alg)
		}
	}
}

// A token must not be allowed to nominate the key that verifies it. jku and x5u
// point at attacker-controlled URLs; an embedded jwk ships the key inline. Any of
// them turns "verify this signature" into "trust whatever the token says".
func TestSelfDescribedKeyMaterialIsRejected(t *testing.T) {
	set, key := testSet(t)

	// A REAL, structurally valid key belonging to the attacker -- not a malformed
	// stub. A stub gets rejected by the JOSE parser before our check runs, which
	// would make this test pass for the wrong reason and hide a regression in the
	// defence it is supposed to cover.
	attacker, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	attackerJWK, err := json.Marshal(attacker.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	var attackerKey map[string]any
	if err := json.Unmarshal(attackerJWK, &attackerKey); err != nil {
		t.Fatal(err)
	}

	for _, h := range []string{"jku", "x5u", "jwk"} {
		header := map[string]any{"alg": "ES256", "typ": TypAccessToken, "kid": key.KID()}
		if h == "jwk" {
			header[h] = attackerKey
		} else {
			header[h] = "https://attacker.test/keys.json"
		}
		raw := forge(t, header, validClaims(), "AAAA")
		_, err := VerifyAccessToken(set, testIssuer, raw)
		if err == nil {
			t.Fatalf("header %q was ACCEPTED -- the token chose its own key", h)
		}
		if !strings.Contains(err.Error(), "key material") {
			t.Errorf("header %q rejected for the wrong reason: %v", h, err)
		}
	}
}

// Cross-token-type confusion. An ID token is handed to the client; if it also
// passes as an access token, every client can call the API as its own user with a
// token it was legitimately given.
func TestIDTokenIsNotAcceptedAsAnAccessToken(t *testing.T) {
	set, key := testSet(t)
	idt, err := NewSigner(key).SignIDToken(IDTokenClaims{
		Issuer: testIssuer, Subject: "u1", Audience: "webapp",
		Expiry: time.Now().Add(5 * time.Minute).Unix(), IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAccessToken(set, testIssuer, idt)
	if err == nil {
		t.Fatal("an ID token was accepted as an access token")
	}
	if !strings.Contains(err.Error(), "typ") {
		t.Errorf("rejected, but not for typ confusion: %v", err)
	}
}

// A signature from a key we do not publish must not verify, however well-formed.
func TestForeignKeyIsRejected(t *testing.T) {
	set, _ := testSet(t)

	other, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	otherActive, _ := keys.WithState(other, keys.StateActive)
	raw, err := NewSigner(otherActive).SignJSON(validClaims(), TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
		t.Fatal("a token signed by an unpublished key was accepted")
	}
}

// Changing a single claim must invalidate the signature. Verified explicitly
// because "the signature was checked" and "the signature was checked over THESE
// bytes" are different properties.
func TestTamperedPayloadIsRejected(t *testing.T) {
	set, key := testSet(t)
	raw, err := NewSigner(key).SignJSON(validClaims(), TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")

	var claims map[string]any
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(body, &claims)
	claims["sub"] = "22222222-2222-2222-2222-222222222222" // become another user
	swapped, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(swapped)

	if _, err := VerifyAccessToken(set, testIssuer, strings.Join(parts, ".")); err == nil {
		t.Fatal("a token with a rewritten subject was accepted")
	}
}

// A token from another issuer must not be accepted here, even when correctly
// signed by a key we happen to trust. This is the mix-up defence.
func TestWrongIssuerIsRejected(t *testing.T) {
	set, key := testSet(t)
	c := validClaims()
	c.Issuer = "https://evil.test"
	raw, _ := NewSigner(key).SignJSON(c, TypAccessToken)

	if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
		t.Fatal("a token from a different issuer was accepted")
	}
}

func TestExpiryIsEnforcedWithBoundedLeeway(t *testing.T) {
	set, key := testSet(t)

	// Well past expiry: must fail.
	c := validClaims()
	c.Expiry = time.Now().Add(-10 * time.Minute).Unix()
	raw, _ := NewSigner(key).SignJSON(c, TypAccessToken)
	if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
		t.Fatal("a token that expired ten minutes ago was accepted")
	}

	// Just inside the leeway: must pass. Clock skew between machines is real, and
	// rejecting a token that expired one second ago by another host's clock is an
	// outage rather than a defence.
	c2 := validClaims()
	c2.Expiry = time.Now().Add(-Leeway / 2).Unix()
	raw2, _ := NewSigner(key).SignJSON(c2, TypAccessToken)
	if _, err := VerifyAccessToken(set, testIssuer, raw2); err != nil {
		t.Errorf("a token inside the %s leeway was rejected: %v", Leeway, err)
	}
}

// Rotation safety: a token signed before the last rotation must keep verifying
// while its key is passive. If it did not, every rotation would sign out every
// user holding a live token.
func TestPassiveKeyStillVerifies(t *testing.T) {
	k, _ := keys.Generate(keys.NewKID(), keys.ES256)
	active, _ := keys.WithState(k, keys.StateActive)

	raw, err := NewSigner(active).SignJSON(validClaims(), TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}

	// The key is demoted, exactly as `signari keys rotate` would demote it.
	passive, _ := keys.WithState(k, keys.StatePassive)
	newActive, _ := keys.Generate(keys.NewKID(), keys.ES256)
	newActive, _ = keys.WithState(newActive, keys.StateActive)
	set, err := keys.NewSet(newActive, passive)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyAccessToken(set, testIssuer, raw); err != nil {
		t.Fatalf("a token signed before rotation stopped verifying: %v", err)
	}
}

// Required claims. Each of these is something a downstream consumer will assume
// is present; absent, it would be a nil dereference or a silent empty string.
func TestRequiredClaimsAreEnforced(t *testing.T) {
	set, key := testSet(t)

	for name, mutate := range map[string]func(*AccessTokenClaims){
		"no subject": func(c *AccessTokenClaims) { c.Subject = "" },
		"no jti":     func(c *AccessTokenClaims) { c.JTI = "" },
	} {
		c := validClaims()
		mutate(&c)
		raw, _ := NewSigner(key).SignJSON(c, TypAccessToken)
		if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Garbage must fail cleanly rather than panic. This function is reachable by
// anyone on the internet with no authentication, so a panic here is a remote
// denial of service.
func TestMalformedInputDoesNotPanic(t *testing.T) {
	set, _ := testSet(t)
	for _, raw := range []string{
		"", ".", "..", "a.b.c", "not-a-jwt",
		strings.Repeat("A", 10000),
		"eyJhbGciOiJFUzI1NiJ9..", "....",
	} {
		if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
			t.Errorf("%.20q was accepted", raw)
		}
	}
}

// RFC 9700 §2.3: "every resource server is obliged to verify, for every
// request, whether the access token sent with that request was meant to be used
// for that particular resource server. If it was not, the resource server MUST
// refuse to serve the respective request."
//
// We are a resource server for our own /userinfo, and we honour RFC 8707
// `resource` when minting -- so a token a client asked us to scope to a
// downstream API must not also open our own endpoint. Verification checked
// signature, typ, iss, sub, exp, iat and jti, and never looked at aud.
func TestAudienceRestrictionIsEnforcedAgainstOurselves(t *testing.T) {
	const issuer = "https://id.example"

	t.Run("the ordinary case still works", func(t *testing.T) {
		// Default mint: audience is the client the token was issued to.
		c := &AccessTokenClaims{ClientID: "app", Audience: []string{"app"}}
		if !AudienceAccepted(c, issuer) {
			t.Fatal("an ordinary OIDC access token was refused at userinfo")
		}
	})

	t.Run("the issuer named as a resource works", func(t *testing.T) {
		c := &AccessTokenClaims{ClientID: "app", Audience: []string{issuer}}
		if !AudienceAccepted(c, issuer) {
			t.Fatal("a token explicitly audienced to this issuer was refused")
		}
	})

	t.Run("a token for a downstream API is refused", func(t *testing.T) {
		// What RFC 8707 produces when the client sends
		// resource=https://api.example.
		c := &AccessTokenClaims{ClientID: "app", Audience: []string{"https://api.example"}}
		if AudienceAccepted(c, issuer) {
			t.Fatal("a token the client asked us to restrict to https://api.example " +
				"was accepted at our own resource endpoint. Whoever holds that " +
				"token -- including a compromised api.example -- could read the " +
				"subject's profile, which is exactly what audience restriction " +
				"exists to prevent (RFC 9700 §4.9.2)")
		}
	})

	t.Run("asking for both works", func(t *testing.T) {
		// RFC 8707 §2 allows multiple resource parameters. A client that wants
		// one token for both asks for both, rather than getting the second
		// because nobody checked.
		c := &AccessTokenClaims{ClientID: "app",
			Audience: []string{"https://api.example", issuer}}
		if !AudienceAccepted(c, issuer) {
			t.Fatal("a token audienced to both the API and this issuer was refused")
		}
	})

	t.Run("no audience is not a wildcard", func(t *testing.T) {
		// RFC 9068 §4 requires aud. A token naming no recipient cannot be shown
		// to have been meant for this one.
		c := &AccessTokenClaims{ClientID: "app"}
		if AudienceAccepted(c, issuer) {
			t.Fatal("a token with no audience was treated as audienced to everyone")
		}
		c.Audience = []string{}
		if AudienceAccepted(c, issuer) {
			t.Fatal("an empty audience was treated as audienced to everyone")
		}
	})
}

// TestOnlyAnIDTokenIsAcceptedAsAnIDTokenHint.
//
// VerifyIDTokenAudience is what reads an `id_token_hint` at the end-session
// endpoint. Its answer decides two things: which client's registered
// post-logout URIs apply, and whether the logout confirmation prompt is skipped
// — OIDC RP-Initiated Logout accepts a verified hint in place of asking the
// person.
//
// It hand-rolled its own copy of the header hardening and that copy had drifted:
// every other verification path in this file checks `typ`, and this one did not.
// So any token this server signs whose claims happen to unmarshal into
// IDTokenClaims was accepted as an ID token.
//
// Access tokens were never usable this way — theirs is `"aud": ["webapp"]`, an
// array, which fails to unmarshal into a string field. Transaction tokens carry
// a STRING `aud`, so they were, and holding one is enough to suppress a logout
// confirmation.
//
// Found by mutation: removing the typ check from the shared verifier broke
// nothing, because the path the tests exercise never used the shared verifier.
func TestOnlyAnIDTokenIsAcceptedAsAnIDTokenHint(t *testing.T) {
	set, key := testSet(t)
	now := time.Now()

	// A properly SIGNED token with a string audience and our issuer, differing
	// from an ID token only in its typ. A forged signature would be rejected
	// before the typ check and would prove nothing.
	type stringAudClaims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
	}
	claims := stringAudClaims{
		Issuer: testIssuer, Subject: "user-1", Audience: "webapp",
		Expiry: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(),
	}

	for _, typ := range []string{"txntoken+jwt", "at+jwt", "pending+jwt", "kb+jwt"} {
		raw, err := NewSigner(key).SignJSON(claims, typ)
		if err != nil {
			t.Fatal(err)
		}
		aud, err := VerifyIDTokenAudience(set, testIssuer, raw)
		if err == nil {
			t.Errorf("a token with typ=%q was accepted as an id_token_hint and "+
				"reported audience %q; it identifies a relying party and can skip "+
				"the logout confirmation", typ, aud)
		}
	}

	// And a genuine ID token still works, so the check above is not simply
	// refusing everything.
	idt, err := NewSigner(key).SignJSON(IDTokenClaims{
		Issuer: testIssuer, Subject: "user-1", Audience: "webapp",
		Expiry: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(),
	}, TypIDToken)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := VerifyIDTokenAudience(set, testIssuer, idt)
	if err != nil {
		t.Fatalf("a genuine ID token was refused as an id_token_hint: %v", err)
	}
	if aud != "webapp" {
		t.Errorf("audience = %q, want webapp", aud)
	}
}

// TestAlgConfusionWithARealSignatureIsRejected.
//
// TestAlgConfusionIsRejected above forges tokens with the signature "AAAA" --
// garbage. Every one of them is refused, but by the LAST check rather than the
// one under test: whichever header defence you delete, the token still fails at
// `tok.Verify`. Deleting the algorithm allow-list broke no test.
//
// This is the actual attack. An ES256 verifier that takes the algorithm from the
// HEADER rather than from the key can be handed a token signed HS256, using the
// verifier's own PUBLIC key as the HMAC secret -- which the attacker has, because
// it is published at /oauth2/jwks. The signature is genuinely valid for the
// algorithm claimed, so nothing downstream saves you.
//
// Written after mutation showed the existing test could not distinguish "refused
// because the algorithm is not permitted" from "refused because the signature is
// nonsense".
func TestAlgConfusionWithARealSignatureIsRejected(t *testing.T) {
	set, key := testSet(t)

	// The attacker's material: the public key, exactly as we publish it.
	pubJWK, err := json.Marshal(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}

	header := map[string]any{"alg": "HS256", "typ": TypAccessToken, "kid": key.KID()}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(validClaims())
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)

	// A CORRECT HMAC over the signing input, keyed with the published public key.
	mac := hmac.New(sha256.New, pubJWK)
	mac.Write([]byte(signingInput))
	raw := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if _, err := VerifyAccessToken(set, testIssuer, raw); err == nil {
		t.Fatal("a token signed HS256 with our own published public key as the HMAC " +
			"secret was ACCEPTED; anyone who can read /oauth2/jwks can mint tokens")
	}

	// And the refusal must come from the algorithm being impermissible, not from
	// the signature happening not to verify -- otherwise this test would pass
	// again the moment somebody widened the allow-list.
	_, err = VerifyAccessToken(set, testIssuer, raw)
	if strings.Contains(err.Error(), "signature does not verify") {
		t.Errorf("refused only at signature verification (%v); the algorithm should "+
			"have been refused before any key was consulted", err)
	}
}

// TestAtHashAndCHashAgainstIndependentlyComputedVectors.
//
// OIDC Core §3.3.2.11: at_hash is "the base64url encoding of the left-most half
// of the hash of the octets of the ASCII representation of the access_token
// value" — "if the alg is RS256, hash the access_token value with SHA-256, then
// take the left-most 128 bits and base64url-encode them". c_hash is the same
// construction over the authorization code.
//
// These two claims are what bind an ID token to the access token and the code
// issued with it. A relying party that validates them rejects our tokens
// outright if we compute them wrongly, so the value is interoperability-critical
// — and it had NO test. Mutation proved it: hashing the wrong thing, taking the
// whole hash instead of half, and returning a fixed string for EdDSA all passed
// the suite.
//
// The expected values are the ones in the specification's own ID Token examples,
// and they are used here having been recomputed independently with openssl
// rather than read off the page:
//
//	printf '%s' "$TOKEN" | openssl dgst -sha256 -binary \
//	  | head -c 16 | base64 | tr '+/' '-_' | tr -d '='
//
// That matters more than convenience. Every other test here is written from the
// same reading of the specification that produced the implementation, so it
// agrees with the code by construction. A value produced by a different tool, on
// a different code path, is the one kind of check that cannot.
func TestAtHashAndCHashAgainstIndependentlyComputedVectors(t *testing.T) {
	const (
		accessToken  = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
		wantAtHash   = "77QmUPtjPfzWtF2AnpK9RQ"
		code         = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
		wantCodeHash = "LDktKdoQak3Pk0cnXxCltA"
	)

	for _, alg := range []keys.Algorithm{keys.ES256, keys.RS256, keys.PS256} {
		got, err := AtHash(alg, accessToken)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if got != wantAtHash {
			t.Errorf("%s: at_hash = %q, want %q -- a relying party validating this "+
				"claim will refuse every ID token we issue", alg, got, wantAtHash)
		}
		got, err = CHash(alg, code)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if got != wantCodeHash {
			t.Errorf("%s: c_hash = %q, want %q", alg, got, wantCodeHash)
		}
	}

	// 128 bits, base64url, no padding: 22 characters. Asserted separately so a
	// change that produced a well-formed value of the wrong LENGTH — the whole
	// hash rather than half of it — is named as that rather than as a mismatch.
	if n := len(wantAtHash); n != 22 {
		t.Fatalf("the vector itself is %d characters, not 22; the test is wrong", n)
	}

	// A second vector, chosen because its encoding DISTINGUISHES the two base64
	// alphabets. The specification's example above does not: its hash happens to
	// contain no byte that encodes to `+` or `/`, so standard and URL-safe
	// base64 produce the same 22 characters and swapping the encoder breaks
	// nothing. This one differs in the twelfth character.
	//
	//	printf '%s' "tok-4" | openssl dgst -sha256 -binary | head -c 16 | base64
	//	  -> mm5z0CjQGPltZ/GoEUxk1Q     (standard)
	//	  -> mm5z0CjQGPltZ_GoEUxk1Q     (URL-safe, which is what §3.3.2.11 wants)
	//
	// A relying party decoding with the URL-safe alphabet gets different bytes
	// from a `/`, so the comparison fails and the ID token is refused.
	if got, err := AtHash(keys.ES256, "tok-4"); err != nil {
		t.Fatal(err)
	} else if got != "mm5z0CjQGPltZ_GoEUxk1Q" {
		t.Errorf("at_hash = %q, want mm5z0CjQGPltZ_GoEUxk1Q -- base64url, not "+
			"standard base64", got)
	}

	// EdDSA has no paired hash in the JOSE registry, so the claim is omitted
	// rather than guessed. An empty string here means "do not set at_hash"; a
	// non-empty one would be a value no relying party could verify.
	if got, err := AtHash(keys.EdDSA, accessToken); err != nil || got != "" {
		t.Errorf("EdDSA at_hash = %q, err = %v; it must be omitted, because there "+
			"is no hash paired with Ed25519 and inventing one produces a claim that "+
			"fails validation everywhere", got, err)
	}
}

// OIDC Core 1.0 §2: iss, sub, aud, exp and iat are REQUIRED in an ID Token.
//
// Enforced at the point of MINTING, which is the only place it can be enforced
// -- we are the issuer, so nothing downstream will catch a malformed one before
// a relying party does. Both guards survived mutation against the whole test
// suite: SignIDToken would emit a token with no `sub`, or no `exp`, and no test
// anywhere noticed.
//
// A regression here does not fail loudly on our side. It ships tokens that every
// conformant relying party rejects, and the report comes back as "login stopped
// working" from somebody else's logs.
func TestAnIDTokenCannotBeMintedWithoutItsRequiredClaims(t *testing.T) {
	_, k := testSet(t)
	now := time.Now()

	full := func() IDTokenClaims {
		return IDTokenClaims{
			Issuer:   "https://idp.example",
			Subject:  "user-1",
			Audience: "client-1",
			Expiry:   now.Add(time.Hour).Unix(),
			IssuedAt: now.Unix(),
		}
	}

	// The positive case first: the fixture must actually be mintable, or every
	// assertion below would pass for the wrong reason.
	if _, err := NewSigner(k).SignIDToken(full()); err != nil {
		t.Fatalf("a complete ID token was refused, so this test proves nothing: %v", err)
	}

	for name, break_ := range map[string]func(*IDTokenClaims){
		"no iss": func(c *IDTokenClaims) { c.Issuer = "" },
		"no sub": func(c *IDTokenClaims) { c.Subject = "" },
		"no aud": func(c *IDTokenClaims) { c.Audience = "" },
		"no exp": func(c *IDTokenClaims) { c.Expiry = 0 },
		"no iat": func(c *IDTokenClaims) { c.IssuedAt = 0 },
	} {
		c := full()
		break_(&c)
		if _, err := NewSigner(k).SignIDToken(c); err == nil {
			t.Errorf("%s: an ID token was minted without a claim OIDC Core §2 makes "+
				"REQUIRED; conformant relying parties will reject it and the failure "+
				"will surface in their logs, not ours", name)
		}
	}
}
