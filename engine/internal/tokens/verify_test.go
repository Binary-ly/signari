package tokens

import (
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
