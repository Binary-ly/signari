package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	testMethod = "GET"
	testURI    = "https://auth.example.com/oauth2/userinfo"
)

type clientKey struct {
	priv *ecdsa.PrivateKey
	jwk  jose.JSONWebKey
}

func newClientKey(t *testing.T) *clientKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &clientKey{priv: k, jwk: jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"}}
}

func (c *clientKey) thumbprint(t *testing.T) string {
	t.Helper()
	th, err := c.jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(th)
}

// sign builds a proof. Every field is a parameter so a test can make exactly
// one of them wrong.
func (c *clientKey) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).
		WithHeader(jose.HeaderType, typ).
		WithHeader("jwk", c.jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: c.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func goodClaims() map[string]any {
	return map[string]any{
		"jti": "proof-1", "htm": testMethod, "htu": testURI,
		"iat": time.Now().Unix(),
	}
}

func TestValidProofIsAccepted(t *testing.T) {
	k := newClientKey(t)
	p, err := Verify(k.sign(t, TypDPoP, goodClaims()), testMethod, testURI, "", time.Now())
	if err != nil {
		t.Fatalf("a valid proof was refused: %v", err)
	}
	if p.JKT != k.thumbprint(t) {
		t.Errorf("JKT = %q, want the key's thumbprint", p.JKT)
	}
	if p.JTI != "proof-1" {
		t.Errorf("JTI = %q", p.JTI)
	}
}

// TestProofAttacks. Every entry is a proof that must not be accepted. Any one
// accepted makes the binding decorative.
func TestProofAttacks(t *testing.T) {
	k := newClientKey(t)
	now := time.Now()

	cases := []struct {
		name   string
		proof  func() string
		method string
		uri    string
		token  string
		why    string
	}{
		{
			name:  "wrong typ (a JWT minted for another purpose)",
			proof: func() string { return k.sign(t, "JWT", goodClaims()) },
			why:   "an ID token or access token would otherwise be usable as a proof",
		},
		{
			name:   "method the proof did not authorise",
			proof:  func() string { return k.sign(t, TypDPoP, goodClaims()) },
			method: "POST",
			why:    "a proof for a read would authorise a write",
		},
		{
			name:  "different endpoint",
			proof: func() string { return k.sign(t, TypDPoP, goodClaims()) },
			uri:   "https://auth.example.com/admin/users",
			why:   "a proof for /userinfo would authorise /admin",
		},
		{
			name:  "different host, same path",
			proof: func() string { return k.sign(t, TypDPoP, goodClaims()) },
			uri:   "https://evil.test/oauth2/userinfo",
			why:   "a proof captured by one server would authorise a request to another",
		},
		{
			name: "no jti",
			proof: func() string {
				c := goodClaims()
				delete(c, "jti")
				return k.sign(t, TypDPoP, c)
			},
			why: "without a jti a replay cannot be detected at all",
		},
		{
			name: "stale",
			proof: func() string {
				c := goodClaims()
				c["iat"] = now.Add(-10 * time.Minute).Unix()
				return k.sign(t, TypDPoP, c)
			},
			why: "a proof captured earlier would still work",
		},
		{
			name: "timestamped far in the future",
			proof: func() string {
				c := goodClaims()
				c["iat"] = now.Add(10 * time.Minute).Unix()
				return k.sign(t, TypDPoP, c)
			},
			why: "a client could mint proofs valid long after capture",
		},
		{
			name: "no iat",
			proof: func() string {
				c := goodClaims()
				delete(c, "iat")
				return k.sign(t, TypDPoP, c)
			},
			why: "age cannot be checked, so no proof ever expires",
		},
		{
			name:  "access token present but no ath",
			proof: func() string { return k.sign(t, TypDPoP, goodClaims()) },
			token: "the-access-token",
			why:   "the proof would not be bound to the token it accompanies",
		},
		{
			name: "ath for a different access token",
			proof: func() string {
				c := goodClaims()
				c["ath"] = AccessTokenHash("some-other-token")
				return k.sign(t, TypDPoP, c)
			},
			token: "the-access-token",
			why:   "a proof made while using one token would authorise another",
		},
		{
			name:  "not a JWT",
			proof: func() string { return "not-a-proof" },
			why:   "malformed input must not reach the claim checks",
		},
		{
			name:  "two proofs in one header",
			proof: func() string { return k.sign(t, TypDPoP, goodClaims()) + "," + k.sign(t, TypDPoP, goodClaims()) },
			why:   "which one was checked would be up to the parser",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			method, uri := c.method, c.uri
			if method == "" {
				method = testMethod
			}
			if uri == "" {
				uri = testURI
			}
			if _, err := Verify(c.proof(), method, uri, c.token, now); err == nil {
				t.Fatalf("ACCEPTED: %s -- %s", c.name, c.why)
			}
		})
	}
}

// TestUnsignedProofIsRefused. `alg: none` is the first thing anybody tries.
func TestUnsignedProofIsRefused(t *testing.T) {
	k := newClientKey(t)
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": TypDPoP, "jwk": k.jwk})
	body, _ := json.Marshal(goodClaims())
	unsigned := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(body) + "."

	if _, err := Verify(unsigned, testMethod, testURI, "", time.Now()); err == nil {
		t.Fatal("an UNSIGNED proof was accepted")
	}
}

// TestSymmetricAlgorithmIsRefused.
//
// The proof carries its own verification key. With HMAC that key is also the
// signing key, so anybody could mint a proof for any key: the signature would
// verify perfectly and demonstrate nothing.
func TestSymmetricAlgorithmIsRefused(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderType, TypDPoP).
			WithHeader("jwk", jose.JSONWebKey{Key: secret}))
	if err != nil {
		t.Skip("the library refused to build a symmetric signer with a jwk header, which " +
			"is itself the right answer")
	}
	payload, _ := json.Marshal(goodClaims())
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Skip("signing refused")
	}
	s, _ := obj.CompactSerialize()
	if _, err := Verify(s, testMethod, testURI, "", time.Now()); err == nil {
		t.Fatal("an HMAC-signed proof was accepted; anybody could mint one for any key")
	}
}

// TestProofSignedByADifferentKeyThanItAdvertises.
func TestProofSignedByADifferentKeyThanItAdvertises(t *testing.T) {
	signerKey := newClientKey(t)
	otherKey := newClientKey(t)

	// Advertise other's public key, sign with signerKey's private key.
	opts := (&jose.SignerOptions{}).
		WithHeader(jose.HeaderType, TypDPoP).
		WithHeader("jwk", otherKey.jwk)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signerKey.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(goodClaims())
	obj, _ := s.Sign(payload)
	compact, _ := obj.CompactSerialize()

	if _, err := Verify(compact, testMethod, testURI, "", time.Now()); err == nil {
		t.Fatal("a proof whose signature does not match its advertised key was accepted")
	}
}

// TestPrivateKeyInProofIsRefused. A client that publishes its own private key
// has destroyed the binding; continuing would authorise a request with a key
// everybody now holds.
func TestPrivateKeyInProofIsRefused(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv := jose.JSONWebKey{Key: k, Algorithm: "RS256"}
	opts := (&jose.SignerOptions{}).
		WithHeader(jose.HeaderType, TypDPoP).
		WithHeader("jwk", priv)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(goodClaims())
	obj, _ := signer.Sign(payload)
	compact, _ := obj.CompactSerialize()

	if _, err := Verify(compact, testMethod, testURI, "", time.Now()); err == nil {
		t.Fatal("a proof carrying PRIVATE key material was accepted")
	}
}

// TestBindingIsWhatMakesItReal.
//
// The scenario the whole feature exists for: an attacker has the access token
// but not the key. They can mint a perfectly valid proof -- with their own key.
// Only the binding check stops them.
func TestBindingIsWhatMakesItReal(t *testing.T) {
	legit := newClientKey(t)
	thief := newClientKey(t)
	const token = "stolen-access-token"

	cnf := &Confirmation{JKT: legit.thumbprint(t)}

	// The rightful holder.
	c := goodClaims()
	c["ath"] = AccessTokenHash(token)
	good, err := Verify(legit.sign(t, TypDPoP, c), testMethod, testURI, token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := BoundTo(cnf, good); err != nil {
		t.Fatalf("the rightful holder was refused: %v", err)
	}

	// The thief: a VALID proof, from a key they generated. Everything about it
	// verifies. It is the binding, and only the binding, that refuses them.
	c2 := goodClaims()
	c2["jti"] = "thief-proof"
	c2["ath"] = AccessTokenHash(token)
	stolen, err := Verify(thief.sign(t, TypDPoP, c2), testMethod, testURI, token, time.Now())
	if err != nil {
		t.Fatalf("the thief's proof should VERIFY on its own terms: %v", err)
	}
	if err := BoundTo(cnf, stolen); err == nil {
		t.Fatal("A STOLEN TOKEN WAS ACCEPTED with a proof from the thief's own key. " +
			"The binding check is what makes DPoP more than decoration.")
	}
}

// TestUnboundTokenIsNotSilentlyAccepted. A token with no cnf must not pass a
// binding check just because a proof was supplied.
func TestUnboundTokenIsNotSilentlyAccepted(t *testing.T) {
	k := newClientKey(t)
	p, _ := Verify(k.sign(t, TypDPoP, goodClaims()), testMethod, testURI, "", time.Now())

	if err := BoundTo(nil, p); err == nil {
		t.Error("a nil confirmation passed the binding check")
	}
	if err := BoundTo(&Confirmation{}, p); err == nil {
		t.Error("an empty confirmation passed the binding check")
	}
	if err := BoundTo(&Confirmation{JKT: k.thumbprint(t)}, nil); err == nil {
		t.Error("a bound token was accepted with NO proof at all")
	}
}

// TestQueryAndFragmentAreIgnoredInHTU. RFC 9449 §4.3 specifies htu without
// them; comparing them would fail against clients that include them, and that
// interoperability failure looks like an attack in the logs.
func TestQueryAndFragmentAreIgnoredInHTU(t *testing.T) {
	k := newClientKey(t)
	c := goodClaims()
	c["htu"] = testURI + "?foo=bar#frag"
	if _, err := Verify(k.sign(t, TypDPoP, c), testMethod, testURI+"?other=1", "", time.Now()); err != nil {
		t.Errorf("query and fragment were compared: %v", err)
	}
}

func TestAccessTokenHashIsStable(t *testing.T) {
	if AccessTokenHash("abc") != AccessTokenHash("abc") {
		t.Error("not deterministic")
	}
	if AccessTokenHash("abc") == AccessTokenHash("abd") {
		t.Error("collides on a one-character change")
	}
	if strings.ContainsAny(AccessTokenHash("abc"), "+/=") {
		t.Error("not base64url without padding")
	}
}

// RFC 9449 §7.1 and §7.2 attach MUST-level requirements to the authentication
// SCHEME, not to the token. Enforcement that keys only on the token's `cnf`
// claim -- which is what this codebase did -- satisfies neither.
func TestPresentationRulesKeyOnTheSchemeNotTheToken(t *testing.T) {
	for _, c := range []struct {
		name    string
		bound   bool
		scheme  string
		wantErr error
	}{
		{
			// §7.2: "such a protected resource MUST reject a DPoP-bound access
			// token received as a bearer token". Checking `cnf` alone let this
			// through whenever a valid proof happened to accompany it.
			"a bound token under Bearer", true, "Bearer", ErrBoundTokenAsBearer,
		},
		{
			// §7.1 is unconditional on the scheme. The client is asserting
			// proof-of-possession; serving the request confirms a proof that
			// never happened.
			"an unbound token under DPoP", false, "DPoP", ErrDPoPSchemeUnboundToken,
		},
		{"a bound token under DPoP", true, "DPoP", nil},
		{"an unbound token under Bearer", false, "Bearer", nil},
		// A token that arrived some other way is not a scheme violation; the
		// binding check still applies to it downstream.
		{"a bound token, no scheme", true, "", nil},
		{"an unbound token, no scheme", false, "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := CheckPresentation(c.bound, c.scheme)
			if err != c.wantErr {
				t.Fatalf("CheckPresentation(%v, %q) = %v, want %v",
					c.bound, c.scheme, err, c.wantErr)
			}
		})
	}
}

// The `algs` advertised in a DPoP challenge must be the algorithms Verify will
// actually accept. A challenge naming an algorithm we refuse sends the client
// away to build a proof that cannot succeed.
func TestAdvertisedAlgsAreTheOnesEnforced(t *testing.T) {
	got := strings.Fields(SupportedAlgs())
	if len(got) != len(allowedAlgs) {
		t.Fatalf("advertised %d algorithms, enforce %d", len(got), len(allowedAlgs))
	}
	for i, a := range allowedAlgs {
		if got[i] != string(a) {
			t.Errorf("advertised %q at position %d, enforce %q", got[i], i, a)
		}
	}
	// Neither may ever appear, whatever the list is edited to.
	for _, forbidden := range []string{"none", "HS256"} {
		if strings.Contains(SupportedAlgs(), forbidden) {
			t.Errorf("the challenge advertises %q", forbidden)
		}
	}
}

func TestTheReplayWindowOutlivesEveryAcceptableProof(t *testing.T) {
	// A proof is accepted while iat-MaxSkew <= now <= iat+MaxAge.
	widest := MaxAge + MaxSkew
	if ReplayWindow < widest {
		t.Fatalf("ReplayWindow is %s but a proof stays acceptable for %s "+
			"(MaxAge %s + MaxSkew %s). The replay record expires while the proof "+
			"is still accepted, so a captured proof works again in the gap — this "+
			"is a known upstream issue",
			ReplayWindow, widest, MaxAge, MaxSkew)
	}

	// The boundary case stated as the timeline it comes from, so a future reader
	// can check the reasoning rather than trusting the sum.
	//
	// Earliest a proof can be seen: iat - MaxSkew (client clock maximally ahead).
	// Latest it is still accepted: iat + MaxAge.
	const iat = 1_000_000
	earliestFirstSight := iat - int64(MaxSkew.Seconds())
	lastAcceptable := iat + int64(MaxAge.Seconds())
	recordExpiresAt := earliestFirstSight + int64(ReplayWindow.Seconds())
	if recordExpiresAt < lastAcceptable {
		t.Errorf("a proof first seen at the earliest possible moment (%d) has its "+
			"replay record expire at %d, while it is still accepted until %d",
			earliestFirstSight, recordExpiresAt, lastAcceptable)
	}
}

func TestTheProofLifetimeStaysOnTheOrderOfMinutes(t *testing.T) {
	if MaxAge > 5*time.Minute {
		t.Errorf("MaxAge is %s. RFC 9449 §11.1 asks for \"a relatively brief "+
			"period on the order of seconds or minutes\", and every second of it "+
			"is a second a captured proof still works", MaxAge)
	}
}

func TestRSAProofKeysAreBoundedInBothDirections(t *testing.T) {
	for _, tc := range []struct {
		bits    int
		wantErr string
	}{
		{1024, "under"},
		{2048, ""},
	} {
		t.Run(fmt.Sprint(tc.bits), func(t *testing.T) {
			k, err := rsa.GenerateKey(rand.Reader, tc.bits)
			if err != nil {
				t.Skipf("cannot generate a %d-bit key here: %v", tc.bits, err)
			}
			jwk := jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "RS256"}
			opts := (&jose.SignerOptions{}).
				WithHeader(jose.HeaderType, TypDPoP).WithHeader("jwk", jwk)
			signer, serr := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, opts)
			if serr != nil {
				t.Fatal(serr)
			}
			payload, _ := json.Marshal(map[string]any{
				"jti": "k-" + fmt.Sprint(tc.bits), "htm": http.MethodGet,
				"htu": "https://x.test/r", "iat": time.Now().Unix(),
			})
			obj, _ := signer.Sign(payload)
			proof, _ := obj.CompactSerialize()

			_, verr := Verify(proof, http.MethodGet, "https://x.test/r", "", time.Now())
			switch {
			case tc.wantErr == "" && verr != nil:
				t.Errorf("a %d-bit key was refused: %v", tc.bits, verr)
			case tc.wantErr != "" && verr == nil:
				t.Errorf("a %d-bit RSA proof key was accepted", tc.bits)
			case tc.wantErr != "" && !strings.Contains(verr.Error(), tc.wantErr):
				t.Errorf("a %d-bit key was refused for the wrong reason: %v", tc.bits, verr)
			}
		})
	}
}

func TestAnOversizedJTIIsRefused(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"}
	opts := (&jose.SignerOptions{}).
		WithHeader(jose.HeaderType, TypDPoP).WithHeader("jwk", jwk)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, opts)

	for _, tc := range []struct{ name, jti string }{
		{"ordinary", strings.Repeat("a", 36)},
		{"oversized", strings.Repeat("a", 4000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{
				"jti": tc.jti, "htm": http.MethodGet,
				"htu": "https://x.test/r", "iat": time.Now().Unix(),
			})
			obj, _ := signer.Sign(payload)
			proof, _ := obj.CompactSerialize()
			_, verr := Verify(proof, http.MethodGet, "https://x.test/r", "", time.Now())
			if tc.name == "ordinary" && verr != nil {
				t.Errorf("an ordinary jti was refused: %v", verr)
			}
			if tc.name == "oversized" && verr == nil {
				t.Error("a 4 kB jti was accepted and would be stored verbatim, once " +
					"per request, by an unauthenticated caller")
			}
		})
	}
}

// The ceiling, against `checkKeyStrength` directly.
//
// Generating a 16384-bit RSA key takes minutes; constructing a public key of
// that size takes microseconds, and the bound under test reads only `N.BitLen()`.
// Verified once out-of-band that a real 16384-bit proof does reach this check and
// costs ~3 ms to verify — which is the number that motivates the bound.
func TestTheRSACeilingRejectsAnOversizedKey(t *testing.T) {
	for _, bits := range []int{8192, 8193, 16384, 32768} {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) // exactly `bits` long
		jwk := &jose.JSONWebKey{Key: &rsa.PublicKey{N: n, E: 65537}}
		err := checkKeyStrength(jwk)
		switch {
		case bits <= maxRSABits && err != nil:
			t.Errorf("%d-bit key refused: %v", bits, err)
		case bits > maxRSABits && err == nil:
			t.Errorf("%d-bit RSA proof key accepted; verification cost is chosen by "+
				"an unauthenticated caller at this endpoint", bits)
		}
	}
}

// A non-RSA key has no size to check here: each EC and Ed algorithm in
// allowedAlgs pins one curve, so `alg` already fixes the strength and go-jose
// refuses a mismatch. The bound must not accidentally refuse them.
func TestTheKeyStrengthCheckIgnoresNonRSAKeys(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkKeyStrength(&jose.JSONWebKey{Key: &k.PublicKey}); err != nil {
		t.Errorf("an EC key was refused by the RSA size bound: %v", err)
	}
}
