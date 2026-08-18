package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Key proofs, OID4VCI Appendix F.1.
//
// Every rejection below is a way a credential could be bound to a key its
// presenter does not control, which turns a sender-constrained credential back
// into a bearer token.

type holder struct {
	key *ecdsa.PrivateKey
	jwk *jose.JSONWebKey
}

func newHolder(t *testing.T) *holder {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &holder{key: k, jwk: &jose.JSONWebKey{Key: k.Public(), Algorithm: string(jose.ES256)}}
}

// sign builds a proof. Every part is separable so a test can break exactly one.
func (h *holder) sign(t *testing.T, typ string, claims map[string]any, embedKey bool, kid string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if embedKey {
		opts = opts.WithHeader("jwk", h.jwk)
	}
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: h.key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const issuerID = "https://credentials.example.test"

func goodProofClaims(now time.Time) map[string]any {
	return map[string]any{"aud": issuerID, "iat": now.Unix(), "nonce": "n-123"}
}

func ctxFor() ProofContext {
	return ProofContext{CredentialIssuer: issuerID, ExpectedNonce: "n-123",
		ClientID: "wallet", Anonymous: false}
}

func TestAGenuineProofValidates(t *testing.T) {
	h := newHolder(t)
	now := time.Now()
	raw := h.sign(t, TypProof, goodProofClaims(now), true, "")

	key, err := ValidateJWTProof(raw, ctxFor(), now)
	if err != nil {
		t.Fatalf("a conformant key proof was refused: %v", err)
	}
	if key.JWK == nil {
		t.Fatal("no key returned, so nothing could be bound")
	}
	if key.Nonce != "n-123" {
		t.Errorf("nonce = %q", key.Nonce)
	}
}

func TestEveryProofRejection(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		build func(t *testing.T) (string, ProofContext)
		want  string
		why   string
	}{
		{
			name: "typ is not openid4vci-proof+jwt",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				return h.sign(t, "JWT", goodProofClaims(now), true, ""), ctxFor()
			},
			want: "typ",
			why:  "an ID token is also signed JSON with aud and iat",
		},
		{
			name: "audience is not the credential issuer",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				c := goodProofClaims(now)
				c["aud"] = "https://somebody-else.test"
				return h.sign(t, TypProof, c, true, ""), ctxFor()
			},
			want: "aud",
			why:  "a proof made for another issuer would be replayable here",
		},
		{
			name: "no key identified at all",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				return h.sign(t, TypProof, goodProofClaims(now), false, ""), ctxFor()
			},
			want: "identifies no key",
			why:  "there would be nothing to bind the credential to",
		},
		{
			name: "both jwk and kid present",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				return h.sign(t, TypProof, goodProofClaims(now), true, "key-1"), ctxFor()
			},
			want: "mutually exclusive",
			why:  "the key verified and the key bound could then differ",
		},
		{
			name: "signed by a different key than it carries",
			build: func(t *testing.T) (string, ProofContext) {
				h, other := newHolder(t), newHolder(t)
				// Sign with `other`, advertise h's key.
				opts := (&jose.SignerOptions{}).WithType(jose.ContentType(TypProof)).
					WithHeader("jwk", h.jwk)
				signer, err := jose.NewSigner(
					jose.SigningKey{Algorithm: jose.ES256, Key: other.key}, opts)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := json.Marshal(goodProofClaims(now))
				obj, err := signer.Sign(body)
				if err != nil {
					t.Fatal(err)
				}
				s, _ := obj.CompactSerialize()
				return s, ctxFor()
			},
			want: "does not verify",
			why:  "anybody could bind a credential to somebody else's public key",
		},
		{
			name: "missing the c_nonce the issuer provided",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				c := goodProofClaims(now)
				delete(c, "nonce")
				return h.sign(t, TypProof, c, true, ""), ctxFor()
			},
			want: "c_nonce",
			why:  "a captured proof could otherwise be replayed forever",
		},
		{
			name: "wrong c_nonce",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				c := goodProofClaims(now)
				c["nonce"] = "somebody-elses-nonce"
				return h.sign(t, TypProof, c, true, ""), ctxFor()
			},
			want: "c_nonce",
			why:  "freshness must come from the value this issuer handed out",
		},
		{
			name: "no iat",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				c := goodProofClaims(now)
				delete(c, "iat")
				return h.sign(t, TypProof, c, true, ""), ctxFor()
			},
			want: "iat",
			why:  "an undated proof cannot be aged out",
		},
		{
			name: "older than the proof lifetime",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				c := goodProofClaims(now.Add(-30 * time.Minute))
				return h.sign(t, TypProof, c, true, ""), ctxFor()
			},
			want: "older than",
			why:  "an unbounded proof is an issuance capability that never expires",
		},
		{
			name: "dated in the future",
			build: func(t *testing.T) (string, ProofContext) {
				h := newHolder(t)
				c := goodProofClaims(now.Add(30 * time.Minute))
				return h.sign(t, TypProof, c, true, ""), ctxFor()
			},
			want: "future",
			why:  "a clock problem or a forgery; neither is something to act on",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ctx := tc.build(t)
			_, err := ValidateJWTProof(raw, ctx, now)
			if err == nil {
				t.Fatalf("accepted; %s", tc.why)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// §F.1: `iss` "MUST be omitted if the access token authorizing the issuance call
// was obtained from a Pre-Authorized Code Flow through anonymous access".
//
// This is the rule that makes ProofContext carry Anonymous separately from an
// empty ClientID: "we do not know the client" and "there deliberately was no
// client" are different states, and only the second forbids the claim.
func TestIssuerClaimRulesForAnonymousPreAuthorizedTokens(t *testing.T) {
	now := time.Now()

	t.Run("iss present after an anonymous redemption is refused", func(t *testing.T) {
		h := newHolder(t)
		c := goodProofClaims(now)
		c["iss"] = "wallet"
		ctx := ctxFor()
		ctx.Anonymous, ctx.ClientID = true, ""
		if _, err := ValidateJWTProof(h.sign(t, TypProof, c, true, ""), ctx, now); err == nil {
			t.Fatal("a proof carrying iss was accepted for an anonymously obtained token")
		}
	})

	t.Run("iss omitted after an anonymous redemption is correct", func(t *testing.T) {
		h := newHolder(t)
		ctx := ctxFor()
		ctx.Anonymous, ctx.ClientID = true, ""
		if _, err := ValidateJWTProof(h.sign(t, TypProof, goodProofClaims(now), true, ""),
			ctx, now); err != nil {
			t.Fatalf("the conformant anonymous case was refused: %v", err)
		}
	})

	t.Run("iss naming another client is refused", func(t *testing.T) {
		h := newHolder(t)
		c := goodProofClaims(now)
		c["iss"] = "some-other-wallet"
		if _, err := ValidateJWTProof(h.sign(t, TypProof, c, true, ""), ctxFor(), now); err == nil {
			t.Fatal("a proof claiming to be from another client was accepted")
		}
	})
}

// alg: none, and the symmetric algorithms §F.1 forbids.
func TestUnsafeAlgorithmsAreRefused(t *testing.T) {
	now := time.Now()
	b64 := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := b64(map[string]any{"alg": "none", "typ": TypProof})
	body := b64(goodProofClaims(now))
	if _, err := ValidateJWTProof(header+"."+body+".", ctxFor(), now); err == nil {
		t.Fatal("a key proof with alg=none was accepted; anybody could bind a " +
			"credential to any key by writing JSON")
	}
}
