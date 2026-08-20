package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeProvider is an external identity provider we control, so every claim can
// be made wrong on purpose.
type fakeProvider struct {
	*httptest.Server
	key    *rsa.PrivateKey
	issuer string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProvider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}}
		_ = json.NewEncoder(w).Encode(set)
	})
	fp.Server = httptest.NewServer(mux)
	fp.issuer = fp.Server.URL
	t.Cleanup(fp.Server.Close)
	return fp
}

// sign builds an id_token with whatever claims the test wants.
func (fp *fakeProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: fp.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"),
	)
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

func (fp *fakeProvider) config() Config {
	p, _ := PresetFor(KindOIDC)
	p.OIDC = true
	return Config{
		ClientID:       "our-client-id",
		Kind:           KindOIDC,
		Preset:         p,
		IssuerOverride: fp.issuer,
		JWKSOverride:   fp.Server.URL + "/jwks",
	}
}

func goodClaims(fp *fakeProvider) map[string]any {
	return map[string]any{
		"iss": fp.issuer, "sub": "ext-subject-1", "aud": "our-client-id",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"nonce": "the-nonce", "email": "alice@example.com", "email_verified": true,
	}
}

func TestValidIDTokenIsAccepted(t *testing.T) {
	fp := newFakeProvider(t)
	c := fp.config()
	tok := fp.sign(t, goodClaims(fp))

	id, err := c.FetchIdentity(context.Background(), fp.Client(),
		&TokenSet{IDToken: tok}, "the-nonce")
	if err != nil {
		t.Fatalf("a valid id_token was refused: %v", err)
	}
	if id.Subject != "ext-subject-1" || id.Email != "alice@example.com" {
		t.Errorf("identity = %+v", id)
	}
}

// TestIDTokenAttacks. Each case is a token that must not be believed. Any one
// of them accepted is authentication bypass: the attacker signs in as whoever
// the token names.
func TestIDTokenAttacks(t *testing.T) {
	fp := newFakeProvider(t)
	other := newFakeProvider(t)
	c := fp.config()

	cases := []struct {
		name  string
		token func() string
		nonce string
	}{
		{
			// ASVS 5.0.0 V9.2.1: "if a validity time span is present in the token
			// data, the token and its content are accepted only if the
			// verification time is within this validity time span. For example,
			// for JWTs, the claims 'nbf' and 'exp' must be verified."
			//
			// We never emit nbf ourselves, which is why this was unchecked: every
			// token this code was written against lacked one. An upstream that
			// says "not valid before T" has said something we were ignoring.
			name: "not valid until an hour from now",
			token: func() string {
				cl := goodClaims(fp)
				cl["nbf"] = time.Now().Add(time.Hour).Unix()
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "issued an hour in the future",
			token: func() string {
				cl := goodClaims(fp)
				cl["iat"] = time.Now().Add(time.Hour).Unix()
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "audience is a different application",
			token: func() string {
				cl := goodClaims(fp)
				cl["aud"] = "some-other-app"
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "issuer is somebody else",
			token: func() string {
				cl := goodClaims(fp)
				cl["iss"] = "https://evil.test"
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "signed by a different provider's key",
			token: func() string {
				cl := goodClaims(fp)
				return other.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "expired",
			token: func() string {
				cl := goodClaims(fp)
				cl["exp"] = time.Now().Add(-time.Hour).Unix()
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "no expiry at all",
			token: func() string {
				cl := goodClaims(fp)
				delete(cl, "exp")
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "nonce from a different login (replay)",
			token: func() string {
				cl := goodClaims(fp)
				cl["nonce"] = "somebody-elses-nonce"
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "no nonce at all",
			token: func() string {
				cl := goodClaims(fp)
				delete(cl, "nonce")
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "no subject",
			token: func() string {
				cl := goodClaims(fp)
				delete(cl, "sub")
				return fp.sign(t, cl)
			},
			nonce: "the-nonce",
		},
		{
			name: "alg none, unsigned",
			token: func() string {
				// Hand-built: no library will produce this willingly.
				hdr := `{"alg":"none","typ":"JWT"}`
				body, _ := json.Marshal(goodClaims(fp))
				return b64url(hdr) + "." + b64urlBytes(body) + "."
			},
			nonce: "the-nonce",
		},
		{
			name:  "not a JWT at all",
			token: func() string { return "not-a-token" },
			nonce: "the-nonce",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := c.FetchIdentity(context.Background(), fp.Client(),
				&TokenSet{IDToken: tc.token()}, tc.nonce)
			if err == nil {
				t.Fatalf("ACCEPTED an id_token that was %s -> subject %q would be signed in",
					tc.name, id.Subject)
			}
		})
	}
}

// TestAudienceArrayIsHandled. `aud` is legally either a string or an array, and
// an implementation that handles only one either breaks on real providers or,
// worse, skips the check when it cannot parse.
func TestAudienceArrayIsHandled(t *testing.T) {
	fp := newFakeProvider(t)
	c := fp.config()

	cl := goodClaims(fp)
	cl["aud"] = []string{"another-app", "our-client-id"}
	if _, err := c.FetchIdentity(context.Background(), fp.Client(),
		&TokenSet{IDToken: fp.sign(t, cl)}, "the-nonce"); err != nil {
		t.Errorf("an audience array containing our client id was refused: %v", err)
	}

	cl["aud"] = []string{"another-app", "a-third-app"}
	if _, err := c.FetchIdentity(context.Background(), fp.Client(),
		&TokenSet{IDToken: fp.sign(t, cl)}, "the-nonce"); err == nil {
		t.Error("an audience array NOT containing our client id was accepted")
	}
}

// TestMicrosoftEmailIsNotBelievedWithoutXmsEdov.
//
// Microsoft's documentation says of the email claim: "This value isn't
// guaranteed to be correct... never use it for authorization." The optional
// xms_edov claim is the only signal that the domain owner was verified.
func TestMicrosoftEmailIsNotBelievedWithoutXmsEdov(t *testing.T) {
	fp := newFakeProvider(t)
	c := fp.config()
	c.Kind = KindMicrosoft

	// email_verified: true, but no xms_edov -- exactly the shape that has caused
	// cross-tenant takeovers in applications that matched on the address.
	cl := goodClaims(fp)
	cl["email_verified"] = true
	id, err := c.FetchIdentity(context.Background(), fp.Client(),
		&TokenSet{IDToken: fp.sign(t, cl)}, "the-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if id.EmailVerified {
		t.Error("believed Microsoft's email_verified claim with no xms_edov present")
	}

	// With xms_edov true, it counts.
	cl["xms_edov"] = true
	id, err = c.FetchIdentity(context.Background(), fp.Client(),
		&TokenSet{IDToken: fp.sign(t, cl)}, "the-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if !id.EmailVerified {
		t.Error("xms_edov was true and the address was still treated as unverified")
	}

	// And explicitly false must not be read as "absent, so maybe".
	cl["xms_edov"] = false
	id, _ = c.FetchIdentity(context.Background(), fp.Client(),
		&TokenSet{IDToken: fp.sign(t, cl)}, "the-nonce")
	if id.EmailVerified {
		t.Error("xms_edov was false and the address was treated as verified")
	}
}

// TestGitHubUsesTheVerifiedEmailEndpoint.
//
// GET /user returns whatever the user set as publicly visible, which may be an
// address they never confirmed. Believing it is how somebody signs up here with
// an address belonging to a person who has never used GitHub.
func TestGitHubUsesTheVerifiedEmailEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		// A public address the user never confirmed.
		_, _ = w.Write([]byte(`{"id":4242,"login":"octocat","name":"Octo",
			"email":"unconfirmed@example.com"}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"email":"unconfirmed@example.com","primary":true,"verified":false},
			{"email":"real@example.com","primary":false,"verified":true}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := githubConfigPointingAt(srv.URL)
	id, err := c.FetchIdentity(context.Background(), srv.Client(),
		&TokenSet{AccessToken: "tok"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if id.Email == "unconfirmed@example.com" {
		t.Error("used the unconfirmed address from /user")
	}
	if id.Email != "real@example.com" || !id.EmailVerified {
		t.Errorf("identity = %+v, want the verified address", id)
	}
	// And the subject must be the numeric id, not the login: a login can be
	// changed and then claimed by somebody else.
	if id.Subject != "4242" {
		t.Errorf("subject = %q, want the immutable numeric id", id.Subject)
	}
}

// TestGitHubWithNoVerifiedAddressIsNotMarkedVerified.
func TestGitHubWithNoVerifiedAddressIsNotMarkedVerified(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":7,"login":"nobody","email":"nope@example.com"}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"email":"nope@example.com","primary":true,"verified":false}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	id, err := githubConfigPointingAt(srv.URL).FetchIdentity(
		context.Background(), srv.Client(), &TokenSet{AccessToken: "tok"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if id.EmailVerified {
		t.Error("marked an address verified when GitHub said it was not")
	}
}

// TestGitHubEmailEndpointFailureIsNotFatalButIsNotTrusted.
func TestGitHubEmailEndpointFailureIsNotFatalButIsNotTrusted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":9,"login":"x","email":"x@example.com"}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		// Missing the user:email scope looks like this.
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	id, err := githubConfigPointingAt(srv.URL).FetchIdentity(
		context.Background(), srv.Client(), &TokenSet{AccessToken: "tok"}, "")
	if err != nil {
		t.Fatalf("a missing email endpoint should not fail the whole sign-in: %v", err)
	}
	if id.EmailVerified {
		t.Error("could not check verification and assumed it anyway")
	}
	if id.Subject != "9" {
		t.Errorf("subject = %q", id.Subject)
	}
}

func TestAuthorizeURLCarriesPKCEAndNonce(t *testing.T) {
	fp := newFakeProvider(t)
	c := fp.config()
	c.AuthorizeOverride = "https://provider.test/authorize"

	u := c.AuthorizeURL("https://auth.example.com/cb", "state1", "nonce1", "verifier1")
	for _, want := range []string{
		"code_challenge_method=S256", "code_challenge=", "state=state1", "nonce=nonce1",
		"redirect_uri=https%3A%2F%2Fauth.example.com%2Fcb",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("authorize URL is missing %s\n%s", want, u)
		}
	}
	// The verifier itself must never be on the wire.
	if strings.Contains(u, "verifier1") {
		t.Error("the PKCE verifier was sent in the authorize URL; only its hash may be")
	}
}

func githubConfigPointingAt(base string) Config {
	p, _ := PresetFor(KindGitHub)
	return Config{ClientID: "id", Kind: KindGitHub, Preset: p,
		UserinfoOverride: base + "/user"}
}

func b64url(s string) string      { return b64urlBytes([]byte(s)) }
func b64urlBytes(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
