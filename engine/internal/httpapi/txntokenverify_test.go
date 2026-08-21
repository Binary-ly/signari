package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/txntoken"
)

// Verifying a presented Transaction Token.
//
// draft-ietf-oauth-transaction-tokens-11 §9.2 makes `exp` REQUIRED, and §13.15
// says a Transaction Token Service "MUST NOT issue a new Txn-Token when the
// Txn-Token being replaced has expired".
//
// verifyTxnToken had no test of any kind. It is the function that decides
// whether a token presented for replacement is real, so every rule in §13.15
// rests on it.

// txnVerifyServer is the minimum Server verifyTxnToken touches: a key set and an
// issuer. No database -- reaching one would mean a token got further than it
// should have.
func txnVerifyServer(t *testing.T) (*Server, *keys.Set, string) {
	t.Helper()
	const issuer = "https://txn-verify.example"
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		cfg: oidc.Config{Issuer: issuer, Keys: set, AllowInsecureIssuer: true},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, set, issuer
}

// signTxn mints a Transaction Token with whatever claims a test wants, using the
// server's own key. A token an attacker could not forge -- which is the point:
// these tests are about what we accept from ourselves.
func signTxn(t *testing.T, set *keys.Set, claims txntoken.Claims) string {
	t.Helper()
	k, err := set.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tokens.NewSigner(k).SignJSON(claims, txntoken.Typ)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func goodTxnClaims(issuer string) txntoken.Claims {
	now := time.Now()
	return txntoken.Claims{
		Issuer:             issuer,
		IssuedAt:           now.Unix(),
		Expiry:             now.Add(2 * time.Minute).Unix(),
		Audience:           "https://trust-domain.example",
		Transaction:        "txn-1",
		Subject:            "user-1",
		RequestingWorkload: "edge",
		Scope:              "transfer",
	}
}

// TestAValidTransactionTokenVerifies, so the refusals below are not simply
// everything being refused.
func TestAValidTransactionTokenVerifies(t *testing.T) {
	s, set, issuer := txnVerifyServer(t)
	got, err := s.verifyTxnToken(signTxn(t, set, goodTxnClaims(issuer)))
	if err != nil {
		t.Fatalf("a well-formed transaction token was refused: %v", err)
	}
	if got.Transaction != "txn-1" || got.Subject != "user-1" {
		t.Errorf("claims did not survive verification: %+v", got)
	}
}

// TestATransactionTokenWithoutAnExpiryIsRefused.
//
// §9.2 lists `exp` as REQUIRED. The check was written as
//
//	if c.Expiry > 0 && time.Now().Unix() >= c.Expiry
//
// so a token carrying no `exp` skipped it entirely and was treated as valid
// forever — and `Replace` skipped its clamp for the same reason, minting a
// successor with a fresh full lifetime. A chain built on such a token never
// ends, which is the outcome §13.15's "MUST NOT issue a new Txn-Token when the
// Txn-Token being replaced has expired" exists to prevent.
//
// Not reachable by an attacker today: the token must be signed by our own key
// and carry typ=txntoken+jwt, and every path that mints one sets an expiry. It
// is still the wrong shape — the guard disabled the safety check exactly when
// the safety-critical claim was missing.
func TestATransactionTokenWithoutAnExpiryIsRefused(t *testing.T) {
	s, set, issuer := txnVerifyServer(t)

	claims := goodTxnClaims(issuer)
	claims.Expiry = 0

	_, err := s.verifyTxnToken(signTxn(t, set, claims))
	if err == nil {
		t.Fatal("a transaction token with no exp was accepted; it never expires, and " +
			"every replacement built on it gets a fresh lifetime")
	}
	if !strings.Contains(err.Error(), "expiry") && !strings.Contains(err.Error(), "exp") {
		t.Errorf("refused, but not as a missing expiry: %v", err)
	}
}

// TestAnExpiredTransactionTokenIsRefused -- the case the guard did cover.
func TestAnExpiredTransactionTokenIsRefused(t *testing.T) {
	s, set, issuer := txnVerifyServer(t)

	claims := goodTxnClaims(issuer)
	claims.Expiry = time.Now().Add(-time.Second).Unix()

	if _, err := s.verifyTxnToken(signTxn(t, set, claims)); err == nil {
		t.Fatal("an expired transaction token was accepted")
	}
}

// TestAnAccessTokenIsNotATransactionToken.
//
// The distinct `typ` is what stops one being replayed as the other. Asserted
// because it is the kind of property that survives only while somebody keeps
// asserting it.
func TestAnAccessTokenIsNotATransactionToken(t *testing.T) {
	s, set, issuer := txnVerifyServer(t)

	k, err := set.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
		Issuer: issuer, Subject: "user-1", Audience: []string{"api"},
		Expiry: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
		JTI: "jti-1", Scope: "transfer",
	}, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.verifyTxnToken(raw); err == nil {
		t.Fatal("an access token verified as a transaction token; the distinct typ " +
			"exists precisely to stop that")
	}
}

// TestATransactionTokenFromAnotherIssuerIsRefused.
func TestATransactionTokenFromAnotherIssuerIsRefused(t *testing.T) {
	s, set, _ := txnVerifyServer(t)

	claims := goodTxnClaims("https://somebody-else.example")
	if _, err := s.verifyTxnToken(signTxn(t, set, claims)); err == nil {
		t.Fatal("a transaction token naming another issuer was accepted")
	}
}

// §13.13: "A workload MUST NOT use a transaction token as an OAuth 2.0 Access
// Token." §13.12 says the same about authenticating a workload.
//
// # Whose obligation this is, and why it is still our test
//
// Both sentences are written on the *workload*, so a specification lawyer could
// say neither is ours to enforce. That reading is how this goes wrong. A
// Txn-Token asserts a subject and a scope and is signed by the same key as our
// access tokens, so if anything here accepted one as a bearer credential, the
// workload's mistake would become our compromise — and the workload is the party
// least able to notice.
//
// The engine's defence is RFC 8725 explicit typing: `txntoken+jwt` is not
// `at+jwt`. That defence is one shared function, so it is worth proving it holds
// at the entry point every protected endpoint funnels through, rather than
// assuming it because the constant differs.
//
// The existing suite tested the opposite direction — an access token refused as a
// Txn-Token. This is the direction that carries the authority.
func TestATransactionTokenIsNotAnAccessToken(t *testing.T) {
	srv, set, issuer := txnVerifyServer(t)

	// A genuine Txn-Token: our key, our issuer, nothing wrong with it.
	raw := signTxn(t, set, goodTxnClaims(issuer))
	if _, err := srv.verifyTxnToken(raw); err != nil {
		t.Fatalf("the fixture token is not a valid Txn-Token: %v", err)
	}

	// Now present it where an access token belongs.
	if _, err := tokens.VerifyAccessToken(set, issuer, raw); err == nil {
		t.Fatal("a Transaction Token was accepted as an access token; §13.13 says a " +
			"workload must not use one that way, and here the server would let it")
	}

	// The above is weaker than it looks, and mutation proved it: an ordinary
	// Txn-Token carries no `jti`, and access-token verification requires one
	// (RFC 9068 §4), so it is refused for the missing claim whether or not `typ`
	// is checked at all. Removing the typ defence leaves that assertion green.
	//
	// So here is the isolating case: a token carrying EVERY claim access-token
	// verification wants, signed by our key, differing from a real access token
	// in exactly one respect -- `typ` says txntoken+jwt. If it is accepted, the
	// only defence between a Txn-Token and a bearer credential is gone.
	k, err := set.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	disguised, err := tokens.NewSigner(k).SignJSON(map[string]any{
		"iss":       issuer,
		"sub":       "user-1",
		"aud":       []string{"some-client"},
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "j-1",
		"client_id": "some-client",
		"scope":     "transfer",
		// And the Txn-Token claims alongside them.
		"txn":    "txn-1",
		"req_wl": "edge",
	}, txntoken.Typ)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.VerifyAccessTokenAny(set, []string{issuer}, disguised); err == nil {
		t.Fatal("a token whose ONLY defect was typ=txntoken+jwt was accepted as an " +
			"access token; explicit typing is the whole defence and it is not holding")
	}

	// And it must not pass as an ID token either -- the end-session endpoint
	// reads one of those to decide which client is asking.
	if _, err := tokens.VerifyIDTokenAudience(set, issuer, raw); err == nil {
		t.Fatal("a Transaction Token was accepted as an id_token_hint")
	}
}

// §13.3, the half nobody tests: "the TTS response MUST NOT include a refresh
// token."
//
// The input half — a refresh token refused as a subject_token — is covered in
// internal/txntoken. This is the output half, and it is the one that would be
// broken by a refactor rather than by a mistake: the Txn-Token response is
// deliberately its own shape, and the obvious "simplification" is to reuse the
// ordinary token response, which carries a refresh token field.
func TestTheTransactionTokenResponseCarriesNoRefreshToken(t *testing.T) {
	body, err := json.Marshal(txntoken.NewResponse("a.b.c"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range []string{"refresh_token", "refresh_expires_in", "id_token"} {
		if _, present := fields[forbidden]; present {
			t.Errorf("the Txn-Token response carries %q; §13.3 forbids a refresh token "+
				"and the response shape should carry nothing but the token", forbidden)
		}
	}

	// And the three fields it must carry, with token_type literally "N_A" --
	// saying "Bearer" would invite exactly the §13.13 misuse tested above.
	if fields["token_type"] != "N_A" {
		t.Errorf("token_type = %v, want \"N_A\"", fields["token_type"])
	}
	if fields["issued_token_type"] != txntoken.TokenType {
		t.Errorf("issued_token_type = %v, want %s", fields["issued_token_type"], txntoken.TokenType)
	}
	if fields["access_token"] != "a.b.c" {
		t.Errorf("access_token = %v, want the minted token", fields["access_token"])
	}
}
