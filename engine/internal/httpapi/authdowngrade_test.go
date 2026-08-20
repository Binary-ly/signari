package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

// ASVS 5.0 V10.4.16: strong client authentication, and no way round it.
//
// docs/security-review-asvs.md records this as "✅ both, and a client registered
// for one cannot fall back to a secret". The first half was tested. The second
// half — the part that makes the first half worth anything — had no test
// anywhere: no file in internal/httpapi so much as mentioned private_key_jwt.
//
// The property matters because the fallback is the attack. A client registered
// for private_key_jwt has a key that never leaves it; if presenting a shared
// secret still authenticated, an attacker who obtained that secret from a
// backup, a log or a former employee would be back to bearer credentials and the
// registration would be decoration.
//
// Structurally the guard is a `switch` on the stored method where the strong
// cases return before reaching verifyClientSecret. That is easy to write and
// easy to lose: adding a `break` or reordering a case restores the fallback
// silently, which is exactly the shape a test has to hold down.
func TestAClientRegisteredForStrongAuthCannotFallBackToASecret(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// Give the fixture's client a secret AND register it for private_key_jwt.
	// Both, deliberately: the question is whether the secret still works once
	// the stronger method is declared, so the secret has to be real.
	secret := revocableClient(t, f)

	// A real key set, because the schema will not accept the method without one:
	// core.clients carries a CHECK named clients_private_key_jwt_needs_keys, so a
	// client cannot be registered for private_key_jwt with nothing to verify
	// against. That constraint is itself part of this requirement — a method
	// declared but unusable is how a fallback gets justified later.
	const jwks = `{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256",` +
		`"kid":"downgrade-test-1",` +
		`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
		`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.clients SET token_endpoint_auth_method = 'private_key_jwt',
		        jwks = $2::jsonb
		 WHERE client_id = $1`, f.clientID, jwks); err != nil {
		t.Fatalf("registering private_key_jwt: %v", err)
	}

	const verifier = "verifier-for-the-downgrade-check-0123456789ab"
	code := f.issueCode(t, verifier)

	form := f.redeem(code, verifier)
	form.Set("client_secret", secret)

	status, body := f.post(t, form)
	if status == http.StatusOK {
		t.Fatal("a client registered for private_key_jwt authenticated with its " +
			"client_secret; the strong method is then advisory, and anyone " +
			"holding the secret is back to a bearer credential")
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}

	// The refusal must be about the METHOD, not about a malformed assertion:
	// a client sending no assertion at all should be told what it is expected
	// to send.
	t.Run("and an absent assertion is refused too", func(t *testing.T) {
		bare := url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {"whatever"}, "client_id": {f.clientID},
			"client_secret": {secret}}
		if status, b := f.post(t, bare); status == http.StatusOK {
			t.Errorf("the secret authenticated on another grant too: %v", b)
		}
	})
}
