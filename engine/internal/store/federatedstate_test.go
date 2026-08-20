package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ASVS 5.0 V10.2.1: CSRF defence on the code flow.
//
// Signari is the relying party for social login, so the `state` parameter is its
// own protection, not somebody else's. The doc records this as "✅ both" (PKCE
// and state) and nothing tested the state half — no test referenced
// ConsumeFederatedLogin or core.federated_logins.
//
// Two properties, and the second is the one that is easy to lose:
//
//  1. the state is SINGLE-USE, so a callback URL captured from a browser's
//     history or a referrer header cannot be replayed; and
//  2. it is bound to the browser that started the login, by a cookie value the
//     attacker does not have — without which a state observed in transit could
//     be completed by anybody.
func TestAFederatedLoginStateIsSingleUseAndBoundToItsBrowser(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	var providerID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, client_id)
		VALUES ($1::uuid, $2, 'Test IdP', 'test-client')
		RETURNING id::text`,
		orgID, "idp-"+itoa(time.Now().UnixNano())).Scan(&providerID); err != nil {
		t.Fatalf("identity provider: %v", err)
	}

	begin := func() (state, binding string) {
		t.Helper()
		s, b, err := BeginFederatedLogin(ctx, tx, PendingLogin{
			ProviderID: providerID, OrgID: orgID, Nonce: "n-1",
			CodeVerifier: "v-1", LinkUserID: userID,
		})
		if err != nil {
			t.Fatalf("beginning: %v", err)
		}
		return s, b
	}

	t.Run("the happy path works, then does not work twice", func(t *testing.T) {
		state, binding := begin()
		if _, err := ConsumeFederatedLogin(ctx, tx, state, binding); err != nil {
			t.Fatalf("a legitimate callback was refused: %v", err)
		}
		_, err := ConsumeFederatedLogin(ctx, tx, state, binding)
		if err == nil {
			t.Fatal("the same state was consumed twice; a callback URL from a " +
				"browser history or a referrer header could be replayed")
		}
		if !strings.Contains(err.Error(), "already been used") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("a different browser cannot finish the login", func(t *testing.T) {
		state, _ := begin()
		if _, err := ConsumeFederatedLogin(ctx, tx, state, "some-other-browsers-cookie"); err == nil {
			t.Fatal("a callback completed with the wrong browser binding; anyone " +
				"who observed the state could finish somebody else's sign-in")
		} else if !strings.Contains(err.Error(), "different browser") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})

	// The subtle one, and the reason the comparison happens after the DELETE:
	// a wrong binding must still BURN the state. Otherwise an attacker can
	// probe with guesses and leave the real state usable for the victim, or
	// grind it themselves.
	t.Run("a wrong binding burns the state anyway", func(t *testing.T) {
		state, binding := begin()
		if _, err := ConsumeFederatedLogin(ctx, tx, state, "wrong"); err == nil {
			t.Fatal("the wrong binding was accepted")
		}
		if _, err := ConsumeFederatedLogin(ctx, tx, state, binding); err == nil {
			t.Fatal("after a failed attempt the state was still usable; a wrong " +
				"binding must burn it, or it can be ground against")
		}
	})
}
