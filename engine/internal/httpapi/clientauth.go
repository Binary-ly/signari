package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
)

// authenticateConfidentialClient checks a client's proof of identity.
//
// # The downgrade this function exists to prevent
//
// A client configured for private_key_jwt must NOT be able to authenticate with
// a secret, even if a stale hash is still in the row. Otherwise an attacker who
// obtained the old secret -- the exact thing the migration to keys was meant to
// retire -- can keep using it, and the upgrade bought nothing.
//
// So the method is read from configuration and dispatched on, rather than
// inferred from whichever credential the request happens to carry.
func (s *Server) authenticateConfidentialClient(ctx context.Context, r *http.Request,
	c *clients.Client, presentedSecret string) error {

	method, jwks, err := store.ClientAuthMethod(ctx, s.db, c.ClientID)
	if err != nil {
		return fmt.Errorf("reading the client's authentication method: %w", err)
	}

	switch method {
	case "private_key_jwt":
		assertionType := r.PostFormValue("client_assertion_type")
		if assertionType != clientauth.AssertionType {
			return fmt.Errorf("this client authenticates with private_key_jwt; "+
				"client_assertion_type must be %q", clientauth.AssertionType)
		}
		assertion := r.PostFormValue("client_assertion")

		// BOTH the issuer and the token endpoint are accepted as the audience.
		// Implementations legitimately differ about which to use, and rejecting
		// one breaks real clients for no security gain -- either value names this
		// server and nobody else.
		aud := []string{s.cfg.Issuer, s.cfg.Issuer + "/oauth2/token"}

		a, err := clientauth.VerifyPrivateKeyJWT(assertion, c.ClientID, jwks, aud, time.Now())
		if err != nil {
			return err
		}

		// Replay. The assertion is signed, fresh and correctly addressed -- and
		// still replayable within its lifetime by whoever captured it in a proxy
		// log. Reusing the DPoP proof store, keyed by client id rather than a key
		// thumbprint, because the two namespaces must not collide.
		fresh, err := store.MarkDPoPProofSeen(ctx, s.db, "client:"+c.ClientID, a.JTI,
			clientauth.MaxAssertionLifetime)
		if err != nil {
			// Fail closed: without replay detection the assertion cannot be shown
			// to be fresh.
			return fmt.Errorf("replay detection is unavailable")
		}
		if !fresh {
			return fmt.Errorf("this client assertion has already been used")
		}
		return nil

	case "none":
		// Configured to need nothing. Only reachable for a client somebody
		// deliberately set this way.
		return nil

	default:
		ok, err := s.verifyClientSecret(ctx, c, presentedSecret)
		if err != nil || !ok {
			return fmt.Errorf("the client secret did not match")
		}
		return nil
	}
}
