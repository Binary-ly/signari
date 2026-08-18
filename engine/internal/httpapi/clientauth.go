package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"signari.dev/engine/internal/abca"
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

	// Mutual-TLS first: a client registered for it authenticates by the
	// certificate on the connection, not by anything in the body. Checked before
	// the stored method because the expectation lives on the client row rather
	// than in client_auth_methods, and because a client that presents a
	// certificate should never fall through to a secret comparison.
	if exp := c.TLSExpectation(); exp.Configured() {
		if err := clientauth.VerifyClientCertificate(r.TLS, exp, s.clientCAs); err != nil {
			return fmt.Errorf("mutual-TLS client authentication failed: %w", err)
		}
		return nil
	}

	switch method {
	case "private_key_jwt":
		assertionType := r.PostFormValue("client_assertion_type")
		if assertionType != clientauth.AssertionType {
			return fmt.Errorf("this client authenticates with private_key_jwt; "+
				"client_assertion_type must be %q", clientauth.AssertionType)
		}
		assertion := r.PostFormValue("client_assertion")

		// Accepted audiences: the issuer, the token endpoint, and THE ENDPOINT
		// BEING CALLED.
		//
		// The last one was missing and it broke PAR outright -- a client
		// authenticating at /oauth2/par naturally addresses its assertion to
		// /oauth2/par, and the list only knew about the token endpoint. Every
		// value here names this server and nobody else, which is what the
		// audience check is for; being strict about WHICH of our own URLs was
		// used buys nothing and breaks real clients.
		aud := []string{
			s.cfg.Issuer,
			s.cfg.Issuer + "/oauth2/token",
			s.cfg.Issuer + r.URL.Path,
		}

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

	case abca.MethodPoP:
		// Attestation-Based Client Authentication, §7.5. Placed here rather than
		// before the switch because it IS a client authentication method, chosen
		// per client like private_key_jwt -- unlike mutual TLS above, which is a
		// property of the connection.
		return s.authenticateWithAttestation(ctx, r, c)

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
