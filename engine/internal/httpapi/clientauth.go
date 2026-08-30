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
	c *clients.Client, presentedSecret string) (err error) {

	// A failure budget, checked here because this is the ONE place a confidential
	// client proves itself -- /token, /introspect, /revoke and /par all arrive
	// through it, so a new endpoint cannot forget the control.
	//
	// Deliberately NOT a rate limit on those endpoints. `client_credentials` runs
	// at five figures a second on this engine, so a limiter on the endpoint would
	// throttle legitimate machine traffic and hand an attacker a tenant-wide
	// denial of service: burn the bucket, lock the integration out. The
	// brute-forceable asset here is the secret, not the endpoint, so the budget
	// counts FAILURES and a correct secret is never charged.
	if !s.clientAuthAllowed(ctx, r, c.ClientID) {
		return fmt.Errorf("too many failed client authentications; try again shortly")
	}
	defer func() {
		if err != nil {
			s.recordClientAuthFailure(ctx, r, c.ClientID)
		}
	}()

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

// Failure budgets for client authentication.
//
// # Why the key is (client, address) and not the client alone
//
// A per-client budget is a way to take somebody's integration offline on
// purpose: send wrong secrets for their client_id until the budget is spent, and
// the real service is refused with a correct secret. For a human account this
// codebase accepts that tradeoff deliberately -- fifteen minutes of slower
// sign-in beats an account needing an administrator. A machine integration is
// different: it has no human to notice, and the failure is a production outage
// rather than an inconvenience.
//
// Keying on the pair removes the cross-tenant attack entirely. An attacker
// grinding from one address exhausts only their own budget against that client,
// while a legitimate deployment authenticating from its own addresses is
// untouched however much noise anyone else makes.
//
// What this does not bound is guessing distributed across many addresses. That
// is the accepted residual, and it is acceptable because the secret is 256 bits
// of random data -- distributed guessing does not become feasible by being
// distributed. The budget exists to bound CPU spent on failed comparisons and to
// catch a weak secret carried in from a migration, not to be the thing standing
// between an attacker and a correctly generated secret.
const (
	clientAuthPerPairLimit  = 50
	clientAuthPerPairWindow = 10 * time.Minute

	// A second, wider key on the address alone, so one source cannot sweep many
	// client_ids cheaply. Generous, because a shared NAT egress may legitimately
	// carry several failing integrations at once.
	clientAuthPerIPLimit  = 200
	clientAuthPerIPWindow = 10 * time.Minute
)

// clientAuthAllowed reports whether this address may attempt this client again.
//
// Reads only. The budget is charged in recordClientAuthFailure, so a correct
// secret costs nothing and a busy legitimate client is never throttled by its
// own success.
func (s *Server) clientAuthAllowed(ctx context.Context, r *http.Request, clientID string) bool {
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}

	pair, err := store.CountRate(ctx, s.db,
		"clientauth:fail:pair:"+clientID+":"+ip, clientAuthPerPairWindow)
	if err != nil {
		// Fail closed, for the reason allowSignInAttempt gives: authenticating a
		// client needs the database one query later anyway, so refusing here costs
		// nothing that was going to work, and failing open turns a database blip
		// into an unlimited guessing window.
		s.log.Error("checking the client authentication rate limit", "err", err)
		return false
	}
	if pair >= clientAuthPerPairLimit {
		return false
	}

	byIP, err := store.CountRate(ctx, s.db, "clientauth:fail:ip:"+ip, clientAuthPerIPWindow)
	if err != nil {
		s.log.Error("checking the client authentication rate limit", "err", err)
		return false
	}
	return byIP < clientAuthPerIPLimit
}

// recordClientAuthFailure charges both budgets. Called only when the proof was
// actually wrong.
func (s *Server) recordClientAuthFailure(ctx context.Context, r *http.Request, clientID string) {
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	if _, err := store.AllowRate(ctx, s.db, "clientauth:fail:pair:"+clientID+":"+ip,
		clientAuthPerPairLimit, clientAuthPerPairWindow); err != nil {
		s.log.Error("recording a client authentication failure", "err", err)
	}
	if _, err := store.AllowRate(ctx, s.db, "clientauth:fail:ip:"+ip,
		clientAuthPerIPLimit, clientAuthPerIPWindow); err != nil {
		s.log.Error("recording a client authentication failure", "err", err)
	}
}
