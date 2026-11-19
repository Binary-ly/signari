package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
	// at thousands a second on this engine (3.4k measured with two workers; this
	// once claimed five figures), so a limiter on the endpoint would
	// throttle legitimate machine traffic and hand an attacker a tenant-wide
	// denial of service: burn the bucket, lock the integration out. The
	// brute-forceable asset here is the secret, not the endpoint, so the budget
	// counts FAILURES and a correct secret is never charged.
	if !s.clientAuthAllowed(ctx, r, c.ClientID) {
		return fmt.Errorf("too many failed client authentications; try again shortly")
	}
	// Counted by mechanism (signari_auth_failures_total), which was declared
	// and incremented nowhere: a guessing run against client secrets was
	// visible only in the audit trail.
	mechanism := "client_secret"
	defer func() {
		if err != nil {
			s.recordClientAuthFailure(ctx, r, c.ClientID)
			if s.metrics != nil {
				s.metrics.AuthFailures.Inc(mechanism)
			}
		}
	}()

	// Mutual-TLS first: a client registered for it authenticates by the
	// certificate on the connection, not by anything in the body. Checked before
	// the stored method because the expectation lives on the client row rather
	// than in client_auth_methods, and because a client that presents a
	// certificate should never fall through to a secret comparison.
	if exp := c.TLSExpectation(); exp.Configured() {
		mechanism = "client_certificate"
		if err := clientauth.VerifyClientCertificate(r.TLS, exp, s.clientCAs); err != nil {
			return fmt.Errorf("mutual-TLS client authentication failed: %w", err)
		}
		return nil
	}

	switch c.TokenEndpointAuthMethod {
	case "private_key_jwt":
		mechanism = "client_assertion"
		assertionType := r.PostFormValue("client_assertion_type")
		if assertionType != clientauth.AssertionType {
			return fmt.Errorf("this client authenticates with private_key_jwt; "+
				"client_assertion_type must be %q", clientauth.AssertionType)
		}
		assertion := r.PostFormValue("client_assertion")
		jwks, err := store.ClientJWKS(ctx, s.db, c.ClientID)
		if err != nil {
			return fmt.Errorf("reading the client's keys: %w", err)
		}

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
		// FAPI 2.0 §5.3.2.1: "shall only accept its issuer identifier value ... as
		// a string in the aud claim received in client authentication assertions",
		// which is the leniency above taken away, and §5.4.1's algorithms.
		if c.FAPI2() && (a.Audience != s.cfg.Issuer || !slices.Contains(clients.FAPI2Algorithms, a.Algorithm)) {
			return fmt.Errorf("a client held to FAPI 2.0 addresses its assertion to the issuer alone, "+
				"as a string, and signs it with %s", strings.Join(clients.FAPI2Algorithms, ", "))
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
		mechanism = "client_assertion"
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

	// Read with the client, in the same round trip, when the endpoint asked for both
	// (lookupClientToAuthenticate); the same counters, read on this request either way.
	var spent []int
	var err error
	if b, ok := ctx.Value(clientAuthBudgetKey{}).(*clientAuthBudget); ok && b.clientID == clientID && b.ip == ip {
		spent, err = b.spent, b.err
	} else {
		spent, err = store.CountRates(ctx, s.db, clientAuthWindows(clientID, ip)...)
	}
	if err != nil {
		// Fail closed, for the reason allowSignInAttempt gives: authenticating a
		// client needs the database one query later anyway, so refusing here costs
		// nothing that was going to work, and failing open turns a database blip
		// into an unlimited guessing window.
		s.log.ErrorContext(ctx, "checking the client authentication rate limit", "err", err)
		return false
	}
	return spent[0] < clientAuthPerPairLimit && spent[1] < clientAuthPerIPLimit
}

// clientAuthWindows are the two failure budgets a client authenticates under: this
// client from this address, and this address for every client.
func clientAuthWindows(clientID, ip string) []store.RateWindow {
	return []store.RateWindow{
		{Key: "clientauth:fail:pair:" + clientID + ":" + budgetIP(ip), Window: clientAuthPerPairWindow},
		{Key: "clientauth:fail:ip:" + budgetIP(ip), Window: clientAuthPerIPWindow},
	}
}

type clientAuthBudgetKey struct{}

// clientAuthBudget is the failure counters read alongside a client, for the client and
// address they were read for.
type clientAuthBudget struct {
	clientID, ip string
	spent        []int
	err          error
}

// lookupClientToAuthenticate is lookupClient for an endpoint about to authenticate the
// client, with that authentication's failure counters read in the same round trip (E.23):
// the client and the counters were two, one after the other, on every client-authenticated
// request. Every refusal lookupClient makes is made here alike, and the counters are read
// on this request, as before, so a guess is still counted the moment it is made.
func (s *Server) lookupClientToAuthenticate(ctx context.Context, r *http.Request, clientID string) (
	context.Context, *clients.Client, error) {
	if clientID == "" {
		return ctx, nil, clients.ErrNotFound
	}
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	var b pgx.Batch
	client := clients.QueueLookup(&b, clientID)
	counts := store.QueueCountRates(&b, clientAuthWindows(clientID, ip)...)
	if also, ok := ctx.Value(alsoInBatchKey{}).(func(*pgx.Batch)); ok {
		also(&b)
	}
	if err := s.db.SendBatch(ctx, &b).Close(); err != nil {
		return ctx, nil, err
	}
	spent, cerr := counts()
	ctx = context.WithValue(ctx, clientAuthBudgetKey{}, &clientAuthBudget{clientID: clientID, ip: ip, spent: spent, err: cerr})
	c, err := client()
	if err != nil {
		return ctx, nil, err
	}
	c, err = s.servedClient(ctx, c)
	return ctx, c, err
}

// alsoInBatchKey carries a read that depends on the request alone, for the round trip that
// finds the client to ask it too (E.23). It must change nothing: the client has not
// authenticated when it is asked, and its answer is used only once the client has.
type alsoInBatchKey struct{}

func withAlsoInBatch(ctx context.Context, queue func(*pgx.Batch)) context.Context {
	return context.WithValue(ctx, alsoInBatchKey{}, queue)
}

// recordClientAuthFailure charges both budgets. Called only when the proof was
// actually wrong.
func (s *Server) recordClientAuthFailure(ctx context.Context, r *http.Request, clientID string) {
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	if _, err := store.AllowRate(ctx, s.db, "clientauth:fail:pair:"+clientID+":"+budgetIP(ip),
		clientAuthPerPairLimit, clientAuthPerPairWindow); err != nil {
		s.log.ErrorContext(ctx, "recording a client authentication failure", "err", err)
	}
	if _, err := store.AllowRate(ctx, s.db, "clientauth:fail:ip:"+budgetIP(ip),
		clientAuthPerIPLimit, clientAuthPerIPWindow); err != nil {
		s.log.ErrorContext(ctx, "recording a client authentication failure", "err", err)
	}
}
