package httpapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A failure budget on client authentication, without the denial of service a
// per-client budget would create.
//
// # Why this is not a rate limit on /token
//
// `client_credentials` runs at five figures a second on this engine. A limiter
// on the endpoint would throttle legitimate machine traffic and, worse, hand an
// attacker a tenant-wide outage: spend the bucket, and the real integration is
// refused holding a correct secret. The brute-forceable asset is the secret, so
// the budget counts FAILURES and a correct secret is never charged.
//
// # Why the key is (client, address)
//
// A budget keyed on client_id alone is the same outage by another route --
// anybody who knows a client_id can spend it. Keying on the pair means an
// attacker exhausts only their own budget against that client while the real
// deployment, authenticating from its own addresses, is untouched. That
// property is what these tests exist to hold.

func throttleServer(t *testing.T) (*Server, context.Context) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Server{db: pool, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, ctx
}

// THE property: burning one address's budget must not refuse another address.
//
// This is the whole reason the key is a pair. If it regresses to client_id
// alone, an attacker takes a production integration offline by sending wrong
// secrets from anywhere, and the victim is refused while holding the right one.
func TestOneAddressCannotLockOutAnotherAddressForTheSameClient(t *testing.T) {
	s, ctx := throttleServer(t)
	client := fmt.Sprintf("throttle-test-%d", time.Now().UnixNano())

	attacker := httptest.NewRequest("POST", "/oauth2/token", nil)
	attacker.RemoteAddr = "203.0.113.9:5555"
	victim := httptest.NewRequest("POST", "/oauth2/token", nil)
	victim.RemoteAddr = "198.51.100.4:5555"

	// Spend the attacker's budget against this client, and then some.
	for i := 0; i < clientAuthPerPairLimit+5; i++ {
		s.recordClientAuthFailure(ctx, attacker, client)
	}

	if s.clientAuthAllowed(ctx, attacker, client) {
		t.Error("the attacker's own budget was never exhausted, so the control is " +
			"not binding on the source doing the guessing")
	}
	if !s.clientAuthAllowed(ctx, victim, client) {
		t.Fatal("a DIFFERENT address is now refused for the same client. The budget " +
			"has regressed to a per-client key, which means anybody who knows a " +
			"client_id can take that integration offline while it holds a correct " +
			"secret")
	}
}

// A correct secret is never charged, so a busy legitimate client cannot throttle
// itself by succeeding.
func TestSuccessfulClientAuthenticationIsNotCharged(t *testing.T) {
	s, ctx := throttleServer(t)
	client := fmt.Sprintf("throttle-ok-%d", time.Now().UnixNano())

	r := httptest.NewRequest("POST", "/oauth2/token", nil)
	r.RemoteAddr = "192.0.2.7:5555"

	// Far more than the limit, but none of them failures.
	for i := 0; i < clientAuthPerPairLimit*3; i++ {
		if !s.clientAuthAllowed(ctx, r, client) {
			t.Fatalf("refused after %d successful authentications; the budget is "+
				"counting attempts rather than failures, so a high-volume "+
				"client_credentials integration throttles itself", i)
		}
	}
}

// The budget must actually bind on the source that is guessing.
func TestFailuresFromOneSourceAreEventuallyRefused(t *testing.T) {
	s, ctx := throttleServer(t)
	client := fmt.Sprintf("throttle-bind-%d", time.Now().UnixNano())

	r := httptest.NewRequest("POST", "/oauth2/token", nil)
	r.RemoteAddr = "203.0.113.44:5555"

	if !s.clientAuthAllowed(ctx, r, client) {
		t.Fatal("refused before a single failure was recorded")
	}
	for i := 0; i < clientAuthPerPairLimit+1; i++ {
		s.recordClientAuthFailure(ctx, r, client)
	}
	if s.clientAuthAllowed(ctx, r, client) {
		t.Errorf("still allowed after %d failures; the budget does not bind",
			clientAuthPerPairLimit+1)
	}
}

// The throttle must sit at the choke point, not at each endpoint, or a new
// endpoint that authenticates a client inherits nothing.
func TestTheThrottleIsAtTheSingleClientAuthChokePoint(t *testing.T) {
	b, err := os.ReadFile("clientauth.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "func (s *Server) authenticateConfidentialClient") {
		t.Fatal("the choke point is gone; find where clients authenticate now")
	}
	fn := src[strings.Index(src, "func (s *Server) authenticateConfidentialClient"):]
	if e := strings.Index(fn, "\n// Failure budgets"); e > 0 {
		fn = fn[:e]
	}
	if !strings.Contains(fn, "clientAuthAllowed") {
		t.Fatal("authenticateConfidentialClient no longer consults the failure " +
			"budget, so /token, /introspect, /revoke and /par are all unmetered " +
			"against secret guessing")
	}
	if !strings.Contains(fn, "recordClientAuthFailure") {
		t.Fatal("failures are no longer charged, so the budget can never be reached " +
			"and the check above always passes")
	}

	// The charge must be CONDITIONAL on the error.
	//
	// An unconditional call is the "count attempts, not failures" bug wearing the
	// right function name: every successful client_credentials call would spend
	// budget, and a high-volume integration would throttle itself out of its own
	// service. The behavioural test above cannot see this, because it exercises
	// the helper rather than this call site -- which is exactly how the mutation
	// survived when this guard was missing.
	cond := strings.Index(fn, "if err != nil")
	charge := strings.Index(fn, "recordClientAuthFailure")
	if cond < 0 || cond > charge {
		t.Fatal("recordClientAuthFailure is not guarded by an error check, so a " +
			"SUCCESSFUL authentication is charged too. A busy client_credentials " +
			"integration then throttles itself by working correctly")
	}
}
