package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/policy"
	"signari.dev/engine/internal/risk"
	"signari.dev/engine/internal/store"
)

// Access policy evaluation at every way into a relying party.
//
// # Read on every decision
//
// Which document is in force is asked of the database on every decision: one
// indexed row, its digest only. The document is fetched and parsed again only
// when the digest has changed, so the parse is memoised and the decision is not.
//
// It used to be a full reload on a thirty-second timer, undeclared, for a
// document whose rules include `deny: true` -- a security-negative decision,
// which ADR-007 says is never served from a snapshot. A deny rule written to
// shut a client out took up to half a minute to start working on each node, and
// the guard meant to catch undeclared caches matched field names and could not
// see a field called `policies`.
//
// Only a policy that PARSED AND PASSED ITS OWN TESTS is ever used. A stored
// document that fails -- possible only if it was written directly, bypassing
// `policy apply` -- keeps the previous one in force, and with no previous one
// refuses everything: a broken policy must never become an absent policy,
// because "absent" means "allow everything" and that is the one outcome nobody
// would choose deliberately.

type policyCache struct {
	mu    sync.Mutex
	byOrg map[string]policyEntry
}

// policyEntry is the parse of one organisation's document.
type policyEntry struct {
	// digest is md5(document) of the row this entry answers for. A broken
	// document is recorded too, so it is reported once rather than re-parsed
	// and logged on every request.
	digest string
	file   *policy.File
}

func newPolicyCache() *policyCache {
	return &policyCache{byOrg: map[string]policyEntry{}}
}

// refuseEverything stands in for a policy that will not load and has no
// predecessor.
var refuseEverything = &policy.File{Version: 1, Default: "deny"}

// policyFor returns the policy in force for an organisation, as it is in the
// database now.
func (s *Server) policyFor(ctx context.Context, q dbReader, orgID string) *policy.File {
	s.policies.mu.Lock()
	cached, have := s.policies.byOrg[orgID]
	s.policies.mu.Unlock()

	// The document travels only when it differs from the one already parsed.
	var digest string
	var doc *string
	err := q.QueryRow(ctx, `
		SELECT md5(document), CASE WHEN md5(document) = $2 THEN NULL ELSE document END
		  FROM core.access_policies WHERE org_id = $1::uuid`, orgID, cached.digest).
		Scan(&digest, &doc)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		s.policies.mu.Lock()
		delete(s.policies.byOrg, orgID)
		s.policies.mu.Unlock()
		return nil
	case err != nil:
		// The database could not say. The last answer it gave is the best
		// available; the request this decision belongs to needs the same
		// database a moment later and is unlikely to get further.
		s.log.Error("reading the access policy", "org_id", orgID, "err", err)
		if have {
			return cached.file
		}
		return refuseEverything
	case have && digest == cached.digest, doc == nil:
		// Unchanged. (The document is NULL exactly when its digest is the one
		// asked about, computed in the same statement.)
		return cached.file
	}

	entry := policyEntry{digest: digest}
	f, perr := policy.Parse([]byte(*doc))
	switch {
	case perr == nil:
		entry.file = f
	case have:
		s.log.Error("the stored access policy will not load; keeping the previous one",
			"org_id", orgID, "err", perr)
		entry.file = cached.file
	default:
		s.log.Error("the stored access policy will not load and there is no previous one; "+
			"refusing every authorization in this organisation until it is fixed",
			"org_id", orgID, "err", perr)
		entry.file = refuseEverything
	}
	s.policies.mu.Lock()
	s.policies.byOrg[orgID] = entry
	s.policies.mu.Unlock()
	return entry.file
}

// checkAccessPolicy evaluates the policy for one authorization.
//
// Returns nil when access is permitted, or a message for the person refused.
//
// r is the person's own request. It is nil at a refresh-token grant, where the
// request is the application's server's and carries nothing about where the
// person is: the decision is then made as policy.Request.Refresh describes.
func (s *Server) checkAccessPolicy(ctx context.Context, r *http.Request,
	orgID, clientID, userID, scope string, mfa bool, amr []string) *policy.Decision {
	return s.checkAccessPolicyIn(ctx, s.db, r, orgID, clientID, userID, scope, mfa, amr)
}

// dbReader is a pool or a transaction.
type dbReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// checkAccessPolicyIn is checkAccessPolicy reading through q, for a caller that
// holds a transaction: the refresh grant asks while holding one, and reading
// the policy and the memberships from the pool there took a second connection,
// which deadlocks the pool under concurrent refreshes.
func (s *Server) checkAccessPolicyIn(ctx context.Context, q dbReader, r *http.Request,
	orgID, clientID, userID, scope string, mfa bool, amr []string) *policy.Decision {

	f := s.policyFor(ctx, q, orgID)
	if f == nil {
		return nil
	}

	// Groups read fresh, like every other authorization decision that depends on
	// them. A policy consulting a cached membership would enforce yesterday's
	// answer.
	groups, err := store.AllGroupsForUser(ctx, q, userID)
	if err != nil {
		s.log.Error("reading groups for a policy decision", "err", err)
		// Fail CLOSED only when a policy exists: we cannot evaluate a rule that
		// depends on membership, and guessing "not a member" would deny while
		// guessing "a member" would grant. Refusing is the honest answer.
		return &policy.Decision{Allowed: false, Rule: "(internal)",
			Message: "Access could not be checked. Please try again."}
	}

	req := policy.Request{
		Client: clientID, Scope: scope, Groups: groups, MFA: mfa, AMR: amr,
		Refresh: r == nil,
	}
	if r != nil {
		req.IP = clientIP(r)

		// The travel check runs only when a policy actually asks about it.
		// Resolving a position and querying history on every authorization
		// would be work done for nothing in the deployments -- most of them --
		// whose policy never mentions it.
		if f.UsesImpossibleTravel() {
			req.ImpossibleTravel = s.impossibleTravel(ctx, userID, req.IP)
		}

		// Device posture, likewise only when a rule asks. Evaluating it always
		// would verify a certificate chain on every authorization for the
		// deployments -- most of them -- whose policy never mentions a device.
		if f.UsesDevicePosture() {
			device := s.posture.Evaluate(r)
			s.log.Debug("device posture", "managed", device.Managed,
				"compliant", device.Compliant, "source", device.Source)
			req.DeviceManaged, req.DeviceCompliant = device.Managed, device.Compliant
		}
	}

	d := f.Evaluate(req)
	if d.Allowed {
		return nil
	}
	return &d
}

// clientIP extracts the caller's address for a network condition or a budget.
//
// From r.RemoteAddr, which withClientIP has already resolved: the socket, or,
// behind a proxy the operator named in SIGNARI_TRUSTED_PROXIES, the rightmost
// hop of the forwarding chain that is not one of those proxies. Never a header
// read here. A header any caller can set is not a location, and honouring it
// would let anybody claim to be inside the office network, or spend somebody
// else's budget, by adding one line to their request.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// sessionHasMFA reports whether the session was established with more than one
// factor.
//
// Read from the session's recorded acr/amr rather than inferred, and read at
// decision time: a step-up that happened moments ago must count, and a policy
// consulting a value captured at login would miss it.
// sessionFactors reports what a session actually proved.
//
// Returns the amr list as well as the boolean, because a policy can now ask
// about specific factors -- `phishing_resistant: true` and `factors_any_of`
// exist precisely so a weak factor like SMS cannot silently satisfy a rule
// written for a strong one. A caller given only the boolean could not tell the
// difference, which is the state this was in when SMS was added.
func sessionFactors(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, sid string) (bool, []string) {
	var amr []string
	if err := db.QueryRow(ctx,
		`SELECT amr FROM core.sessions WHERE sid = $1`, sid).Scan(&amr); err != nil {
		// Unknown means NOT multi-factor, and no factors. Guessing the other way
		// would satisfy an MFA requirement for a session we could not read.
		return false, nil
	}
	// The one predicate (oauth.IsMultiFactor), derived from the methods used
	// and never from a stored acr. This used to accept any single possession
	// factor, so a passkey with no user verification satisfied a policy that
	// requires MFA.
	return oauth.IsMultiFactor(amr), amr
}

// grantRefusedByPolicy asks, for a grant that issues a token for a person
// without a sign-in in front of it, the question /authorize asks before a code
// exists: is this person in this client's organisation, and does the access
// policy let them reach it. It writes the refusal and reports true when the
// answer is no.
//
// The token-exchange, jwt-bearer, UMA and pre-authorized code grants issued
// with neither question asked, so an operator's deny rule on a client was
// honoured at its sign-in page and nowhere a token could be got without one.
// The factors are those of the session behind the token when there is one,
// and none otherwise: a rule that demands MFA is not met by a grant that
// proved nothing.
//
// Called before the grant opens a transaction (guard 0.08e), and listed by
// name in TestEveryIssuingPathAsksTheAccessPolicy as an asking function.
func (s *Server) grantRefusedByPolicy(w http.ResponseWriter, r *http.Request, orgID, clientID,
	userID, sid, scope, via string) bool {

	ctx := r.Context()
	var userOrg string
	if err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id::text = $1`,
		userID).Scan(&userOrg); err != nil || userOrg != orgID {
		s.log.Info("a grant named a person outside the client's organisation",
			"client_id", clientID, "via", via, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "this grant does not name a person this client may act for",
			Status:      http.StatusBadRequest})
		return true
	}

	mfa, amr := false, []string(nil)
	if sid != "" {
		mfa, amr = sessionFactors(ctx, s.db, sid)
	}
	// No request, as for a refresh: who the person is, not where they are.
	// These calls come from a server or a wallet, and its address and its lack
	// of a device certificate say nothing about the person.
	pd := s.checkAccessPolicy(ctx, nil, orgID, clientID, userID, scope, mfa, amr)
	if pd == nil {
		return false
	}
	s.log.Info("access refused by policy", "client_id", clientID, "via", via,
		"rule", pd.Rule, "correlation_id", correlationID(ctx))
	s.auditDetached(ctx, audit.Event{
		Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID, ClientID: clientID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"reason": "access_policy", "rule": pd.Rule, "via": via},
	})
	writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
		Description: "the access policy does not allow this: " + pd.Message,
		Status:      http.StatusBadRequest})
	return true
}

// impossibleTravel reports whether this sign-in could not have followed the
// previous one.
//
// False when the check could not run -- no GeoIP database, no history, or two
// sign-ins too close together. That is the honest answer and the safe one: a
// signal that fails closed when it cannot be evaluated locks out every
// first-time user.
func (s *Server) impossibleTravel(ctx context.Context, userID, ip string) bool {
	previous, err := store.PreviousAuthLocation(ctx, s.db, userID)
	if err != nil {
		s.log.Error("reading the previous sign-in location", "err", err)
		return false
	}
	current := s.geo.Resolve(ip)
	current.At = time.Now()

	v := risk.CheckTravel(previous, current)
	if v.Impossible {
		s.log.Warn("impossible travel", "user_id", userID, "reason", v.Reason,
			"correlation_id", correlationID(ctx))
	}
	return v.Impossible
}
