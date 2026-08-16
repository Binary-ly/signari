package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/policy"
	"signari.dev/engine/internal/posture"
	"signari.dev/engine/internal/risk"
	"signari.dev/engine/internal/store"
)

// Access policy evaluation at the authorization endpoint.
//
// # Loaded, cached, and re-checked
//
// The policy is read from the database and held in memory, because it is
// consulted on every authorization and a query there is a query on the login
// path. It is refreshed on a timer rather than per request.
//
// The cache holds only a policy that PARSED AND PASSED ITS OWN TESTS. A file
// that fails is refused at load and the previous one stays in force -- a broken
// policy must never become an absent policy, because "absent" means "allow
// everything" and that is the one outcome nobody would choose deliberately.

type policyCache struct {
	mu       sync.RWMutex
	byOrg    map[string]*policy.File
	loadedAt time.Time
}

const policyRefresh = 30 * time.Second

func newPolicyCache() *policyCache {
	return &policyCache{byOrg: map[string]*policy.File{}}
}

// policyFor returns the policy in force, refreshing if stale.
func (s *Server) policyFor(ctx context.Context, orgID string) *policy.File {
	s.policies.mu.RLock()
	fresh := time.Since(s.policies.loadedAt) < policyRefresh
	f := s.policies.byOrg[orgID]
	s.policies.mu.RUnlock()
	if fresh {
		return f
	}
	s.reloadPolicies(ctx)

	s.policies.mu.RLock()
	defer s.policies.mu.RUnlock()
	return s.policies.byOrg[orgID]
}

func (s *Server) reloadPolicies(ctx context.Context) {
	rows, err := s.db.Query(ctx, `SELECT org_id::text, document FROM core.access_policies`)
	if err != nil {
		s.log.Error("loading access policies", "err", err)
		return
	}
	defer rows.Close()

	loaded := map[string]*policy.File{}
	for rows.Next() {
		var orgID, doc string
		if err := rows.Scan(&orgID, &doc); err != nil {
			continue
		}
		f, perr := policy.Parse([]byte(doc))
		if perr != nil {
			// The stored document no longer passes its own tests -- which can only
			// happen if it was written directly to the database, bypassing
			// `policy apply`. Logged loudly and the PREVIOUS policy kept: dropping
			// it would silently widen access.
			s.log.Error("the stored access policy will not load; keeping the previous one",
				"org_id", orgID, "err", perr)
			s.policies.mu.RLock()
			if prev := s.policies.byOrg[orgID]; prev != nil {
				loaded[orgID] = prev
			}
			s.policies.mu.RUnlock()
			continue
		}
		loaded[orgID] = f
	}

	s.policies.mu.Lock()
	s.policies.byOrg = loaded
	s.policies.loadedAt = time.Now()
	s.policies.mu.Unlock()
}

// checkAccessPolicy evaluates the policy for one authorization.
//
// Returns nil when access is permitted, or a message for the person refused.
func (s *Server) checkAccessPolicy(ctx context.Context, r *http.Request,
	orgID, clientID, userID, scope string, mfa bool, amr []string) *policy.Decision {

	f := s.policyFor(ctx, orgID)
	if f == nil {
		return nil
	}

	// Groups read fresh, like every other authorization decision that depends on
	// them. A policy consulting a cached membership would enforce yesterday's
	// answer.
	groups, err := store.AllGroupsForUser(ctx, s.db, userID)
	if err != nil {
		s.log.Error("reading groups for a policy decision", "err", err)
		// Fail CLOSED only when a policy exists: we cannot evaluate a rule that
		// depends on membership, and guessing "not a member" would deny while
		// guessing "a member" would grant. Refusing is the honest answer.
		return &policy.Decision{Allowed: false, Rule: "(internal)",
			Message: "Access could not be checked. Please try again."}
	}

	// The travel check runs only when a policy actually asks about it. Resolving
	// a position and querying history on every authorization would be work done
	// for nothing in the deployments -- most of them -- whose policy never
	// mentions it.
	impossible := false
	if f.UsesImpossibleTravel() {
		impossible = s.impossibleTravel(ctx, userID, clientIP(r))
	}

	// Device posture, likewise only when a rule asks. Evaluating it always would
	// verify a certificate chain on every authorization for the deployments --
	// most of them -- whose policy never mentions a device.
	var device posture.State
	if f.UsesDevicePosture() {
		device = s.posture.Evaluate(r)
		s.log.Debug("device posture", "managed", device.Managed,
			"compliant", device.Compliant, "source", device.Source)
	}

	d := f.Evaluate(policy.Request{
		Client: clientID, Scope: scope, Groups: groups, MFA: mfa, AMR: amr,
		IP: clientIP(r), ImpossibleTravel: impossible,
		DeviceManaged: device.Managed, DeviceCompliant: device.Compliant,
	})
	if d.Allowed {
		return nil
	}
	return &d
}

// clientIP extracts the caller's address for a network condition.
//
// From the socket, NOT from X-Forwarded-For. A header any caller can set is not
// a location -- honouring it would let anybody claim to be inside the office
// network by adding one line to their request. Deployments behind a proxy need
// the proxy to be trusted and the address taken from a configured position in
// the chain, which is a decision an operator has to make explicitly rather than
// something to guess at here.
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
	var acr string
	var amr []string
	if err := db.QueryRow(ctx,
		`SELECT acr, amr FROM core.sessions WHERE sid = $1`, sid).Scan(&acr, &amr); err != nil {
		// Unknown means NOT multi-factor, and no factors. Guessing the other way
		// would satisfy an MFA requirement for a session we could not read.
		return false, nil
	}
	for _, m := range amr {
		switch m {
		case oauth.AMROTP, oauth.AMRHardwareKey, oauth.AMRMFA, oauth.AMRSMS:
			return true, amr
		}
	}
	return acr == oauth.ACRMultiFactor || acr == oauth.ACRPapeMultiFactor, amr
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
