package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// LDAPAuthenticator connects the LDAP shim to the real credential path.
//
// It deliberately does NOT verify passwords itself. Every bind goes through the
// same store lookup and the same Argon2 verifier as the sign-in form, so an
// LDAP bind is throttled and audited like any other authentication. An LDAP
// front end with its own quiet credential path is a way around every control
// the rest of the product has.
//
// That sentence has twice been aspirational, and both halves were found rather
// than remembered:
//
//   - It promised an audit write that did not exist. Fixed; see `audit` below.
//   - It promised throttling that did not exist either. Nothing on this path
//     consulted a limiter, so the LDAP port was an unmetered guessing oracle
//     against every account while the sign-in form next to it was capped at 30
//     failures per quarter hour. Fixed; see `reserveBind` below.
//
// It also claimed a "lockout". There is no lockout anywhere in the product --
// sign-in uses expiring rate limits precisely so nobody can be locked out on
// purpose (`server.go`, signInPerAccountLimit) -- so that word is gone rather
// than implemented.
type LDAPAuthenticator struct {
	db     *pgxpool.Pool
	hasher *passwords.Hasher
	orgID  string
	log    *slog.Logger
	// via labels the audit trail with the network path the credential arrived
	// on. RADIUS delegates to this type, so without it every Access-Accept
	// would be recorded as an LDAP bind -- and an investigation asking "how did
	// this account authenticate" would be told the wrong answer confidently.
	via string
	// demandsMFA answers whether the sign-in flow would ask this person for a
	// second factor after a password (Server.BindDemandsMFA). nil falls back to
	// whether they have one enrolled, which is the built-in flow's answer and
	// misses only an operator's unconditional mfa stage.
	demandsMFA MFAGate
}

// MFAGate reports whether the sign-in flow would demand a second factor of a
// person who has proved only a password.
type MFAGate func(ctx context.Context, orgID, userID string) (bool, error)

func NewLDAPAuthenticator(db *pgxpool.Pool, hasher *passwords.Hasher, orgID string,
	log *slog.Logger) *LDAPAuthenticator {
	if log == nil {
		log = slog.Default()
	}
	return &LDAPAuthenticator{db: db, hasher: hasher, orgID: orgID, log: log, via: "ldap"}
}

// WithMFAGate supplies the flow's answer to "would this person be asked for a
// second factor", so an organisation that refuses password-only binds refuses
// exactly the people its sign-in page would challenge.
func (a *LDAPAuthenticator) WithMFAGate(g MFAGate) *LDAPAuthenticator {
	c := *a
	c.demandsMFA = g
	return &c
}

// errMFARequired is a correct password the organisation will not accept alone.
// Answered as a refusal like any other -- the protocol layer collapses it into
// invalid credentials -- and deliberately not errLDAPInvalid, so it is not
// charged to the guessing budget: the password was right, and charging it would
// let a VPN client retrying in a loop spend the person's budget at the sign-in
// page too.
var errMFARequired = errors.New("a second factor is required and this protocol cannot carry one")

// refusesPasswordOnly applies core.organizations.password_only_binds (0128).
func (a *LDAPAuthenticator) refusesPasswordOnly(ctx context.Context, orgID, userID string) (bool, error) {
	refuses, err := store.RefusesPasswordOnlyBinds(ctx, a.db, orgID)
	if err != nil || !refuses {
		return false, err
	}
	if a.demandsMFA != nil {
		return a.demandsMFA(ctx, orgID, userID)
	}
	return store.HasSecondFactor(ctx, a.db, userID)
}

// withVia returns a copy labelling its audit events differently.
func (a *LDAPAuthenticator) withVia(via string) *LDAPAuthenticator {
	c := *a
	c.via = via
	return &c
}

// audit writes one authentication outcome to the append-only trail.
//
// # Why this exists
//
// The comment above this type claimed an LDAP bind was "throttled, audited and
// subject to the same lockout as any other authentication". Two of those three
// were true. Nothing on this path wrote an audit event, so every bind -- the
// successful ones included -- was invisible to `signari export audit` and to
// anyone asking how an account authenticated on a given day.
//
// It was found by an unused `userID`: the query fetched the id and nothing
// consumed it, because the write that would have consumed it was never
// written.
//
// Detached from the caller's transaction on purpose. An LDAP bind has no
// surrounding transaction to join, and a failure to record must not turn a
// correct authentication decision into an error -- the decision is already
// made by the time this runs.
func (a *LDAPAuthenticator) audit(ctx context.Context, e audit.Event) {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		a.log.Error("auditing an LDAP bind", "event", e.Type, "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.Write(ctx, tx, e); err != nil {
		a.log.Error("auditing an LDAP bind", "event", e.Type, "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		a.log.Error("committing an LDAP bind audit", "event", e.Type, "err", err)
	}
}

var errLDAPInvalid = errors.New("invalid credentials")

// reserveBind takes this bind's place in both failure budgets before anything
// expensive happens, or refuses it.
//
// # The buckets are the sign-in form's, deliberately
//
// `signin:fail:ip:` and `signin:fail:user:` -- the exact keys
// `allowSignInAttempt` uses -- rather than an `ldap:` namespace of its own.
//
// A separate namespace was the obvious implementation and it is the wrong one.
// It would have given an attacker a second full allowance per account: thirty
// guesses at the form, then thirty more at the port, for sixty against a budget
// documented as thirty. Two doors onto one credential must draw down one
// budget, or the budget describes neither door.
//
// # Reserved first, kept only for a failure
//
// The budgets used to be read here and charged after the Argon2 verification.
// Every bind that arrived while others were being verified read a count below
// the limit, so a parallel burst was hashed in full before the first failure
// was counted: a counter, not a control. The place is now taken first
// (store.ReserveRate, which does not count a caller it refuses) and handed
// back by Authenticate for anything but a wrong credential, so a correct bind
// still costs nothing. Charging successes would take out a mail server or a
// VPN concentrator, which bind on every request, within a minute of a busy
// morning.
//
// Kept for an unknown username as for a known one. Charging only for users
// that exist would make the counter itself an enumeration oracle.
func (a *LDAPAuthenticator) reserveBind(ctx context.Context, identifier string) ([]store.Reservation, error) {
	var held []store.Reservation
	refuse := func(err error) ([]store.Reservation, error) {
		if err != nil {
			// Fail closed. The credential lookup needs the same database, so
			// refusing costs nothing that was going to succeed, and failing open
			// would turn a database blip into an unmetered guessing window on
			// the one port with no human in front of it.
			a.log.Error("reserving against the LDAP bind rate limit", "err", err)
		}
		a.release(ctx, held)
		return nil, ldapd.ErrBusy
	}
	// From the socket, never from the request. The peer is the one thing on an
	// LDAP bind an attacker cannot choose.
	if ip := ldapd.PeerAddr(ctx); ip != "" {
		r, ok, err := store.ReserveRate(ctx, a.db, "signin:fail:ip:"+ip, signInPerIPLimit, signInPerIPWindow)
		if err != nil || !ok {
			return refuse(err)
		}
		held = append(held, r)
	}
	// Lowercased to match the form's key exactly. Without it Alice@example.com
	// and alice@example.com would be two budgets on one account, and the LDAP
	// port would hand out a fresh one per spelling.
	if identifier = strings.ToLower(strings.TrimSpace(identifier)); identifier != "" {
		r, ok, err := store.ReserveRate(ctx, a.db, "signin:fail:user:"+identifier,
			signInPerAccountLimit, signInPerAccountWindow)
		if err != nil || !ok {
			return refuse(err)
		}
		held = append(held, r)
	}
	return held, nil
}

// release hands reserved places back. On a context of its own: a bind that ran
// out of time must still return its place, or a slow hasher would charge
// correct binds as failures.
func (a *LDAPAuthenticator) release(ctx context.Context, held []store.Reservation) {
	ctx = context.WithoutCancel(ctx)
	for _, r := range held {
		if err := r.Release(ctx, a.db); err != nil {
			a.log.Error("releasing an LDAP bind reservation", "err", err)
		}
	}
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (_ *ldapd.Identity, err error) {
	// Before the lookup and before the hash: the point of a guessing budget is
	// to stop spending Argon2 on an attacker. A refusal is not counted
	// (ReserveRate), so a client's own retries cannot extend it into the
	// permanent lockout this product deliberately does not have.
	held, rerr := a.reserveBind(ctx, username)
	if rerr != nil {
		a.audit(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: a.orgID,
			Detail: map[string]any{"via": a.via, "reason": "rate_limited"},
		})
		return nil, rerr
	}
	// Kept once, at the single exit, rather than at each of the returns that
	// deny a bind: a new denial branch inherits it, where a call at each site
	// is one somebody adds a branch without. Kept for errLDAPInvalid exactly.
	// Anything else hands the place back: a correct bind; errMFARequired, a
	// right password the organisation will not take alone; and a database error
	// or a timeout, which are our failures, and spending a real user's budget
	// for them would let a five-minute outage deny sign-in for fifteen more.
	defer func() {
		if !errors.Is(err, errLDAPInvalid) {
			a.release(ctx, held)
		}
	}()

	// Belt and braces. The protocol layer refuses an empty password before
	// reaching here (RFC 4513 unauthenticated bind), and this is the second
	// place that would have to fail for one to get through.
	if password == "" {
		return nil, errLDAPInvalid
	}

	// The same query the sign-in form uses, including its status check: a
	// deactivated account must not be able to bind, and duplicating the rule
	// here is how the two paths drift apart.
	// In the listener's organisation, in the query. It used to match the name in
	// every organisation and then refuse a row from the wrong one -- so when two
	// tenants held the same user name, QueryRow picked one of them and the right
	// person's bind failed whenever it picked the other. An empty orgID (a test
	// fixture) matches any.
	var userID, orgID, hash string
	err = a.db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text, pc.hash
		FROM core.users u
		JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status = 'active' AND pc.is_current
		  AND ($2 = '' OR u.org_id::text = $2)
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))`,
		username, a.orgID).Scan(&userID, &orgID, &hash)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("looking up the credential: %w", err)
	}
	if !found || (a.orgID != "" && orgID != a.orgID) {
		// The dummy verify keeps the timing of "no such user" indistinguishable
		// from "wrong password". Skipping it here would make the LDAP port a
		// user-enumeration oracle by stopwatch even though the error text is
		// identical.
		_, _ = a.hasher.Verify(ctx, dummyHash, password)
		// No subject: there is nobody to name. The event still records that a
		// bind was attempted against this directory, which is what makes a
		// guessing run visible at all.
		a.audit(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: a.orgID,
			Detail: map[string]any{"via": a.via, "reason": "unknown_user"},
		})
		return nil, errLDAPInvalid
	}
	if _, err := a.hasher.Verify(ctx, hash, password); err != nil {
		a.audit(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{"via": a.via, "reason": "bad_password"},
		})
		return nil, errLDAPInvalid
	}

	// After the password, so the answer and its timing are the same as for a
	// wrong one: a refusal here must not tell a guesser the password was right.
	refuse, err := a.refusesPasswordOnly(ctx, orgID, userID)
	if err != nil {
		return nil, fmt.Errorf("checking whether a password alone is accepted: %w", err)
	}
	if refuse {
		a.audit(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{"via": a.via, "reason": "second_factor_required"},
		})
		return nil, errMFARequired
	}

	id, err := a.Lookup(ctx, username)
	if err != nil || id == nil {
		a.audit(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{"via": a.via, "reason": "no_identity"},
		})
		return nil, errLDAPInvalid
	}

	a.audit(ctx, audit.Event{
		Type: audit.EventLoginSucceeded, OrgID: orgID, SubjectID: userID,
		Detail: map[string]any{"via": a.via, "amr": []string{"pwd"}},
	})
	return id, nil
}

func (a *LDAPAuthenticator) Lookup(ctx context.Context, username string) (*ldapd.Identity, error) {
	var id ldapd.Identity
	err := a.db.QueryRow(ctx, `
		SELECT COALESCE(NULLIF(u.username,''), u.email, u.id::text),
		       COALESCE(u.email,''), u.status = 'active',
		       COALESCE(u.display_name,''), COALESCE(u.surname,''),
		       COALESCE(u.given_name,'')
		FROM core.users u
		WHERE u.org_id = $1::uuid
		  AND (lower(u.username) = lower($2) OR lower(u.email) = lower($2))
		  AND u.status = 'active'`, a.orgID, username).
		Scan(&id.Username, &id.Email, &id.Active,
			&id.DisplayName, &id.Surname, &id.GivenName)
	if err != nil {
		return nil, nil
	}
	// The username is the fallback, not the value. It used to be assigned
	// unconditionally, which was fine while nothing could set a display name and
	// is now the difference between reading back the `cn` a client wrote and
	// reading back its own uid.
	if id.DisplayName == "" {
		id.DisplayName = id.Username
	}

	// Groups, unfiltered by any release policy: an LDAP listener is configured
	// per organisation by an operator, unlike an OIDC client which asks for
	// itself. There is no third party here to withhold them from.
	var userID string
	if err := a.db.QueryRow(ctx,
		`SELECT id::text FROM core.users WHERE org_id = $1::uuid
		   AND (lower(username) = lower($2) OR lower(email) = lower($2))`,
		a.orgID, username).Scan(&userID); err == nil {
		if groups, gerr := store.AllGroupsForUser(ctx, a.db, userID); gerr == nil {
			id.Groups = groups
		}
	}
	return &id, nil
}

func (a *LDAPAuthenticator) List(ctx context.Context, limit int) ([]*ldapd.Identity, error) {
	// Groups come back in the SAME query. The obvious shape -- list users, then
	// look up each one's groups -- is a query per user on a path a client can
	// call repeatedly, which is a denial of service with a valid bind.
	rows, err := a.db.Query(ctx, `
		SELECT COALESCE(NULLIF(u.username,''), u.email, u.id::text), COALESCE(u.email,''),
		       COALESCE(u.display_name,''), COALESCE(u.surname,''),
		       COALESCE(u.given_name,''),
		       COALESCE(array_agg(g.name ORDER BY g.name)
		                FILTER (WHERE g.name IS NOT NULL), '{}')
		FROM core.users u
		LEFT JOIN core.group_members m ON m.user_id = u.id
		LEFT JOIN core.groups g ON g.id = m.group_id
		WHERE u.org_id = $1::uuid AND u.status = 'active'
		GROUP BY u.id, u.username, u.email, u.display_name, u.surname,
		         u.given_name, u.created_at
		ORDER BY u.created_at
		LIMIT $2`, a.orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*ldapd.Identity
	for rows.Next() {
		var id ldapd.Identity
		if err := rows.Scan(&id.Username, &id.Email, &id.DisplayName,
			&id.Surname, &id.GivenName, &id.Groups); err != nil {
			return nil, err
		}
		id.Active = true
		if id.DisplayName == "" {
			id.DisplayName = id.Username
		}
		out = append(out, &id)
	}
	return out, rows.Err()
}
