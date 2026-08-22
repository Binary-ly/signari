package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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
// LDAP bind is throttled, audited and subject to the same lockout as any other
// authentication. An LDAP front end with its own quiet credential path is a way
// around every control the rest of the product has.
//
// That sentence used to be two-thirds true: the audit write it promised did not
// exist. See the `audit` method below.
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
}

func NewLDAPAuthenticator(db *pgxpool.Pool, hasher *passwords.Hasher, orgID string,
	log *slog.Logger) *LDAPAuthenticator {
	if log == nil {
		log = slog.Default()
	}
	return &LDAPAuthenticator{db: db, hasher: hasher, orgID: orgID, log: log, via: "ldap"}
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

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*ldapd.Identity, error) {
	// Belt and braces. The protocol layer refuses an empty password before
	// reaching here (RFC 4513 unauthenticated bind), and this is the second
	// place that would have to fail for one to get through.
	if password == "" {
		return nil, errLDAPInvalid
	}

	// The same query the sign-in form uses, including its status check: a
	// deactivated account must not be able to bind, and duplicating the rule
	// here is how the two paths drift apart.
	var userID, orgID, hash string
	err := a.db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text, pc.hash
		FROM core.users u
		JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status = 'active' AND pc.is_current
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))`,
		username).Scan(&userID, &orgID, &hash)
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
