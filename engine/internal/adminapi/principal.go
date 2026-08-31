package adminapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Scopes. Deliberately few. A permission model nobody can hold in their head is
// one that gets granted wholesale, which is the situation this replaces.
const (
	ScopeUsersWrite   = "users:write"
	ScopeClientsWrite = "clients:write"
	ScopeConfigRead   = "config:read"
	// Read scopes, so a token can be granted the ability to LIST and GET without
	// the ability to change anything. An integration that renders an operator
	// console, or a reconciliation loop that diffs before it writes, needs
	// exactly this and previously had to be given write access to get it.
	ScopeUsersRead   = "users:read"
	ScopeClientsRead = "clients:read"
	// Groups get their own pair rather than riding on users:*. A group decides
	// which applications its members reach, so granting somebody the ability to
	// edit group membership is granting application access -- a different
	// decision from being able to reset a password.
	ScopeGroupsRead  = "groups:read"
	ScopeGroupsWrite = "groups:write"
	// ScopeSubjectsErase is its own scope rather than part of users:write.
	//
	// A token that may rename a user should not thereby be able to destroy one
	// irreversibly, and most tokens that need the former do not need the latter.
	// Erasure is the only operation in this API that nobody can undo.
	ScopeSubjectsErase = "subjects:erase"
	// ScopeOrganizationsWrite provisions tenants, and is separate for the same
	// reason as subjects:erase: the blast radius differs in kind.
	//
	// A provisioning system that creates tenants has no business editing the
	// people inside them, and a support desk token that edits people has no
	// business creating tenants. It is additionally useless to an
	// organisation-scoped token -- creating an organisation requires an unscoped
	// one, because a tenant that can provision tenants has escaped the isolation
	// boundary the product is built on.
	ScopeOrganizationsWrite = "organizations:write"
	// ScopeAuditRead reads the audit trail.
	//
	// Its own scope, and deliberately NOT implied by users:write. The implication
	// rule exists so a token that may change a thing can see that thing; the
	// trail is not that thing, it is the record of everyone who touched it. A
	// provisioning script that needs to look up users should not thereby be able
	// to read every person's authentication history.
	ScopeAuditRead = "audit:read"
	// ScopeAll is what the break-glass environment token carries. It is not
	// grantable to a database token: a stored credential that can do everything
	// is the thing this package exists to stop handing out.
	ScopeAll = "*"
)

// KnownScopes is what `admin-token create` will accept.
var KnownScopes = []string{ScopeUsersWrite, ScopeClientsWrite, ScopeConfigRead,
	ScopeSubjectsErase, ScopeUsersRead, ScopeClientsRead,
	ScopeGroupsRead, ScopeGroupsWrite, ScopeOrganizationsWrite,
	ScopeAuditRead}

// impliedBy says which scope a write scope satisfies on its own.
//
// A token that may CHANGE a client can obviously read one, and requiring both to
// be granted would mean every existing write-scoped token silently lost the
// ability to read the thing it edits the moment read endpoints existed. The
// implication runs one way only: a read scope never grants a write.
var impliedBy = map[string]string{
	ScopeUsersRead:   ScopeUsersWrite,
	ScopeClientsRead: ScopeClientsWrite,
	ScopeGroupsRead:  ScopeGroupsWrite,
}

// Principal is whoever is making an admin request.
type Principal struct {
	// TokenID is empty for the break-glass environment token, which has no row.
	TokenID string
	Name    string
	// OrgID empty means every organisation.
	OrgID  string
	Scopes []string
	// BreakGlass marks the environment token, so it can be logged differently.
	// A credential that bypasses revocation should be visible every time it is
	// used, not silently equivalent to the others.
	BreakGlass bool

	// ClientIDs and GroupIDs narrow the token to named objects.
	//
	// nil means every object of that kind in the token's organisation, which is
	// what every token issued before this existed carries. An EMPTY slice means
	// none, and the difference is the whole point: a `'{}'` that read as
	// unrestricted would turn a narrowing feature into a widening one the first
	// time somebody cleared a list intending to revoke access.
	ClientIDs []string
	GroupIDs  []string
}

// MayActOnClient reports whether this principal may touch a client.
func (p *Principal) MayActOnClient(clientID string) error {
	return p.mayActOnObject("client", clientID, p.ClientIDs)
}

// MayActOnGroup reports whether this principal may touch a group.
func (p *Principal) MayActOnGroup(groupID string) error {
	return p.mayActOnObject("group", groupID, p.GroupIDs)
}

// mayActOnObject is the shared rule.
//
// nil is unrestricted; anything else is an allow-list, including the empty one.
// Written once because the two call sites must not drift: a copy that treated
// empty as unrestricted for groups and not for clients would be a boundary that
// holds for one object kind, which reads as enforced and is not.
func (p *Principal) mayActOnObject(kind, id string, allowed []string) error {
	if allowed == nil {
		return nil
	}
	for _, a := range allowed {
		if strings.EqualFold(a, id) {
			return nil
		}
	}
	return fmt.Errorf("%w: this token is restricted to named %ss and %s is not one of them",
		errCrossOrg, kind, id)
}

// Can reports whether this principal holds a scope.
//
// A write scope satisfies the matching read scope (see impliedBy). Without that,
// adding read endpoints would have quietly broken every token already issued with
// `clients:write`, which would have been an upgrade that removed access.
func (p *Principal) Can(scope string) bool {
	implied := impliedBy[scope]
	for _, s := range p.Scopes {
		if s == scope || s == ScopeAll {
			return true
		}
		if implied != "" && s == implied {
			return true
		}
	}
	return false
}

// MayActOn reports whether this principal may touch an organisation.
//
// The check that makes org_id worth having. A token scoped to one tenant must
// not be able to create a user in another, and the two places that decide an
// org -- the request body on a create, the existing row on an update -- must
// both go through here. Missing it in one of them leaves a boundary that holds
// for creates and not for edits, which is worse than no boundary at all because
// it reads as enforced.
func (p *Principal) MayActOn(orgID string) error {
	if p.OrgID == "" {
		return nil // unscoped: every organisation
	}
	if orgID == "" {
		return fmt.Errorf("this token is scoped to one organisation, and the request " +
			"does not name one")
	}
	if !strings.EqualFold(p.OrgID, orgID) {
		return fmt.Errorf("this token may only act on organisation %s", p.OrgID)
	}
	return nil
}

type principalKey struct{}

func withPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// principalFrom returns the caller. The second result is false when there is
// none, which can only happen if a handler is registered without the auth
// wrapper -- so callers treat it as a programming error rather than a denial.
func principalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

// errTokenRejected is returned for every authentication failure, whatever the
// cause. Distinguishing "no such token" from "expired" from "revoked" tells an
// attacker which of their guesses was once real.
var errTokenRejected = errors.New("unauthorized")

// resolveToken identifies the caller from a presented bearer token.
func (s *Server) resolveToken(ctx context.Context, presented string) (*Principal, error) {
	// The environment token first, and without touching the database. It is the
	// path that has to work when the database does not -- which is exactly when
	// somebody needs to get in.
	if s.token != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) == 1 {
		return &Principal{Name: "break-glass environment token",
			Scopes: []string{ScopeAll}, BreakGlass: true}, nil
	}

	sum := sha256.Sum256([]byte(presented))

	var p Principal
	var orgID *string
	var expires, revoked *time.Time
	err := s.db.QueryRow(ctx, `
		SELECT id::text, name, org_id::text, scopes, expires_at, revoked_at,
		       client_ids, group_ids
		FROM core.admin_tokens
		WHERE token_hash = $1`, sum[:]).
		Scan(&p.TokenID, &p.Name, &orgID, &p.Scopes, &expires, &revoked,
			&p.ClientIDs, &p.GroupIDs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errTokenRejected
		}
		return nil, err
	}
	if revoked != nil {
		return nil, errTokenRejected
	}
	if expires != nil && time.Now().After(*expires) {
		return nil, errTokenRejected
	}
	if orgID != nil {
		p.OrgID = *orgID
	}
	return &p, nil
}

// touch records that a token was used, best-effort and out of band.
//
// Not in the request transaction on purpose: an UPDATE on this row per request
// would serialise every concurrent admin call behind one row lock, and the value
// is only ever read by a human deciding whether a token is still needed.
func (s *Server) touch(tokenID string) {
	if tokenID == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := s.db.Exec(ctx,
			`UPDATE core.admin_tokens SET last_used_at = now() WHERE id = $1::uuid`,
			tokenID); err != nil {
			s.log.Debug("recording admin token use", "err", err)
		}
	}()
}

// errCrossOrg is returned when a token scoped to one organisation tries to act
// on another. Distinct from errNotFound so the handler can answer 403 rather
// than 404 -- the resource exists, the caller simply may not touch it, and
// saying "not found" would be a lie that costs an operator an hour.
var errCrossOrg = errors.New("outside this token's organisation")

// requireOrg enforces the organisation boundary for a request.
//
// Called at BOTH points an organisation is decided: the request body on a
// create, and the existing row on an update. Enforcing it in only one leaves a
// boundary that holds for new records and not for edits -- worse than none,
// because it reads as enforced.
// requireClient narrows a request to the clients this token may act on.
//
// Called ALONGSIDE requireOrg, never instead of it: the organisation check
// decides which tenant, and this decides which object within it. A handler that
// called only one would enforce half a boundary.
func requireClient(ctx context.Context, clientID string) error {
	p, ok := principalFrom(ctx)
	if !ok {
		return fmt.Errorf("no admin principal on the request context; the handler is " +
			"registered without auth()")
	}
	return p.MayActOnClient(clientID)
}

// requireGroup narrows a request to the groups this token may act on.
func requireGroup(ctx context.Context, groupID string) error {
	p, ok := principalFrom(ctx)
	if !ok {
		return fmt.Errorf("no admin principal on the request context; the handler is " +
			"registered without auth()")
	}
	return p.MayActOnGroup(groupID)
}

func requireOrg(ctx context.Context, orgID string) error {
	p, ok := principalFrom(ctx)
	if !ok {
		// A handler reachable without the auth wrapper. Fail closed and say so,
		// rather than treating "no principal" as "no restriction".
		return fmt.Errorf("no admin principal on the request context; the handler is " +
			"registered without auth()")
	}
	if err := p.MayActOn(orgID); err != nil {
		return fmt.Errorf("%w: %s", errCrossOrg, err)
	}
	return nil
}

// orgFilter is the organisation a LIST must be restricted to, or nil for a
// principal that may see every organisation.
//
// Returned as a *string so it can be passed straight to a query as a nullable
// parameter -- `($n::uuid IS NULL OR org_id = $n::uuid)` -- which keeps the
// restriction in the WHERE clause rather than in a filter applied to the result.
// A filter applied afterwards is one a later refactor moves or drops, and the
// failure is one tenant enumerating another's users.
//
// Fails CLOSED: a request with no principal (a handler registered without
// auth()) gets an organisation that matches nothing rather than everything.
func orgFilter(ctx context.Context) *string {
	p, ok := principalFrom(ctx)
	if !ok {
		none := "00000000-0000-0000-0000-000000000000"
		return &none
	}
	if p.OrgID == "" {
		return nil
	}
	org := p.OrgID
	return &org
}

// TokenIDFrom returns the acting token's id for the audit trail, empty when the
// caller is the break-glass environment token (which has no row to reference).
func TokenIDFrom(ctx context.Context) string {
	if p, ok := principalFrom(ctx); ok {
		return p.TokenID
	}
	return ""
}

// sha256Of is the stored form of a token.
func sha256Of(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
