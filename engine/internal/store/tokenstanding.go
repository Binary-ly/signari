package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/tokens"
)

// TokenStanding is what has become of a token since it was issued, read now
// (ADR-007). Each is a separate reason, because a caller says which.
type TokenStanding struct {
	// GrantRevoked: the family it was minted from is revoked or gone, a token naming
	// a grant this server cannot find being no token to honour. RFC 7009 §2.1's
	// cascade: revoking a refresh token SHOULD invalidate "all access tokens based
	// on the same authorization grant". Revocation is otherwise recorded per jti,
	// and an authorization with no refresh token has no grant to revoke.
	GrantRevoked bool
	// JTIRevoked: this token was revoked, or has no jti to be revoked by.
	JTIRevoked bool
	// SessionEnded: the session it was minted from has ended, and no offline grant
	// keeps it (5.10). A token from client credentials has no session.
	SessionEnded bool
	// HolderGone: its client is disabled or gone, or its subject is no longer an
	// active person or, for a token a client holds for itself, an enabled client.
	// A token with none of the above behind it has nothing else to end it.
	HolderGone bool
}

// Live is whether the token may still be honoured.
func (t TokenStanding) Live() bool {
	return !t.GrantRevoked && !t.JTIRevoked && !t.SessionEnded && !t.HolderGone
}

// endedForAll is the answer when the question could not be asked. Fail CLOSED:
// the caller is asking "may I honour this credential", and the safe answer when
// nobody can tell is no. Answering yes would turn a database blip into a window
// where revoked tokens are accepted.
var endedForAll = TokenStanding{GrantRevoked: true, JTIRevoked: true, SessionEnded: true, HolderGone: true}

// tokenSessionLive is the SQL for whether a token minted under a session may still
// be used: the session is live, or the grant the token was minted from is an
// offline grant within its own lifetime, of somebody still active (5.10). Every
// check of a token's session asks this rather than SessionLive, or an offline
// grant would mint tokens that its own userinfo, introspection and token exchange
// refuse the moment the person signs out.
func tokenSessionLive(sid, grant string) string {
	return `(EXISTS (SELECT 1 FROM core.sessions s JOIN core.users u ON u.id = s.user_id
	                  WHERE s.sid = ` + sid + ` AND s.revoked_at IS NULL AND s.not_after > now()
	                    AND u.status = 'active' AND ` + OrgInService("u.org_id") + `)
	      OR EXISTS (SELECT 1 FROM core.refresh_token_families f JOIN core.users u ON u.id = f.user_id
	                  WHERE f.id = NULLIF(` + grant + `, '')::uuid AND f.sid = ` + sid + ` AND f.revoked_at IS NULL
	                    AND f.offline_not_after > now() AND u.status = 'active'
	                    AND ` + OrgInService("u.org_id") + `))`
}

// TokenStandingOf asks, in one statement, everything that can have ended a token
// since it was issued. These were four round trips, repeated at each of the eight
// places a token is accepted, and a place that asked three of them was how a
// disabled client's token stayed good.
//
// A subject shaped like a UUID that names a person is held to that person, so a
// client registered under somebody's id cannot stand in for them. The client's
// organisation must be in service too (6.09), which is the subject's as well.
func TokenStandingOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, c *tokens.AccessTokenClaims) (TokenStanding, error) {
	if c.JTI == "" {
		// A token with no jti cannot be individually revoked. Treated as revoked
		// rather than guessed at: every token minted here has one, so an absent
		// jti means it did not come from here in the shape expected.
		return endedForAll, errors.New("access token has no jti")
	}
	var person *string
	if id, err := uuid.Parse(c.Subject); err == nil {
		s := id.String()
		person = &s
	}
	var st TokenStanding
	err := q.QueryRow(ctx, `
		SELECT $2 <> '' AND NOT EXISTS (SELECT 1 FROM core.refresh_token_families
		                                 WHERE id = NULLIF($2, '')::uuid AND revoked_at IS NULL),
		       EXISTS (SELECT 1 FROM core.revoked_jtis WHERE jti = $1),
		       $3 <> '' AND NOT `+tokenSessionLive("$3", "$2")+`,
		       NOT (EXISTS (SELECT 1 FROM core.clients c WHERE c.client_id = $4 AND c.enabled
		                     AND `+OrgInService("c.org_id")+`)
		            AND CASE
		                  WHEN EXISTS (SELECT 1 FROM core.users WHERE id = $5::uuid)
		                    THEN EXISTS (SELECT 1 FROM core.users u WHERE u.id = $5::uuid AND u.status = 'active'
		                                  AND `+OrgInService("u.org_id")+`)
		                  ELSE EXISTS (SELECT 1 FROM core.clients WHERE client_id = $6 AND enabled)
		                END)`,
		c.JTI, c.GrantID, c.SessionID, c.ClientID, person, c.Subject).
		Scan(&st.GrantRevoked, &st.JTIRevoked, &st.SessionEnded, &st.HolderGone)
	if err != nil {
		return endedForAll, fmt.Errorf("reading what has become of a token: %w", err)
	}
	return st, nil
}
