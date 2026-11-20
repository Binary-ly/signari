package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provider"
)

// UserinfoPerson is what the userinfo endpoint reads of an active person, and
// whether there is anything further to ask, so that a deployment with no claim
// mappers and no provider asks nothing further.
type UserinfoPerson struct {
	Email, Username, Name, Given, Family string
	EmailVerified                        bool
	OrgID                                string
	// ClientOfOrg is whether the token's client is of the person's organisation,
	// and RolesClaim the claim it named for their roles there.
	ClientOfOrg bool
	RolesClaim  string
	HasMappers  bool
	HasProvider bool
	// AsJWT is whether the client asked for its answer signed or encrypted, and so
	// whether there is the client to read as well.
	AsJWT bool
}

// UserinfoPersonOf reads the person a userinfo answer is about, in one statement.
// A person who has gone or is no longer active is an error, as is a subject that
// is not a person.
func UserinfoPersonOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID, clientID string) (UserinfoPerson, error) {
	return scanUserinfoPerson(q.QueryRow(ctx, userinfoPersonStatement, userinfoPersonArgs(userID, clientID)...))
}

// QueueUserinfoPersonOf is UserinfoPersonOf as one more statement in a batch the caller
// sends: userinfo asks it in the round trip that asks the token's standing (E.06), since
// what it asks depends on the token alone. The answer is read once the batch is closed.
func QueueUserinfoPersonOf(b *pgx.Batch, userID, clientID string) func() (UserinfoPerson, error) {
	var p UserinfoPerson
	err := errors.New("the batch asking for the person a token names was not sent")
	b.Queue(userinfoPersonStatement, userinfoPersonArgs(userID, clientID)...).QueryRow(func(row pgx.Row) error {
		p, err = scanUserinfoPerson(row)
		return nil
	})
	return func() (UserinfoPerson, error) { return p, err }
}

func userinfoPersonArgs(userID, clientID string) []any {
	return []any{userID, clientID, string(ClaimInUserInfo), string(provider.HookUserinfo)}
}

func scanUserinfoPerson(row pgx.Row) (UserinfoPerson, error) {
	var p UserinfoPerson
	err := row.Scan(&p.Email, &p.Username, &p.EmailVerified, &p.Name, &p.Given, &p.Family, &p.OrgID,
		&p.ClientOfOrg, &p.RolesClaim, &p.HasMappers, &p.HasProvider, &p.AsJWT)
	if err != nil {
		return p, fmt.Errorf("reading the person a token names: %w", err)
	}
	return p, nil
}

const userinfoPersonStatement = `
		SELECT COALESCE(u.email, ''), COALESCE(u.username, ''), u.email_verified_at IS NOT NULL,
		       COALESCE(u.display_name, ''), COALESCE(u.given_name, ''), COALESCE(u.surname, ''),
		       u.org_id::text, c.client_id IS NOT NULL, COALESCE(c.roles_claim, ''),
		       EXISTS (SELECT 1 FROM core.claim_mappers m WHERE m.org_id = u.org_id AND m.destination = $3),
		       EXISTS (SELECT 1 FROM core.providers x WHERE x.org_id = u.org_id AND x.hook = $4),
		       COALESCE(c.userinfo_signed_response_alg IS NOT NULL OR c.userinfo_encrypted_response_alg IS NOT NULL, false)
		  FROM core.users u
		  LEFT JOIN core.clients c ON c.org_id = u.org_id AND c.client_id = $2
		 WHERE u.id = $1::uuid AND u.status = 'active'`
