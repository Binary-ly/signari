package adminapi

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// This deployment's own access tokens at the Admin API (6.01): a person signed
// in to a designated application (the console), or such an application acting
// as itself, acts with the roles they are bound to.
//
// Everything is read on each request (ADR-007): the token's signature, issuer,
// audience and expiry, then whether it, its grant, its session, its client and
// its holder are still live, whether the client is still designated, and the
// holder's bindings. A token says who is asking; it never says what they may
// do, so a role taken away or an application undesignated is refused from the
// next request with nothing to revoke.

// AcceptAccessTokens lets the Admin API accept access tokens verified against
// set and audienced to issuer's Admin API audience, from the designated
// applications of instanceID's organisations. Called once for each instance
// the process serves (6.12); never called, it accepts admin tokens only.
func (s *Server) AcceptAccessTokens(instanceID string, set *keys.Set, issuer string) {
	s.accessIssuers = append(s.accessIssuers, accessIssuer{instanceID: instanceID, keys: set, issuer: issuer})
}

// accessIssuer is one instance whose access tokens the Admin API accepts.
type accessIssuer struct {
	instanceID string
	keys       *keys.Set
	issuer     string
}

// errMultiFactorRequired is a person's token from a session that did not prove
// a second factor: administration is not done on a password alone.
var errMultiFactorRequired = errors.New("multi-factor session required")

// looksLikeAccessToken tells a JWT from an admin token's secret, which never
// has a dot.
func looksLikeAccessToken(v string) bool {
	return strings.Count(v, ".") == 2 && !strings.HasPrefix(v, TokenPrefix)
}

func (s *Server) resolveAccessToken(ctx context.Context, raw string) (*Principal, error) {
	// Verified by the instance that signed it, and by no other: each checks
	// its own keys and its own issuer.
	var claims *tokens.AccessTokenClaims
	var from accessIssuer
	var err error
	for _, ai := range s.accessIssuers {
		if claims, err = tokens.VerifyAccessTokenAny(ai.keys, []string{ai.issuer}, raw); err == nil {
			from = ai
			break
		}
	}
	if claims == nil || err != nil {
		return nil, errTokenRejected
	}
	// Exactly the Admin API's audience: tokens.AudienceAccepted's rule, the
	// client's own id or the issuer, would make every application's token an
	// administrator's.
	if !slices.Contains(claims.Audience, tokens.AdminAudience(from.issuer)) {
		return nil, errTokenRejected
	}
	// A sender-constrained token is refused rather than taken as a bearer one:
	// the Admin API does not check proofs, and accepting it without would make
	// the constraint a decoration.
	if claims.Cnf != nil {
		return nil, errTokenRejected
	}
	if revoked, err := store.JTIRevoked(ctx, s.db, claims.JTI); err != nil || revoked {
		return nil, rejectedOr(err)
	}
	if claims.GrantID != "" {
		if revoked, err := store.GrantRevoked(ctx, s.db, claims.GrantID); err != nil || revoked {
			return nil, rejectedOr(err)
		}
	}
	// The client enabled and in service, and a person holder active.
	if live, err := store.TokenHolderLive(ctx, s.db, claims.ClientID, claims.Subject); err != nil || !live {
		return nil, rejectedOr(err)
	}
	// And of the instance that signed (6.12): an application of another
	// instance never had a token from this issuer to present.
	var orgID string
	var designated bool
	if err := s.db.QueryRow(ctx, `
		SELECT c.org_id::text, c.admin_api FROM core.clients c
		  JOIN core.organizations o ON o.id = c.org_id
		 WHERE c.client_id = $1 AND ($2::text = '' OR o.instance_id::text = $2)`,
		claims.ClientID, from.instanceID).Scan(&orgID, &designated); err != nil || !designated {
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		return nil, rejectedOr(err)
	}
	expires := time.Unix(claims.Expiry, 0)

	// The application as itself: client credentials, no session.
	if claims.Subject == claims.ClientID && claims.SessionID == "" {
		bindings, err := store.RoleBindingsFor(ctx, s.db, "", claims.ClientID)
		if err != nil {
			return nil, err
		}
		return rolePrincipal("client:"+claims.ClientID, orgID, bindings, &expires), nil
	}

	// A person: through a session that is itself live (an offline grant
	// outliving its session is not a sign-in to administer with), of their
	// organisation's application, with a second factor proven.
	if claims.SessionID == "" {
		return nil, errTokenRejected
	}
	var amr []string
	var userOrg string
	err = s.db.QueryRow(ctx, `
		SELECT s.amr, u.org_id::text FROM core.sessions s JOIN core.users u ON u.id = s.user_id
		 WHERE s.sid = $1 AND s.user_id::text = $2 AND s.revoked_at IS NULL AND s.not_after > now()
		   AND u.status = 'active' AND `+store.OrgInService("u.org_id"),
		claims.SessionID, claims.Subject).Scan(&amr, &userOrg)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && userOrg != orgID) {
		return nil, errTokenRejected
	}
	if err != nil {
		return nil, err
	}
	if !oauth.Meets(amr, oauth.ACRMultiFactor) {
		return nil, errMultiFactorRequired
	}
	bindings, err := store.RoleBindingsFor(ctx, s.db, claims.Subject, "")
	if err != nil {
		return nil, err
	}
	p := rolePrincipal("user:"+claims.Subject, orgID, bindings, &expires)
	p.UserID = claims.Subject
	return p, nil
}

// rejectedOr is err, or errTokenRejected when there is none: a failed read is
// the server's, a dead token the caller's.
func rejectedOr(err error) error {
	if err != nil {
		return err
	}
	return errTokenRejected
}
