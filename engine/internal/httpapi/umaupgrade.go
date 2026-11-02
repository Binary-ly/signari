package httpapi

import (
	"context"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// rptToUpgrade reads an RPT presented for upgrading (§3.3.5.1) and answers what it
// can carry forward, or nothing when it cannot be upgraded. Not an error either way:
// §3.3.1 gives this server "the option", and a response with no `upgraded` tells the
// client to act as if the new RPT does not include the old one's permissions, so
// saying nothing is an honest answer in a way it would not have been for a server
// that took the parameter and did nothing with it.
//
// Every permission is decided again. It can be an expired token, and what an upgrade
// carries forward gets a new lifetime, so copying them would let a permission taken
// away go on being renewed for as long as the client kept asking: a negative decision
// outliving itself in a token. One refused and there is no upgrade, because §3.3.5.1
// has it add the previous RPT's permissions, and a part of them is not that.
//
// It has to be this client's, for this person and this resource server, and the same
// key's: §1.2 has an RPT unique to all of them, and a token moved between any two has
// proved nothing to the second.
func (s *Server) rptToUpgrade(ctx context.Context, raw string, c *clients.Client, resourceServer, party string,
	subject authzen.Subject, jkt string) ([]string, *tokens.AccessTokenClaims) {

	if raw == "" {
		return nil, nil
	}
	old, err := tokens.VerifyEvenExpired(s.cfg.Keys, s.acceptedIssuers(ctx), raw)
	if err != nil || old.ClientID != c.ClientID || !audienceIncludes(old.Audience, resourceServer) {
		return nil, nil
	}
	person, err := store.PersonNamedBy(ctx, s.db, old.ClientID, old.Subject)
	if err != nil || person != party {
		return nil, nil
	}
	if bound := old.Cnf != nil && old.Cnf.JKT != ""; bound && old.Cnf.JKT != jkt {
		return nil, nil
	}
	if endedDescription(s.standing(ctx, old, "the UMA grant")) != "" {
		return nil, nil
	}
	carried := splitScopes(old.Scope)
	for _, permission := range carried {
		resourceType, resourceID, scope, ok := uma.ParseScope(permission)
		if !ok {
			return nil, nil // Not an RPT: an access token's scope is not a permission.
		}
		resp, err := s.decide(ctx, c.OrgID, authzen.Request{Subject: subject,
			Resource: authzen.Resource{Type: resourceType, ID: resourceID}, Action: authzen.Action{Name: scope}})
		if err != nil {
			s.log.ErrorContext(ctx, "deciding a permission an RPT would carry", "err", err, "correlation_id", correlationID(ctx))
			return nil, nil
		}
		if !resp.Decision {
			return nil, nil
		}
	}
	return carried, old
}

// retireUpgraded revokes the RPT an upgrade replaced, which §3.3.5.1 says SHOULD be
// done. One already expired needs nothing, and a failure leaves two tokens that hold
// what the new one holds, which is worth logging and not worth failing the upgrade.
func (s *Server) retireUpgraded(ctx context.Context, old *tokens.AccessTokenClaims, clientID string) {
	expires := time.Unix(old.Expiry, 0)
	if time.Now().After(expires) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err == nil {
		defer func() { _ = tx.Rollback(ctx) }()
		if err = store.RevokeJTI(ctx, tx, old.JTI, clientID, expires); err == nil {
			err = tx.Commit(ctx)
		}
	}
	if err != nil {
		s.log.ErrorContext(ctx, "revoking an upgraded RPT", "err", err, "correlation_id", correlationID(ctx))
	}
}
