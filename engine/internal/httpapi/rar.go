package httpapi

import (
	"context"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/rar"
	"signari.dev/engine/internal/store"
)

// RFC 9396 Rich Authorization Requests, at the HTTP boundary.

// parseAuthorizationDetails validates the parameter against what this client
// may request.
//
// The registry is scoped to the client, so a type the deployment defines but
// this client was not registered for is an UNKNOWN type here — §5's first
// condition — rather than a known type quietly dropped later. The distinction is
// the whole point: a dropped permission produces a token weaker than the consent
// screen described, and nobody finds out until something fails in production.
func (s *Server) parseAuthorizationDetails(ctx context.Context, c *clients.Client,
	raw string) ([]rar.Detail, *oauth.AuthzError) {

	details, objs, err := rar.Parse(raw)
	if err != nil {
		return nil, &oauth.AuthzError{
			Code: rar.ErrorCode, Description: err.Error(),
			Disposition: oauth.DispositionRedirect,
		}
	}
	if len(details) == 0 {
		return nil, nil
	}

	reg, rerr := store.AuthorizationDetailTypes(ctx, s.db, c.OrgID, c.ClientID)
	if rerr != nil {
		s.log.Error("loading authorization detail types", "err", rerr)
		return nil, &oauth.AuthzError{
			Code: "server_error", Description: "unavailable",
			Disposition: oauth.DispositionRedirect,
		}
	}
	if len(reg) == 0 {
		// No types registered for this client at all. Saying so plainly, because
		// "unknown type X" would send an operator looking at the type name when
		// the missing piece is the registration.
		return nil, &oauth.AuthzError{
			Code: rar.ErrorCode,
			Description: "this client is not registered for any authorization " +
				"details type",
			Disposition: oauth.DispositionRedirect,
		}
	}
	if verr := rar.Validate(details, objs, reg); verr != nil {
		return nil, &oauth.AuthzError{
			Code: rar.ErrorCode, Description: verr.Error(),
			Disposition: oauth.DispositionRedirect,
		}
	}
	return details, nil
}
