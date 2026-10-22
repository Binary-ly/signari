package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// RFC 8707 resource indicators become the access token's audience, so each one
// must be a resource server the client's organisation registered (0157). Asked
// where a resource is accepted -- authorize, PAR, device authorization -- and
// again in mintSet, which every grant goes through, so a resource removed after
// a code or refresh token was issued stops new tokens for it.

// errUnregisteredResource is a requested resource nobody registered. Its
// message names no value: the resource is the caller's input.
var errUnregisteredResource = errors.New("a requested resource is not a resource server this organisation registered")

// The Admin API's audience (tokens.AdminAudience, 6.01) is no organisation's
// resource server: a client the deployment designated (clients.admin_api) may
// ask for it, alone. Alone, because a token audienced to the Admin API and to
// another resource is an admin credential that resource holds.
var (
	errAdminAudienceRefused = errors.New("this client may not ask for a token for the Admin API")
	errAdminAudienceAlone   = errors.New("a token for the Admin API is asked for with no other resource")
)

// refusedTarget reports whether err is a resource the client may not have,
// the client's `invalid_target`, rather than the server's fault.
func refusedTarget(err error) bool {
	return errors.Is(err, errUnregisteredResource) || errors.Is(err, errAdminAudienceRefused) ||
		errors.Is(err, errAdminAudienceAlone)
}

func (s *Server) checkResources(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, c *clients.Client, orgID string, resources []string) error {
	if slices.Contains(resources, tokens.AdminAudience(s.cfg.Issuer)) {
		switch {
		// A client signing under a legacy issuer alias too: the Admin API
		// accepts this deployment's own issuer only.
		case c == nil || !c.AdminAPI || c.IssuerAlias != "":
			return errAdminAudienceRefused
		case len(resources) > 1:
			return errAdminAudienceAlone
		}
		return nil
	}
	missing, err := store.UnregisteredResource(ctx, q, orgID, resources)
	if err != nil {
		return err
	}
	if missing != "" {
		return errUnregisteredResource
	}
	return nil
}

// writeMintError answers a failed mint: a resource refused is the client's
// `invalid_target`, anything else the server's fault.
func writeMintError(w http.ResponseWriter, err error) {
	if refusedTarget(err) {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_target",
			Description: err.Error(), Status: http.StatusBadRequest})
		return
	}
	writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
}
