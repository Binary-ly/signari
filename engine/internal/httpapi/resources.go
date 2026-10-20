package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// RFC 8707 resource indicators become the access token's audience, so each one
// must be a resource server the client's organisation registered (0157). Asked
// where a resource is accepted -- authorize, PAR, device authorization -- and
// again in mintSet, which every grant goes through, so a resource removed after
// a code or refresh token was issued stops new tokens for it.

// errUnregisteredResource is a requested resource nobody registered. Its
// message names no value: the resource is the caller's input.
var errUnregisteredResource = errors.New("a requested resource is not a resource server this organisation registered")

func checkResources(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string, resources []string) error {
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
	if errors.Is(err, errUnregisteredResource) {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_target",
			Description: err.Error(), Status: http.StatusBadRequest})
		return
	}
	writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
}
