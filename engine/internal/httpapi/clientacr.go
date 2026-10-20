package httpapi

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
)

// A client's floor: the weakest authentication it accepts (migration 0166),
// whatever its request asks for. A relying party could ask for multi-factor
// with acr_values, and nothing let an operator require it of an application
// that does not ask, or of a request a user can edit.
//
// Checked wherever a person's session gives the client tokens: an
// authorization, a device or backchannel approval, and every refresh. At
// authorization alone it would be reached around by the device grant, and every
// refresh token issued before it was raised would go on working until it
// expired. Token exchange and the JWT bearer grant are not held to it: they
// carry another token's or another issuer's assertion, not a session here.

// meetsClientFloor reports whether a session's factors meet the client's.
func meetsClientFloor(c *clients.Client, amr []string) bool {
	return c == nil || c.MinimumACR != oauth.ACRMultiFactor || oauth.IsMultiFactor(amr)
}

// clientFloorIsMFA reports whether a client requires multi-factor. An unknown
// client has no floor; it is refused by whatever looked it up.
func clientFloorIsMFA(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (bool, error) {
	var floor string
	err := q.QueryRow(ctx, `SELECT minimum_acr FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&floor)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return floor == oauth.ACRMultiFactor, err
}

// authzClientFloorIsMFA is clientFloorIsMFA for the client a parked
// authorization request names, for the flow's `client_requires_mfa`. A query
// that cannot be read names no client. A floor that cannot be read is treated
// as required: the authorization endpoint holds the session to it anyway, so
// asking for a factor now is the answer that does not loop.
func (f *signInFacts) authzClientFloorIsMFA() bool {
	q, err := url.ParseQuery(strings.TrimPrefix(f.authzQuery, "?"))
	if err != nil || q.Get("client_id") == "" {
		return false
	}
	required, err := clientFloorIsMFA(f.ctx, f.db, q.Get("client_id"))
	if err != nil {
		f.s.log.Error("reading a client's acr floor", "err", err)
		return true
	}
	return required
}
