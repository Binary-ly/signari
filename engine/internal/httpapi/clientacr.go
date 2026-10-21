package httpapi

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
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

// meetsClientFloor reports whether a session's factors meet the client's:
// "1" to "4", the upper two a WebAuthn assertion (oauth.Assurance).
func meetsClientFloor(c *clients.Client, amr []string) bool {
	return c == nil || oauth.Meets(amr, c.MinimumACR)
}

// clientFloor reads a client's floor. An unknown client has none; it is
// refused by whatever looked it up.
func clientFloor(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (string, error) {
	var floor string
	err := q.QueryRow(ctx, `SELECT minimum_acr FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&floor)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return floor, err
}

// clientFloorIsMFA reports whether a client requires multi-factor, at any
// rung from "2" up.
func clientFloorIsMFA(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (bool, error) {
	floor, err := clientFloor(ctx, q, clientID)
	return oauth.RequiredRung("", floor) >= 2, err
}

// floorRefusal is what a person is told when a session does not reach a
// client's floor: which kind of sign-in it asks for.
func floorRefusal(floor string) string {
	if oauth.RequiredRung("", floor) >= 3 {
		return "This application requires a sign-in with a passkey or security key."
	}
	return "This application requires a second factor."
}

type grantedACRKey struct{}

// withGrantedACR carries the rung a code's request asked for and was given
// (oauth.SatisfiedACR) into mintSet for its ID token, as the DPoP thumbprint
// is carried: most callers would never set it.
func withGrantedACR(ctx context.Context, acr string) context.Context {
	return context.WithValue(ctx, grantedACRKey{}, acr)
}

func grantedACRFrom(ctx context.Context) string {
	s, _ := ctx.Value(grantedACRKey{}).(string)
	return s
}

// stepUpNeverAsked reports whether signing in again cannot reach
// multi-factor for somebody who has a factor enrolled: the flow would not ask a
// password sign-in for it, and they have no passkey, whose own sign-in is
// multi-factor. The authorization endpoint then refuses the requirement rather
// than showing a form whose every answer brings the person back to it. An
// error reads as askable, which shows the form, as before.
func (s *Server) stepUpNeverAsked(ctx context.Context, orgID, userID, authzQuery string) bool {
	demanded, _ := s.FlowDemandsMFA(ctx, s.db, orgID, userID, authzQuery,
		[]string{oauth.AMRPassword})
	if demanded {
		return false
	}
	passkey, err := store.HasPasskey(ctx, s.db, userID)
	if err != nil {
		s.log.Error("checking for a passkey at a step-up", "err", err)
		return false
	}
	return !passkey
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
