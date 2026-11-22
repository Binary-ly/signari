package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
)

// ClientLogout is a client's sign-out registration. A nil field is left as it
// is, so each surface changes only what it was asked to.
type ClientLogout struct {
	// PostLogoutRedirectURIs replaces the list a relying party may name as
	// post_logout_redirect_uri. Empty clears it.
	PostLogoutRedirectURIs *[]string
	// FrontchannelURI is loaded in a frame at sign-out. Empty clears it.
	FrontchannelURI *string
	// FrontchannelSessionRequired adds iss and sid to that URI.
	FrontchannelSessionRequired *bool
	// BackchannelURI is where a logout token is posted at sign-out. Empty
	// clears it. Until October 2026 only dynamic registration could set it,
	// unchecked, so a statically registered client could not be told.
	BackchannelURI *string
	// BackchannelSessionRequired puts the session's sid in the logout token.
	BackchannelSessionRequired *bool
}

// ValidateBackchannelLogoutURI holds a back-channel logout URI to OpenID
// Connect Back-Channel Logout 1.0 §2.2: "The back-channel logout URI MUST NOT
// include a fragment component", and https, which the definition says it
// SHOULD use; http is allowed there only where the OP allows http RP URIs,
// and this one does not, since what is posted is a logout token.
func ValidateBackchannelLogoutURI(raw string) error {
	p, err := url.Parse(raw)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil ||
		p.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%w: backchannel_logout_uri %q must be an absolute https URL with no "+
			"user information and no fragment", ErrInvalidLogoutRegistration, raw)
	}
	return nil
}

// ErrInvalidLogoutRegistration wraps every reason one is refused.
var ErrInvalidLogoutRegistration = errors.New("invalid logout registration")

// SetClientLogout records where a relying party may be sent after sign-out and
// where its front channel is told. The one writer, behind `client set-logout`,
// the client PATCH, `signari apply` and dynamic registration.
//
// RP-initiated logout refused every post_logout_redirect_uri, because the
// table it is checked against had a reader and no writer, and front-channel
// logout was advertised with no way to register a URI for it.
func SetClientLogout(ctx context.Context, tx pgx.Tx, clientID string, l ClientLogout) error {
	if l.PostLogoutRedirectURIs != nil {
		seen := map[string]bool{}
		var uris []string
		for _, u := range *l.PostLogoutRedirectURIs {
			if u = strings.TrimSpace(u); u == "" || seen[u] {
				continue
			}
			// The same rules as a redirect URI, for the same reason: it is where
			// a browser is sent on this server's word.
			if err := clients.ValidateRedirectURI(u); err != nil {
				return fmt.Errorf("%w: post_logout_redirect_uri %q: %v", ErrInvalidLogoutRegistration, u, err)
			}
			seen[u] = true
			uris = append(uris, u)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM core.client_post_logout_redirect_uris WHERE client_id = $1`,
			clientID); err != nil {
			return err
		}
		for _, u := range uris {
			if _, err := tx.Exec(ctx, `INSERT INTO core.client_post_logout_redirect_uris (client_id, redirect_uri)
				VALUES ($1, $2)`, clientID, u); err != nil {
				return err
			}
		}
	}
	if l.FrontchannelURI != nil {
		u := strings.TrimSpace(*l.FrontchannelURI)
		if u != "" {
			p, err := url.Parse(u)
			if err != nil || p.Scheme != "https" || p.Host == "" || p.Fragment != "" || strings.Contains(u, "#") {
				return fmt.Errorf("%w: frontchannel_logout_uri %q must be an absolute https URL "+
					"with no fragment", ErrInvalidLogoutRegistration, u)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE core.clients SET frontchannel_logout_uri = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, u); err != nil {
			return err
		}
	}
	if l.FrontchannelSessionRequired != nil {
		if _, err := tx.Exec(ctx, `UPDATE core.clients SET frontchannel_logout_session_required = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *l.FrontchannelSessionRequired); err != nil {
			return err
		}
	}
	if l.BackchannelURI != nil {
		u := strings.TrimSpace(*l.BackchannelURI)
		if u != "" {
			if err := ValidateBackchannelLogoutURI(u); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE core.clients SET backchannel_logout_uri = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, u); err != nil {
			return err
		}
	}
	if l.BackchannelSessionRequired != nil {
		if _, err := tx.Exec(ctx, `UPDATE core.clients SET backchannel_logout_session_required = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *l.BackchannelSessionRequired); err != nil {
			return err
		}
	}
	return nil
}

// ClientLogoutOf reads a client's sign-out registration back.
func ClientLogoutOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (uris []string, frontchannel string, sessionRequired bool, err error) {
	err = q.QueryRow(ctx, `
		SELECT COALESCE((SELECT array_agg(redirect_uri ORDER BY redirect_uri)
		                   FROM core.client_post_logout_redirect_uris WHERE client_id = c.client_id), '{}'),
		       COALESCE(c.frontchannel_logout_uri, ''), c.frontchannel_logout_session_required
		  FROM core.clients c WHERE c.client_id = $1`, clientID).Scan(&uris, &frontchannel, &sessionRequired)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrClientNotFound
	}
	return uris, frontchannel, sessionRequired, err
}
