package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/oauth"
)

// The validated writers for client settings that more than one surface sets.
// The CLI's `client set-*` verbs and the Admin API's PATCH call these (6.03),
// so the two refuse the same things for the same reasons. They lived in the
// CLI alone, and the Admin API could set none of them. Each refusal wraps
// ErrInvalidClientSetting; an unknown client is ErrClientNotFound.

type clientWriter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func invalidSetting(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidClientSetting, fmt.Sprintf(format, a...))
}

func oneClient(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// SetClientGrants replaces the grant types a client may use, each one this
// server dispatches. RFC 6749 §5.2's unauthorized_client is for a client "not
// authorized to use this authorization grant type", so this is registration
// data; a type nothing dispatches would read as a registration and do nothing.
func SetClientGrants(ctx context.Context, q clientWriter, clientID string, grants []string) error {
	if len(grants) == 0 {
		return invalidSetting("a client with no grant types can obtain no tokens at all; "+
			"disable it instead. Known: %s", strings.Join(oauth.GrantTypes, ", "))
	}
	for _, g := range grants {
		if !slices.Contains(oauth.GrantTypes, g) {
			return invalidSetting("%q is not a grant type this server dispatches. Known: %s",
				g, strings.Join(oauth.GrantTypes, ", "))
		}
	}
	return oneClient(q.Exec(ctx, `UPDATE core.clients SET grant_types = $2, updated_at = now()
		WHERE client_id = $1`, clientID, grants))
}

// SetClientCIBA sets how backchannel results reach the client: poll with no
// endpoint, or ping or push to an https one, which CIBA Core 1.0 §7.3 requires
// and push needs most, since it carries the tokens themselves.
func SetClientCIBA(ctx context.Context, q clientWriter, clientID, mode, endpoint string) error {
	switch mode {
	case "poll", "ping", "push":
	default:
		return invalidSetting("the CIBA delivery mode is poll, ping or push, not %q", mode)
	}
	endpoint = strings.TrimSpace(endpoint)
	if mode == "poll" && endpoint != "" {
		return invalidSetting("poll mode has the client collect the result itself, so a " +
			"notification endpoint would never be called; drop it, or choose ping or push")
	}
	if mode != "poll" {
		if endpoint == "" {
			return invalidSetting("%s mode needs a notification endpoint, or a backchannel "+
				"request is accepted with nowhere to deliver its result", mode)
		}
		if !strings.HasPrefix(endpoint, "https://") {
			return invalidSetting("the notification endpoint must be https: in push mode it " +
				"receives the tokens themselves")
		}
	}
	var stored any
	if endpoint != "" {
		stored = endpoint
	}
	return oneClient(q.Exec(ctx, `UPDATE core.clients
		SET backchannel_token_delivery_mode = $2, backchannel_client_notification_endpoint = $3,
		    updated_at = now()
		WHERE client_id = $1`, clientID, mode, stored))
}

// SetClientHybrid lets a client use response_type "code id_token" until a
// review date, for an application being migrated in, with response_types
// moved with it so the two never disagree; off removes both.
func SetClientHybrid(ctx context.Context, q clientWriter, clientID string, allow bool, reviewBy string) error {
	if !allow {
		return oneClient(q.Exec(ctx, `UPDATE core.clients
			SET allow_hybrid = false, hybrid_review_by = NULL,
			    response_types = array_remove(response_types, 'code id_token'), updated_at = now()
			WHERE client_id = $1`, clientID))
	}
	if reviewBy == "" {
		return invalidSetting("give a review date: hybrid exists for applications being " +
			"migrated in, and an exemption with no date on it is a permanent one nobody decided")
	}
	if _, err := time.Parse("2006-01-02", reviewBy); err != nil {
		return invalidSetting("the review date is YYYY-MM-DD, not %q", reviewBy)
	}
	return oneClient(q.Exec(ctx, `UPDATE core.clients
		SET allow_hybrid = true, hybrid_review_by = $2::date,
		    response_types = (SELECT array_agg(DISTINCT rt)
		                        FROM unnest(response_types || ARRAY['code id_token']) AS rt),
		    updated_at = now()
		WHERE client_id = $1`, clientID, reviewBy))
}

// SetClientClaimsRedirects replaces the UMA claims redirection URIs: https,
// since each receives a permission ticket bound to whoever just signed in, and
// no fragment (UMA 2.0 §3.3.2). Empty clears them, never NULL, which the
// column refuses and which an operator reaching for "clear" in a hurry hit.
func SetClientClaimsRedirects(ctx context.Context, q clientWriter, clientID string, uris []string) error {
	list := []string{}
	for _, u := range uris {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return invalidSetting("%q does not parse as a URL: %v", u, err)
		}
		if parsed.Scheme != "https" {
			return invalidSetting("%q must use https: it receives a permission ticket bound "+
				"to whoever just signed in", u)
		}
		if parsed.Fragment != "" || strings.Contains(u, "#") {
			return invalidSetting("%q must not contain a fragment (UMA 2.0 section 3.3.2)", u)
		}
		list = append(list, u)
	}
	return oneClient(q.Exec(ctx, `UPDATE core.clients SET claims_redirect_uris = $2, updated_at = now()
		WHERE client_id = $1`, clientID, list))
}

// SetClientDPoP pins a client to DPoP (RFC 9449 §5.2): with it set, a token
// request without a proof is refused rather than answered with a bearer token.
func SetClientDPoP(ctx context.Context, q clientWriter, clientID string, required bool) error {
	return oneClient(q.Exec(ctx, `UPDATE core.clients SET dpop_bound_access_tokens = $2, updated_at = now()
		WHERE client_id = $1`, clientID, required))
}

// SetClientExchangeContainment holds the client's token exchanges to subject
// tokens it holds or is named in the audience of.
func SetClientExchangeContainment(ctx context.Context, q clientWriter, clientID string, on bool) error {
	return oneClient(q.Exec(ctx, `UPDATE core.clients SET exchange_requires_audience_match = $2,
		updated_at = now() WHERE client_id = $1`, clientID, on))
}

// AssertionIssuerNote is something an operator pairing a client with an
// issuer should know and need not be refused for: the issuer does not accept
// assertions yet, or is disabled.
type AssertionIssuerNote struct {
	Slug     string
	Disabled bool
	NotAllow bool
}

// SetClientAssertionIssuers pairs a client with the identity providers whose
// assertions it may exchange (RFC 7523). Each must exist in the client's
// organisation: the grant's refusals are uniform so they cannot enumerate
// issuers, so a typo has to be caught here or not at all. Empty pairs it with
// none, never NULL.
func SetClientAssertionIssuers(ctx context.Context, q clientWriter, clientID string, slugs []string) ([]AssertionIssuerNote, error) {
	list := []string{}
	for _, sl := range slugs {
		if sl = strings.TrimSpace(sl); sl != "" {
			list = append(list, sl)
		}
	}
	var orgID string
	if err := q.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	var notes []AssertionIssuerNote
	for _, sl := range list {
		var enabled, allowed bool
		err := q.QueryRow(ctx, `SELECT enabled, allow_jwt_bearer FROM core.identity_providers
			WHERE org_id = $1::uuid AND slug = $2`, orgID, sl).Scan(&enabled, &allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, invalidSetting("no identity provider %q in this client's organisation", sl)
		}
		if err != nil {
			return nil, err
		}
		if !enabled || !allowed {
			notes = append(notes, AssertionIssuerNote{Slug: sl, Disabled: !enabled, NotAllow: !allowed})
		}
	}
	return notes, oneClient(q.Exec(ctx, `UPDATE core.clients SET jwt_bearer_providers = $2,
		updated_at = now() WHERE client_id = $1`, clientID, list))
}
