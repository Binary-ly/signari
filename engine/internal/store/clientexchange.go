package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// MaxExchangeAudiences bounds one client's audience allow-list. Each entry is a
// resource server the client may mint tokens for; a list longer than this is a
// client that may exchange for everything, said the long way.
const MaxExchangeAudiences = 64

// ErrExchangeNeedsConfidentialClient refuses granting exchange to a public
// client, which the token endpoint would refuse anyway: it cannot prove it is
// the client the permission was granted to.
var ErrExchangeNeedsConfidentialClient = errors.New("token exchange can be granted only to a confidential client")

// ErrClientNotFound is a client_id that names no client.
var ErrClientNotFound = errors.New("no such client")

// ErrInvalidExchangeAudience wraps every reason an audience list is refused.
var ErrInvalidExchangeAudience = errors.New("invalid exchange audience")

// SetClientExchange grants or withdraws RFC 8693 token exchange for a client,
// with the audiences it may exchange for besides itself, and returns the
// organisation the client belongs to.
//
// The one writer of `may_exchange` and `exchange_audiences`, for the CLI, the
// Admin API and `signari apply` alike, so the three cannot disagree about what
// a grant means. These two columns are the whole authorisation: the token
// endpoint deliberately does not consult `grant_types` for exchange
// (httpapi/flow.go), because a grant-type list cannot say which audiences.
func SetClientExchange(ctx context.Context, tx pgx.Tx, clientID string, may bool, audiences []string) (string, error) {
	clean, err := CleanExchangeAudiences(audiences)
	if err != nil {
		return "", err
	}
	if !may {
		clean = []string{}
	}
	var orgID, kind string
	if err := tx.QueryRow(ctx,
		`SELECT org_id::text, client_type FROM core.clients WHERE client_id = $1 FOR UPDATE`,
		clientID).Scan(&orgID, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrClientNotFound
		}
		return "", err
	}
	if may && kind != "confidential" {
		return "", ErrExchangeNeedsConfidentialClient
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.clients
		   SET may_exchange = $2, exchange_audiences = $3, updated_at = now()
		 WHERE client_id = $1`, clientID, may, clean); err != nil {
		return "", err
	}
	return orgID, nil
}

// CleanExchangeAudiences trims, de-duplicates and checks an audience list.
// An audience is matched exactly at exchange time, so a space or an empty
// entry is a value that can never match and is refused rather than stored.
func CleanExchangeAudiences(audiences []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, a := range audiences {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.ContainsAny(a, " \t\r\n") {
			return nil, fmt.Errorf("%w: %q contains whitespace, and audiences are matched exactly",
				ErrInvalidExchangeAudience, a)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) > MaxExchangeAudiences {
		return nil, fmt.Errorf("%w: %d audiences, at most %d", ErrInvalidExchangeAudience,
			len(out), MaxExchangeAudiences)
	}
	return out, nil
}
