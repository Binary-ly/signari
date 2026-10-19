package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// IssuerAlias is a legacy issuer this deployment also claims while relying
// parties move across.
type IssuerAlias struct {
	Issuer      string
	RetireAfter *time.Time
	// Pinned is how many clients mint their tokens under it.
	Pinned int
}

// ErrInvalidIssuerAlias wraps every reason an alias is refused.
var ErrInvalidIssuerAlias = errors.New("invalid issuer alias")

// AddIssuerAlias registers a legacy issuer for an instance, optionally with a
// planned retirement. Behind `signari instance add-alias`.
//
// The table had a reader and no writer, so a migration could not keep any
// application on its old issuer, while two published pages described doing it.
func AddIssuerAlias(ctx context.Context, tx pgx.Tx, instanceID, issuer string, retireAfter *time.Time) error {
	issuer = strings.TrimSpace(issuer)
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
		strings.HasSuffix(issuer, "/") {
		return fmt.Errorf("%w: %q must be an https URL with no query, fragment or trailing slash, "+
			"exactly as the relying parties compare it", ErrInvalidIssuerAlias, issuer)
	}
	if retireAfter != nil && !retireAfter.After(time.Now()) {
		return fmt.Errorf("%w: a retirement in the past would register an alias nothing accepts",
			ErrInvalidIssuerAlias)
	}
	// Not an issuer this or another instance already is: tokens minted under
	// it would be indistinguishable from that instance's own.
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.instances WHERE issuer = $1)`,
		issuer).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return fmt.Errorf("%w: %s is an instance's own issuer", ErrInvalidIssuerAlias, issuer)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.instance_issuer_aliases (instance_id, issuer, retire_after)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (issuer) DO UPDATE SET retire_after = EXCLUDED.retire_after
		 WHERE core.instance_issuer_aliases.instance_id = EXCLUDED.instance_id`,
		instanceID, issuer, retireAfter)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s is already another instance's alias", ErrInvalidIssuerAlias, issuer)
	}
	return nil
}

// RetireIssuerAlias stops accepting an alias at a time, now by default. From
// then on no token is minted under it and none minted under it is accepted:
// clients pinned to it get the instance's own issuer.
func RetireIssuerAlias(ctx context.Context, tx pgx.Tx, instanceID, issuer string, at time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE core.instance_issuer_aliases SET retire_after = $3
		WHERE instance_id = $1::uuid AND issuer = $2`, instanceID, strings.TrimSpace(issuer), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s is not an alias of this instance", ErrInvalidIssuerAlias, issuer)
	}
	return nil
}

// IssuerAliases lists an instance's aliases, retired ones included.
func IssuerAliases(ctx context.Context, q Querier, instanceID string) ([]IssuerAlias, error) {
	rows, err := q.Query(ctx, `
		SELECT a.issuer, a.retire_after,
		       (SELECT count(*) FROM core.clients c JOIN core.organizations o ON o.id = c.org_id
		         WHERE o.instance_id = a.instance_id AND c.issuer_alias = a.issuer)
		  FROM core.instance_issuer_aliases a
		 WHERE a.instance_id = $1::uuid ORDER BY a.issuer`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IssuerAlias
	for rows.Next() {
		var a IssuerAlias
		if err := rows.Scan(&a.Issuer, &a.RetireAfter, &a.Pinned); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// LiveIssuerAliases are the aliases accepted now: registered and not retired.
// Read per request (ADR-007): read once at startup, an alias registered later
// was refused until a restart and one past its retirement honoured until one.
func LiveIssuerAliases(ctx context.Context, q Querier, instanceID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT issuer FROM core.instance_issuer_aliases
		WHERE instance_id = $1::uuid AND (retire_after IS NULL OR retire_after > now())`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
