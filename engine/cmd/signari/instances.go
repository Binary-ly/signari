package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/httpapi"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
)

// servedInstance is one instance `serve` serves: its issuer, chosen by the
// host a request names, and the keys it signs with (6.12).
type servedInstance struct {
	id, issuer string
	keys       *keys.Set
	refresher  *keys.Refresher
}

// additionalInstances are the instances SIGNARI_ADDITIONAL_ISSUERS names, to
// be served beside the one SIGNARI_ISSUER chose, each by its issuer's host.
//
// Named, never inferred: a development database holds hundreds of instances,
// and one process answering for all of them would be a deployment nobody
// configured. Each must exist, be named once, and differ from the primary.
func additionalInstances(ctx context.Context, conn *pgx.Conn, raw, primaryIssuer string) ([]servedInstance, error) {
	var out []servedInstance
	seen := map[string]bool{primaryIssuer: true}
	for _, want := range strings.Split(raw, ",") {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		if seen[want] {
			return nil, fmt.Errorf("SIGNARI_ADDITIONAL_ISSUERS names %s twice, or names the "+
				"instance SIGNARI_ISSUER already serves", want)
		}
		seen[want] = true
		var in servedInstance
		err := conn.QueryRow(ctx,
			`SELECT id::text, issuer FROM core.instances WHERE issuer = $1`, want).Scan(&in.id, &in.issuer)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("SIGNARI_ADDITIONAL_ISSUERS names %s, and no instance has that "+
				"issuer -- create it with `signari instance create -issuer %s`", want, want)
		}
		if err != nil {
			return nil, fmt.Errorf("reading the instance for %s: %w", want, err)
		}
		out = append(out, in)
	}
	return out, nil
}

// accountNotifier tells an account holder through the server of their
// instance, so the links in a notice are their issuer's. A holder of an
// instance this process does not serve waits for a process that does.
func accountNotifier(db *pgxpool.Pool, byInstance map[string]*httpapi.Server) outbox.AccountNotifier {
	return func(ctx context.Context, n store.AccountNotice) error {
		var instanceID string
		err := db.QueryRow(ctx, `
			SELECT o.instance_id::text FROM core.users u
			  JOIN core.organizations o ON o.id = u.org_id
			 WHERE u.id::text = $1`, n.UserID).Scan(&instanceID)
		if errors.Is(err, pgx.ErrNoRows) {
			return outbox.ErrNoSuchAccount
		}
		if err != nil {
			return fmt.Errorf("reading which instance an account belongs to: %w", err)
		}
		srv, ok := byInstance[instanceID]
		if !ok {
			return fmt.Errorf("the account belongs to an instance this process does not serve")
		}
		return srv.DeliverAccountNotice(ctx, n)
	}
}
