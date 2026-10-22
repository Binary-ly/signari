package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// InInstance is the SQL condition that the organisation the column `col` names
// belongs to the instance the text parameter `param` names (6.12).
//
// One process serves several instances, each its own issuer behind its own
// host, so everything a request is admitted by -- a client, a session, an
// account found by name, a provider found by its slug, a token found by its
// hash -- is asked whether it is this server's before it is used. Without it a
// client registered under one issuer was served by another, which signed its
// tokens with keys the client's relying parties had never been given.
//
// An empty parameter is a server that was not told its instance, a test's,
// and serves the whole database as every server did before; `signari serve`
// tells every server it starts.
func InInstance(col, param string) string {
	return "(" + param + "::text = '' OR EXISTS (SELECT 1 FROM core.organizations o_inst" +
		" WHERE o_inst.id = " + col + " AND o_inst.instance_id::text = " + param + "))"
}

// OrgInInstance reports whether an organisation belongs to an instance, for the
// places that have its id in hand rather than a query to add InInstance to. An
// unknown organisation belongs to none.
func OrgInInstance(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, instanceID string) (bool, error) {
	if instanceID == "" {
		return true, nil
	}
	var in bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.organizations
		WHERE id::text = $1 AND instance_id::text = $2)`, orgID, instanceID).Scan(&in)
	return in, err
}
