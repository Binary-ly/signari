package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// OrgServing reports whether an organisation is in service, for the places
// that have its id in hand rather than a query to add OrgInService to. An
// unknown id is not in service.
func OrgServing(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (bool, error) {
	var serving bool
	err := q.QueryRow(ctx, `SELECT `+OrgInService("$1::uuid"), orgID).Scan(&serving)
	return serving, err
}

// OrgInService is the SQL condition that the organisation the column `col`
// names is in service, not suspended (6.09).
//
// Read on the request path at each place a request is admitted -- a session
// resolved, a token's holder, a client loaded, a sign-in completed, a directory
// bind, a SCIM or outpost token -- never cached, because suspension is a
// security-negative decision (ADR-007). Suspension refuses; it ends nothing, so
// a session or grant with time left resumes when the organisation does.
func OrgInService(col string) string {
	return "EXISTS (SELECT 1 FROM core.organizations o_srv WHERE o_srv.id = " + col +
		" AND o_srv.status = 'active')"
}
