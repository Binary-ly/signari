package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The application portal.
//
// Which applications a user may reach is NOT stored. It is decided by the
// access policy when the portal is rendered, and this file only supplies the
// candidates. That split is the point: a static assignment table can say
// "Alice may use Payroll" and cannot say "from the office, on a managed device,
// during working hours". Reading the live policy means the list a user sees is
// the list they can actually open right now.

// PortalApp is one candidate application.
type PortalApp struct {
	ClientID    string
	DisplayName string
	// LaunchURL is the application's own login-initiation URL. Empty means the
	// operator has not set one, which the portal reports rather than hides --
	// an application nobody can launch is a configuration mistake, and silently
	// omitting it is how it stays a mistake.
	LaunchURL string
	LogoURI   string
}

// ListPortalCandidates returns the applications that could appear on a portal,
// before any policy is applied.
//
// Excluded: disabled clients, clients explicitly hidden, and anything that
// cannot start a browser flow. A machine-to-machine client on a portal is a
// tile nobody can click and a disclosure of the organisation's internal
// service inventory to every employee.
func ListPortalCandidates(ctx context.Context, db *pgxpool.Pool, orgID string) (
	[]PortalApp, error) {

	rows, err := db.Query(ctx, `
		SELECT client_id, display_name,
		       COALESCE(initiate_login_uri, ''), COALESCE(logo_uri, '')
		FROM core.clients
		WHERE org_id = $1::uuid
		  AND enabled
		  AND NOT portal_hidden
		  AND 'authorization_code' = ANY(grant_types)
		ORDER BY display_name, client_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PortalApp
	for rows.Next() {
		var a PortalApp
		if err := rows.Scan(&a.ClientID, &a.DisplayName, &a.LaunchURL, &a.LogoURI); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
