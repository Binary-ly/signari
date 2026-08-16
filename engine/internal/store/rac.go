package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/rac"
)

// Remote access connections.
//
// The credentials in these rows are for machines somebody administers, so they
// are sealed like every other stored secret and unsealed only at the moment a
// connection is made. A database read is not a set of working logins to the
// estate.

// RACConnection is one host a user may reach.
type RACConnection struct {
	ID            string
	OrgID         string
	Slug          string
	DisplayName   string
	Protocol      string
	Hostname      string
	Port          int
	RequireGroup  string
	RecordingPath string

	// Parameters are guacd's parameters WITHOUT the secrets, which are merged
	// separately by Resolve so they never appear in a value returned to a
	// caller that only wanted to list connections.
	Parameters map[string]string

	secrets []byte
}

// LoadRACConnection reads one enabled connection by slug.
func LoadRACConnection(ctx context.Context, db *pgxpool.Pool, orgID, slug string) (
	*RACConnection, error) {

	c := &RACConnection{}
	var params []byte
	var requireGroup, recordingPath *string
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, slug, display_name, protocol, hostname, port,
		       parameters, secrets_enc, require_group, recording_path
		FROM core.rac_connections
		WHERE org_id = $1::uuid AND slug = $2 AND enabled`, orgID, slug).
		Scan(&c.ID, &c.OrgID, &c.Slug, &c.DisplayName, &c.Protocol, &c.Hostname,
			&c.Port, &params, &c.secrets, &requireGroup, &recordingPath)
	if err != nil {
		return nil, err
	}
	if requireGroup != nil {
		c.RequireGroup = *requireGroup
	}
	if recordingPath != nil {
		c.RecordingPath = *recordingPath
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &c.Parameters); err != nil {
			return nil, fmt.Errorf("connection %q has unreadable parameters: %w", slug, err)
		}
	}
	if c.Parameters == nil {
		c.Parameters = map[string]string{}
	}
	return c, nil
}

// ListRACConnections returns what a user may see.
//
// Filtered by group membership here rather than in the caller, so a listing and
// a connection attempt cannot disagree about what somebody is allowed -- a
// listing that shows a host the user cannot reach is a support ticket, and one
// that hides a host they can reach is a feature nobody finds.
func ListRACConnections(ctx context.Context, db *pgxpool.Pool, orgID, userID string) (
	[]RACConnection, error) {

	rows, err := db.Query(ctx, `
		SELECT c.id::text, c.slug, c.display_name, c.protocol, c.hostname, c.port,
		       COALESCE(c.require_group, '')
		FROM core.rac_connections c
		WHERE c.org_id = $1::uuid AND c.enabled
		  AND (c.require_group IS NULL OR EXISTS (
		        SELECT 1 FROM core.group_members gm
		        JOIN core.groups g ON g.id = gm.group_id
		        WHERE gm.user_id = $2::uuid AND g.name = c.require_group))
		ORDER BY c.display_name`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RACConnection
	for rows.Next() {
		var c RACConnection
		if err := rows.Scan(&c.ID, &c.Slug, &c.DisplayName, &c.Protocol,
			&c.Hostname, &c.Port, &c.RequireGroup); err != nil {
			return nil, err
		}
		c.OrgID = orgID
		out = append(out, c)
	}
	return out, rows.Err()
}

// MayUse reports whether a user satisfies the connection's group requirement.
//
// The group requirement is checked IN ADDITION to the access policy, never
// instead of it. Two independent gates, because they answer different
// questions: policy asks whether this person may be here at all right now, and
// this asks whether this particular machine is theirs to reach.
func MayUse(ctx context.Context, db *pgxpool.Pool, c *RACConnection, userID string) (bool, error) {
	if c.RequireGroup == "" {
		return true, nil
	}
	var ok bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM core.group_members gm
			JOIN core.groups g ON g.id = gm.group_id
			WHERE gm.user_id = $1::uuid AND g.name = $2)`,
		userID, c.RequireGroup).Scan(&ok)
	return ok, err
}

// Resolve builds the guacd connection, unsealing credentials at the last
// moment.
//
// The secrets are merged over the stored parameters here and nowhere else, so
// they exist in memory for the length of one handshake rather than for the
// lifetime of a struct somebody might log.
func (c *RACConnection) Resolve(root *keys.RootKey, width, height, dpi int) (
	rac.Connection, error) {

	params := make(map[string]string, len(c.Parameters)+4)
	for k, v := range c.Parameters {
		params[k] = v
	}
	params["hostname"] = c.Hostname
	params["port"] = fmt.Sprintf("%d", c.Port)

	if len(c.secrets) > 0 {
		if root == nil {
			return rac.Connection{}, fmt.Errorf("connection %q has sealed "+
				"credentials and no root key is available to open them", c.Slug)
		}
		plain, err := root.Open(c.secrets, "rac-connection-secret")
		if err != nil {
			return rac.Connection{}, fmt.Errorf("unsealing credentials for %q: %w",
				c.Slug, err)
		}
		var secrets map[string]string
		if err := json.Unmarshal(plain, &secrets); err != nil {
			return rac.Connection{}, fmt.Errorf("credentials for %q are unreadable: %w",
				c.Slug, err)
		}
		for k, v := range secrets {
			params[k] = v
		}
	}

	if c.RecordingPath != "" {
		params["recording-path"] = c.RecordingPath
		// Without this guacd writes nothing when the directory is absent, and
		// the absence of a recording is discovered when somebody asks for one.
		params["create-recording-path"] = "true"
	}

	return rac.Connection{
		Protocol: c.Protocol, Parameters: params,
		Width: width, Height: height, DPI: dpi,
	}, nil
}

// StartRACSession records that somebody connected.
func StartRACSession(ctx context.Context, db *pgxpool.Pool, c *RACConnection,
	userID, guacdID string) (string, error) {

	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO core.rac_sessions
			(connection_id, org_id, user_id, guacd_id, recording_path)
		VALUES ($1::uuid, $2::uuid, $3::uuid, NULLIF($4,''), NULLIF($5,''))
		RETURNING id::text`,
		c.ID, c.OrgID, userID, guacdID, c.RecordingPath).Scan(&id)
	return id, err
}

// EndRACSession records that it finished, and why.
func EndRACSession(ctx context.Context, db *pgxpool.Pool, sessionID, reason string) error {
	_, err := db.Exec(ctx, `
		UPDATE core.rac_sessions SET ended_at = now(), ended_reason = $2
		WHERE id = $1::uuid AND ended_at IS NULL`, sessionID, reason)
	return err
}

// SealRACSecrets encrypts connection credentials for storage.
func SealRACSecrets(root *keys.RootKey, secrets map[string]string) ([]byte, error) {
	if len(secrets) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	return root.Seal(raw, "rac-connection-secret")
}

var _ = pgx.ErrNoRows
