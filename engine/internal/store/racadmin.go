package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"signari.dev/engine/internal/keys"
)

// Remote-access connections as `signari rac` and the Admin API write them
// (6.07).

var (
	// ErrRACProtocol is a protocol guacd is not asked to speak here.
	ErrRACProtocol = errors.New("a remote-access connection is rdp, vnc or ssh")
	// ErrRACExists is a slug the organisation already gave a connection.
	ErrRACExists = errors.New("a remote-access connection with that slug already exists in the organisation")
	// ErrRACUnknown is a slug the organisation gave no connection.
	ErrRACUnknown = errors.New("no remote-access connection with that slug in the organisation")
	// ErrRACReservedParameter is a parameter the connection's own settings
	// supply; see RACReservedParameters.
	ErrRACReservedParameter = errors.New("that is not a parameter: the connection's own settings supply it")
)

// RACReservedParameters are the guacd parameters a connection's own settings
// supply, and which therefore cannot be set as parameters. The handshake
// writes the host, port, credentials and recording path over the parameters,
// so a parameter of one of these names would be stored, shown and ignored,
// and a credential would be stored in the clear, in a column a database read
// returns, when the reason it is sealed is that it must not be.
var RACReservedParameters = []string{"hostname", "port", "username", "password", "private-key", "passphrase",
	"recording-path", "create-recording-path"}

// racReserved is ErrRACReservedParameter naming the parameter.
type racReserved struct{ name string }

func (e racReserved) Error() string {
	return fmt.Sprintf("%s is not a parameter: the connection's own settings supply it", e.name)
}

func (e racReserved) Is(target error) bool { return target == ErrRACReservedParameter }

// RACSpec is what a connection is registered with. Login and Password are
// sealed; RecordingPath is where guacd writes a session recording, empty for
// none.
type RACSpec struct {
	Slug, Name, Protocol, Host string
	Port                       int
	Login, Password            string
	RequireGroup               string
	RecordingPath              string
}

// racDefaultPorts are each protocol's port when none is given.
var racDefaultPorts = map[string]int{"rdp": 3389, "vnc": 5900, "ssh": 22}

// AddRACConnection registers a machine somebody may reach through the
// browser. The credentials are sealed, never stored in the parameters
// column: a database read must not be a working login to somebody's estate.
func AddRACConnection(ctx context.Context, q outpostDB, root *keys.RootKey, orgID string, c RACSpec) (string, error) {
	port, known := racDefaultPorts[c.Protocol]
	if !known {
		return "", ErrRACProtocol
	}
	if c.Port != 0 {
		port = c.Port
	}
	if c.Name == "" {
		c.Name = c.Slug
	}
	secrets := map[string]string{}
	if c.Login != "" {
		secrets["username"] = c.Login
	}
	if c.Password != "" {
		secrets["password"] = c.Password
	}
	if len(secrets) > 0 && root == nil {
		return "", fmt.Errorf("a connection's credentials are sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	sealed, err := SealRACSecrets(root, secrets)
	if err != nil {
		return "", err
	}
	var id string
	if err := q.QueryRow(ctx, `
		INSERT INTO core.rac_connections
			(org_id, slug, display_name, protocol, hostname, port, secrets_enc,
			 require_group, recording_path)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, NULLIF($8,''), NULLIF($9,''))
		RETURNING id::text`,
		orgID, c.Slug, c.Name, c.Protocol, c.Host, port, sealed, c.RequireGroup, c.RecordingPath).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return "", ErrRACExists
		}
		return "", err
	}
	return id, nil
}

// SetRACEnabled takes a connection out of service, or puts it back (2.29).
// Disabled, it is neither listed nor connectable from the next request; a
// session already open runs until it closes.
func SetRACEnabled(ctx context.Context, q Execer, orgID, slug string, enabled bool) error {
	tag, err := q.Exec(ctx, `UPDATE core.rac_connections SET enabled = $3
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRACUnknown
	}
	return nil
}

// SetRACParameters replaces a connection's guacd parameters (2.29); empty
// clears them, and guacd's defaults apply. guacd refuses a name it does not
// take for the protocol at the next connect, by name, which is where the
// protocol's own list is known.
func SetRACParameters(ctx context.Context, q Execer, orgID, slug string, params map[string]string) error {
	for k := range params {
		if slices.Contains(RACReservedParameters, k) {
			return racReserved{k}
		}
	}
	if params == nil {
		params = map[string]string{}
	}
	blob, err := json.Marshal(params)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE core.rac_connections SET parameters = $3
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, blob)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRACUnknown
	}
	return nil
}

// RACListing is one connection as an administrator sees it: never its
// credentials, and only whether it is recorded, not where.
type RACListing struct {
	ID, Slug, Name, Protocol, Host string
	Port                           int
	RequireGroup                   string
	Recorded, Enabled, HasLogin    bool
	Parameters                     map[string]string
}

// RACConnections lists an organisation's connections by slug.
func RACConnections(ctx context.Context, q Querier, orgID string) ([]RACListing, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, slug, display_name, protocol, hostname, port, COALESCE(require_group, ''),
		       recording_path IS NOT NULL, enabled, secrets_enc IS NOT NULL, parameters
		  FROM core.rac_connections WHERE org_id = $1::uuid ORDER BY slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RACListing
	for rows.Next() {
		var c RACListing
		var params []byte
		if err := rows.Scan(&c.ID, &c.Slug, &c.Name, &c.Protocol, &c.Host, &c.Port, &c.RequireGroup,
			&c.Recorded, &c.Enabled, &c.HasLogin, &params); err != nil {
			return nil, err
		}
		c.Parameters = map[string]string{}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &c.Parameters); err != nil {
				return nil, fmt.Errorf("connection %q has unreadable parameters: %w", c.Slug, err)
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
