package store

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

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
	// ErrRACKey is a private key guacd could not use.
	ErrRACKey = errors.New("a private key is a PEM block, and only an ssh connection takes one")
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

// RACSpec is what a connection is registered with. Credentials are sealed, and
// what they leave out the viewer asks the person for; RecordingPath is where guacd
// writes a session recording, empty for none.
type RACSpec struct {
	Slug, Name, Protocol, Host string
	Port                       int
	RACCredentials
	RequireGroup  string
	RecordingPath string
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
	sealed, err := c.RACCredentials.seal(root, c.Protocol)
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
	// MaxConnections and MaxDurationSeconds are 0 for no limit.
	MaxConnections, MaxDurationSeconds int
}

// racMaxDuration is the longest a connection may be limited to, a month, which is
// past the point where the limit is still one.
const racMaxDuration = 30 * 24 * 3600

// CheckRACLimits refuses a limit that could not mean what it says.
func CheckRACLimits(maxConnections, maxDurationSeconds *int) error {
	if maxConnections != nil && *maxConnections < 0 {
		return fmt.Errorf("%w: max_connections must not be negative", ErrRACLimit)
	}
	if maxDurationSeconds != nil && (*maxDurationSeconds < 0 || *maxDurationSeconds > racMaxDuration) {
		return fmt.Errorf("%w: max_duration must be between 0 and %d seconds", ErrRACLimit, racMaxDuration)
	}
	return nil
}

// ErrRACLimit is a connection limit refused.
var ErrRACLimit = errors.New("that limit cannot be set")

// SetRACLimits sets how many may hold a connection, and for how long.
func SetRACLimits(ctx context.Context, q Execer, orgID, slug string, maxConnections, maxDurationSeconds *int) error {
	if err := CheckRACLimits(maxConnections, maxDurationSeconds); err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE core.rac_connections
		   SET max_connections = COALESCE($3::integer, max_connections),
		       max_duration_seconds = COALESCE($4::integer, max_duration_seconds)
		 WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, maxConnections, maxDurationSeconds)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRACUnknown
	}
	return nil
}

// RACConnections lists an organisation's connections by slug.
func RACConnections(ctx context.Context, q Querier, orgID string) ([]RACListing, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, slug, display_name, protocol, hostname, port, COALESCE(require_group, ''),
		       recording_path IS NOT NULL, enabled, secrets_enc IS NOT NULL, parameters,
		       max_connections, max_duration_seconds
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
			&c.Recorded, &c.Enabled, &c.HasLogin, &params, &c.MaxConnections, &c.MaxDurationSeconds); err != nil {
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

// ErrRACCredentialsForAnotherMachine is a connection holding credentials
// moved to another host or port without them: they were given for the machine
// it named, and guacd would type them into whatever answers at the new one.
var ErrRACCredentialsForAnotherMachine = errors.New("a connection's credentials were given for the machine it " +
	"names; moving it to another needs them given again, or they would be typed into whatever answers there")

// RACCredentials are what guacd signs in to the machine with. PrivateKey and
// Passphrase are for an ssh connection, in place of or beside a password.
type RACCredentials struct{ Login, Password, PrivateKey, Passphrase string }

// seal is the credentials as the row holds them: nil when there are none, so a
// connection with none asks the person who opens it.
func (c RACCredentials) seal(root *keys.RootKey, protocol string) ([]byte, error) {
	if c.PrivateKey != "" || c.Passphrase != "" {
		if block, _ := pem.Decode([]byte(c.PrivateKey)); block == nil || protocol != "ssh" {
			return nil, ErrRACKey
		}
	}
	secrets := map[string]string{}
	for name, value := range map[string]string{"username": c.Login, "password": c.Password,
		"private-key": c.PrivateKey, "passphrase": c.Passphrase} {
		if value != "" {
			secrets[name] = value
		}
	}
	if len(secrets) > 0 && root == nil {
		return nil, fmt.Errorf("a connection's credentials are sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	return SealRACSecrets(root, secrets)
}

// RACChange is what changes about a registered connection, a nil field left as
// it is; "" clears RequireGroup and RecordingPath. The protocol is fixed once
// registered.
type RACChange struct {
	Name, Host, RequireGroup, RecordingPath *string
	Port                                    *int
	// Credentials replaces all of them together; all empty clears them.
	Credentials *RACCredentials
}

// UpdateRACConnection changes a registered connection as a configuration file
// declares it (6.19).
func UpdateRACConnection(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, slug string, c RACChange) error {
	var host, protocol string
	var port int
	var holds bool
	if err := q.QueryRow(ctx, `SELECT hostname, port, protocol, secrets_enc IS NOT NULL FROM core.rac_connections
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug).Scan(&host, &port, &protocol, &holds); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRACUnknown
		}
		return err
	}
	moved := (c.Host != nil && *c.Host != host) || (c.Port != nil && *c.Port != port)
	if moved && holds && c.Credentials == nil {
		return ErrRACCredentialsForAnotherMachine
	}
	var sealed []byte
	if c.Credentials != nil {
		var err error
		if sealed, err = c.Credentials.seal(root, protocol); err != nil {
			return err
		}
	}
	_, err := q.Exec(ctx, `
		UPDATE core.rac_connections SET
			display_name   = COALESCE($3::text, display_name),
			hostname       = COALESCE($4::text, hostname),
			port           = COALESCE($5::integer, port),
			require_group  = CASE WHEN $6::text IS NULL THEN require_group ELSE NULLIF($6::text, '') END,
			recording_path = CASE WHEN $7::text IS NULL THEN recording_path ELSE NULLIF($7::text, '') END,
			secrets_enc    = CASE WHEN $8::boolean THEN $9::bytea ELSE secrets_enc END
		 WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug, c.Name, c.Host, c.Port, c.RequireGroup, c.RecordingPath, c.Credentials != nil, sealed)
	return err
}

// RACRecordingPath is where a connection's sessions are recorded, "" for
// nowhere: RACConnections says only whether, which is what a listing shows.
func RACRecordingPath(ctx context.Context, q outpostDB, orgID, slug string) (string, error) {
	var path string
	err := q.QueryRow(ctx, `SELECT COALESCE(recording_path, '') FROM core.rac_connections
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug).Scan(&path)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRACUnknown
	}
	return path, err
}

// HeldRACCredentials opens what a connection signs in with, so a plan can say
// whether the credentials a configuration file names differ. Never shown.
func HeldRACCredentials(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, slug string) (RACCredentials,
	error) {
	var sealed []byte
	if err := q.QueryRow(ctx, `SELECT secrets_enc FROM core.rac_connections WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RACCredentials{}, ErrRACUnknown
		}
		return RACCredentials{}, err
	}
	if len(sealed) == 0 {
		return RACCredentials{}, nil
	}
	if root == nil {
		return RACCredentials{}, fmt.Errorf("connection %q's credentials are sealed and no root key is loaded", slug)
	}
	plain, err := root.Open(sealed, "rac-connection-secret")
	if err != nil {
		return RACCredentials{}, fmt.Errorf("connection %q's credentials do not open: %w", slug, err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return RACCredentials{}, fmt.Errorf("connection %q's credentials are unreadable: %w", slug, err)
	}
	return RACCredentials{Login: secrets["username"], Password: secrets["password"],
		PrivateKey: secrets["private-key"], Passphrase: secrets["passphrase"]}, nil
}
