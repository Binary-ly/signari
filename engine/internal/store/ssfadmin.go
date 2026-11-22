package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ssf"
)

// Shared Signals streams as `signari ssf add-stream` and the Admin API
// register them (6.07): a relying party's receiver, pushed to or polling.

var (
	// ErrStreamExists is a client that has a stream: one receiver per
	// relying party.
	ErrStreamExists = errors.New("that client already has a stream; one receiver per relying party")
	// ErrStreamClientElsewhere is a client the organisation does not have.
	// A stream carries events about the people who signed in to its client,
	// so one registered under another organisation sends that organisation's
	// people's events to a receiver it never chose (0.35).
	ErrStreamClientElsewhere = errors.New("the organisation has no client of that id")
	// ErrStreamInvalid is a stream the rules refuse; its message says which.
	ErrStreamInvalid = errors.New("the stream is not one this engine can deliver")
)

type streamInvalid struct{ msg string }

func (e streamInvalid) Error() string        { return e.msg }
func (e streamInvalid) Is(target error) bool { return target == ErrStreamInvalid }

// SealContextSSFToken binds a sealed receiver token to its column.
const SealContextSSFToken = "ssf-stream-token"

// StreamSpec is a stream to register. A poll stream is pulled, not pushed: it
// has no endpoint of ours to POST to, and the receiver authenticates to us as
// its OAuth client rather than with a token we would push. Events default to
// session-revoked.
type StreamSpec struct {
	ClientID      string
	Endpoint      string
	ReceiverToken string
	Events        []string
	Poll          bool
}

// Validate refuses a stream before anything is loaded or written, and fills
// in the default events.
func (s *StreamSpec) Validate() error {
	if s.Poll {
		// Refused rather than ignored: a stored endpoint nobody reads is a
		// misconfiguration waiting to look like a delivery bug.
		if s.Endpoint != "" {
			return streamInvalid{"a poll stream has no endpoint: the receiver pulls from POST /ssf/poll, " +
				"authenticating as its client"}
		}
		if s.ReceiverToken != "" {
			return streamInvalid{"a poll stream has no receiver token: the receiver authenticates to us " +
				"with its client credentials when it polls"}
		}
	} else {
		if s.Endpoint == "" {
			return streamInvalid{"give the https URL to push Security Event Tokens to, or make it a poll " +
				"stream the receiver pulls from"}
		}
		if !strings.HasPrefix(s.Endpoint, "https://") {
			return streamInvalid{fmt.Sprintf("the endpoint must be https: %q would carry security events "+
				"about real users across the network in the clear", s.Endpoint)}
		}
	}
	// An allow-list: sending an event a receiver did not ask for is at best
	// noise and at worst a disclosure.
	if len(s.Events) == 0 {
		s.Events = []string{ssf.EventSessionRevoked}
	}
	for _, e := range s.Events {
		if !slices.Contains(ssf.SupportedEvents(), e) {
			return streamInvalid{fmt.Sprintf("event %q is not one this engine emits. Supported: %s",
				e, strings.Join(ssf.SupportedEvents(), ", "))}
		}
	}
	return nil
}

// AddStream registers a client's stream in its organisation. The receiver's
// bearer token is sealed with the root key: it is a third party's credential,
// and a database backup must not hand it over.
func AddStream(ctx context.Context, q outpostDB, root *keys.RootKey, orgID string, s StreamSpec) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	var mine bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1 AND org_id = $2::uuid)`,
		s.ClientID, orgID).Scan(&mine); err != nil {
		return "", err
	}
	if !mine {
		return "", ErrStreamClientElsewhere
	}
	var sealed []byte
	if s.ReceiverToken != "" {
		if root == nil {
			return "", fmt.Errorf("a receiver token is sealed under SIGNARI_ROOT_KEY, which is not loaded")
		}
		var err error
		if sealed, err = root.Seal([]byte(s.ReceiverToken), SealContextSSFToken); err != nil {
			return "", fmt.Errorf("sealing the receiver's token: %w", err)
		}
	}
	method := "push"
	var endpoint any = s.Endpoint
	if s.Poll {
		method, endpoint = "poll", nil
	}
	var id string
	if err := q.QueryRow(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url,
		                              auth_token, events_requested)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		RETURNING id::text`, orgID, s.ClientID, method, endpoint, sealed, s.Events).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return "", ErrStreamExists
		}
		return "", err
	}
	return id, nil
}

// ErrStreamTokenForAnotherEndpoint is a push stream holding a receiver token
// moved to another endpoint without one: the token was the receiver's, and
// would be pushed to whoever answers at the new address.
var ErrStreamTokenForAnotherEndpoint = errors.New("a stream's receiver token was given for the endpoint it " +
	"pushes to; a new endpoint needs the token given again, or it would be sent there")

// UpdateStream changes a client's stream as a configuration file declares it
// (6.25), checked as AddStream checks a new one. withToken writes the
// receiver token given; without it the held one is kept, or dropped when the
// stream becomes a poll stream, which has none.
func UpdateStream(ctx context.Context, q outpostDB, root *keys.RootKey, orgID string, s StreamSpec,
	withToken bool) error {
	if !withToken {
		s.ReceiverToken = ""
	}
	if err := s.Validate(); err != nil {
		return err
	}
	var endpoint string
	var held bool
	if err := q.QueryRow(ctx, `SELECT COALESCE(endpoint_url, ''), auth_token IS NOT NULL FROM core.ssf_streams
		WHERE org_id = $1::uuid AND client_id = $2`, orgID, s.ClientID).Scan(&endpoint, &held); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStreamUnknown
		}
		return err
	}
	if !s.Poll && held && !withToken && endpoint != s.Endpoint {
		return ErrStreamTokenForAnotherEndpoint
	}
	var sealed []byte
	if withToken && s.ReceiverToken != "" {
		if root == nil {
			return fmt.Errorf("a receiver token is sealed under SIGNARI_ROOT_KEY, which is not loaded")
		}
		var err error
		if sealed, err = root.Seal([]byte(s.ReceiverToken), SealContextSSFToken); err != nil {
			return fmt.Errorf("sealing the receiver's token: %w", err)
		}
	}
	method := "push"
	var url any = s.Endpoint
	if s.Poll {
		method, url = "poll", nil
	}
	_, err := q.Exec(ctx, `
		UPDATE core.ssf_streams SET delivery_method = $3, endpoint_url = $4, events_requested = $5,
		       auth_token = CASE WHEN $3 = 'poll' THEN NULL WHEN $6 THEN $7::bytea ELSE auth_token END
		 WHERE org_id = $1::uuid AND client_id = $2`, orgID, s.ClientID, method, url, s.Events, withToken, sealed)
	return err
}

// StreamReceiverToken opens a stream's receiver token, so a plan can say
// whether the one a file names differs. Never shown.
func StreamReceiverToken(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, clientID string) (string, error) {
	var sealed []byte
	if err := q.QueryRow(ctx, `SELECT auth_token FROM core.ssf_streams WHERE org_id = $1::uuid AND client_id = $2`,
		orgID, clientID).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrStreamUnknown
		}
		return "", err
	}
	if len(sealed) == 0 {
		return "", nil
	}
	if root == nil {
		return "", fmt.Errorf("the stream's receiver token is sealed and no root key is loaded")
	}
	plain, err := root.Open(sealed, SealContextSSFToken)
	return string(plain), err
}

// RemoveStream stops a client's stream, as a pruned configuration file asks.
func RemoveStream(ctx context.Context, q outpostDB, orgID, clientID string) error {
	_, err := q.Exec(ctx, `DELETE FROM core.ssf_streams WHERE org_id = $1::uuid AND client_id = $2`, orgID, clientID)
	return err
}

// Stream is one registered stream, without its receiver token.
type Stream struct {
	ID, ClientID, Method, Endpoint, Status string
	Events                                 []string
	HasToken                               bool
}

// Streams lists an organisation's streams by client, among the clients given;
// nil means every client.
func Streams(ctx context.Context, q Querier, orgID string, clients []string) ([]Stream, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, client_id, delivery_method, COALESCE(endpoint_url, ''), status, events_requested,
		       auth_token IS NOT NULL
		  FROM core.ssf_streams
		 WHERE org_id = $1::uuid AND ($2::text[] IS NULL OR client_id = ANY($2::text[]))
		 ORDER BY client_id`, orgID, clients)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stream
	for rows.Next() {
		var s Stream
		if err := rows.Scan(&s.ID, &s.ClientID, &s.Method, &s.Endpoint, &s.Status, &s.Events, &s.HasToken); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
