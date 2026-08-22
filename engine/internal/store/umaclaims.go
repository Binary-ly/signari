package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/uma"
)

// UMA 2.0 claims gathering: the state a request accumulates between "the client
// asked" and "somebody decided".

// ErrInteractionUnknown means the claims interaction handle is unknown, expired,
// or already used.
var ErrInteractionUnknown = errors.New("this claims interaction is not valid")

// ErrPendingUnknown means no such pending request.
var ErrPendingUnknown = errors.New("no such pending request")

// UMASettings is a per-organisation UMA configuration.
type UMASettings struct {
	OwnerIntervention bool
	PollInterval      time.Duration
}

// LoadUMASettings reads an organisation's settings.
//
// A missing row is the ordinary case and is NOT an error: most deployments never
// configure resource-owner intervention, and the zero value is the correct
// behaviour for them -- a refusal stays final.
func LoadUMASettings(ctx context.Context, db Querier, orgID string) (UMASettings, error) {
	rows, err := db.Query(ctx, `
		SELECT owner_intervention, poll_interval_seconds
		FROM core.uma_settings WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return UMASettings{}, err
	}
	defer rows.Close()
	if rows.Next() {
		var s UMASettings
		var secs int
		if err := rows.Scan(&s.OwnerIntervention, &secs); err != nil {
			return UMASettings{}, err
		}
		s.PollInterval = time.Duration(secs) * time.Second
		return s, rows.Err()
	}
	return UMASettings{}, rows.Err()
}

// SetUMASettings writes an organisation's settings.
func SetUMASettings(ctx context.Context, e Execer, orgID string, s UMASettings) error {
	_, err := e.Exec(ctx, `
		INSERT INTO core.uma_settings (org_id, owner_intervention, poll_interval_seconds)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (org_id) DO UPDATE
		SET owner_intervention = EXCLUDED.owner_intervention,
		    poll_interval_seconds = EXCLUDED.poll_interval_seconds,
		    updated_at = now()`,
		orgID, s.OwnerIntervention, int(s.PollInterval.Seconds()))
	return err
}

// --- tickets that carry a requesting party ----------------------------------

// TicketOrigin describes the ticket a successor is minted from.
type TicketOrigin struct {
	OrgID           string
	ResourceServer  string
	Permissions     []uma.Permission
	RequestingParty string
	BoundClient     string
	PendingRequest  string
}

// MintSuccessorTicket records a new ticket continuing an authorization process.
//
// §3.3.6, of both need_info and request_submitted: "The value MUST NOT be the
// same as the one the client used to make its request." A caller passes a fresh
// random ticket; this records what it stands for.
//
// The successor carries the SAME permissions as its predecessor, verbatim.
// Re-deriving them would let the thing being asked for change between one refusal
// and the next retry, so a client that was told "you need X" could come back and
// be granted Y.
func MintSuccessorTicket(ctx context.Context, db *pgxpool.Pool, ticketHash []byte,
	o TicketOrigin, lifetime time.Duration) error {

	blob, err := json.Marshal(o.Permissions)
	if err != nil {
		return err
	}
	var party, pending, bound any
	if o.RequestingParty != "" {
		party = o.RequestingParty
	}
	if o.PendingRequest != "" {
		pending = o.PendingRequest
	}
	if o.BoundClient != "" {
		bound = o.BoundClient
	}
	_, err = db.Exec(ctx, `
		INSERT INTO core.uma_permission_tickets
			(org_id, resource_server, ticket_hash, permissions, expires_at,
			 requesting_party, pending_request_id, bound_client)
		VALUES ($1::uuid, $2, $3, $4, now() + $5::interval, $6::uuid, $7::uuid, $8)`,
		o.OrgID, o.ResourceServer, ticketHash, blob,
		fmt.Sprintf("%d seconds", int(lifetime.Seconds())),
		party, pending, bound)
	if err != nil {
		return fmt.Errorf("recording a successor permission ticket: %w", err)
	}
	return nil
}

// --- the claims interaction -------------------------------------------------

// Interaction is one visit to the claims interaction endpoint.
type Interaction struct {
	ID                string
	OrgID             string
	ClientID          string
	TicketHash        []byte
	ClaimsRedirectURI string
	// State is §3.3.3's: returned "if and only if the client provided it", so
	// the presence of the value matters and not only its content.
	State           string
	HasState        bool
	RequestingParty string
}

// BeginInteraction records what a confirmation page is about.
//
// The page is rendered from THIS row, and the submission names only the handle.
// Putting the ticket and the redirect URI in the form instead would let a
// submission carry values the person was never shown -- which is the shape of
// CSRF §5.1 requires this endpoint to be protected against, dressed as a
// same-origin POST.
func BeginInteraction(ctx context.Context, db *pgxpool.Pool, i Interaction,
	handleHash []byte, lifetime time.Duration) (string, error) {

	var state any
	if i.HasState {
		state = i.State
	}
	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO core.uma_claims_interactions
			(org_id, client_id, handle_hash, ticket_hash, claims_redirect_uri,
			 state, requesting_party, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid, now() + $8::interval)
		RETURNING id::text`,
		i.OrgID, i.ClientID, handleHash, i.TicketHash, i.ClaimsRedirectURI,
		state, i.RequestingParty,
		fmt.Sprintf("%d seconds", int(lifetime.Seconds()))).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("recording a claims interaction: %w", err)
	}
	return id, nil
}

// ConsumeInteraction claims an interaction, once.
//
// Same single-statement shape as redeeming a permission ticket, and for the same
// reason: two submissions of the same confirmation form must not both proceed,
// or the person's identity is bound to two tickets and only one of them was ever
// shown to them.
//
// requestingParty is checked IN THE STATEMENT rather than compared afterwards.
// The person who submits must be the person the page was rendered for -- a
// shared machine where somebody signs in between the GET and the POST is not
// exotic, and comparing after the fact leaves a window where the row is already
// spent by the wrong person.
func ConsumeInteraction(ctx context.Context, db *pgxpool.Pool, handleHash []byte,
	requestingParty string) (*Interaction, error) {

	var i Interaction
	var state *string
	err := db.QueryRow(ctx, `
		UPDATE core.uma_claims_interactions
		SET consumed_at = now()
		WHERE handle_hash = $1 AND consumed_at IS NULL AND expires_at > now()
		  AND requesting_party = $2::uuid
		RETURNING id::text, org_id::text, client_id, ticket_hash,
		          claims_redirect_uri, state, requesting_party::text`,
		handleHash, requestingParty).
		Scan(&i.ID, &i.OrgID, &i.ClientID, &i.TicketHash, &i.ClaimsRedirectURI,
			&state, &i.RequestingParty)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInteractionUnknown
	}
	if err != nil {
		return nil, err
	}
	if state != nil {
		i.State, i.HasState = *state, true
	}
	return &i, nil
}

// PurgeExpiredInteractions is the janitor's share.
func PurgeExpiredInteractions(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.uma_claims_interactions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- pending resource-owner decisions ---------------------------------------

// PendingRequest is a refused request awaiting a resource owner.
type PendingRequest struct {
	ID              string
	OrgID           string
	ResourceServer  string
	ClientID        string
	RequestingParty string
	// RequestingPartyEmail is filled by the listing, for an operator who has to
	// recognise the person before deciding.
	RequestingPartyEmail string
	Permissions          []uma.Permission
	State                string
	GrantedRelation      string
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

// SubmitRequest records a refusal for a resource owner to decide, returning the
// pending request.
//
// Idempotent by design: a client polling every thirty seconds arrives here on
// every poll, and each arrival must find the SAME decision rather than enqueue
// another. The partial unique index makes that a single statement -- ON CONFLICT
// DO UPDATE with a no-op touch so RETURNING yields the existing row, which a
// plain DO NOTHING would not.
func SubmitRequest(ctx context.Context, db *pgxpool.Pool, p PendingRequest,
	lifetime time.Duration) (*PendingRequest, error) {

	blob, err := json.Marshal(p.Permissions)
	if err != nil {
		return nil, err
	}
	// Look first, because ON CONFLICT cannot target a partial index predicate
	// that references a column not in the index. A pending row found here is
	// returned unchanged; the INSERT below still races against a concurrent poll,
	// and the unique index is what settles that -- see the retry.
	if existing, err := pendingFor(ctx, db, p.OrgID, p.ClientID, p.RequestingParty,
		p.ResourceServer); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrPendingUnknown) {
		return nil, err
	}

	var id string
	err = db.QueryRow(ctx, `
		INSERT INTO core.uma_pending_requests
			(org_id, resource_server, client_id, requesting_party, permissions, expires_at)
		VALUES ($1::uuid, $2, $3, $4::uuid, $5, now() + $6::interval)
		RETURNING id::text`,
		p.OrgID, p.ResourceServer, p.ClientID, p.RequestingParty, blob,
		fmt.Sprintf("%d seconds", int(lifetime.Seconds()))).Scan(&id)
	if err != nil {
		// The unique index fired: another poll from the same client for the same
		// person got there first. That is the expected outcome of the race, not an
		// error to report -- read theirs.
		if existing, e := pendingFor(ctx, db, p.OrgID, p.ClientID, p.RequestingParty,
			p.ResourceServer); e == nil {
			return existing, nil
		}
		return nil, fmt.Errorf("recording a pending request: %w", err)
	}
	p.ID, p.State = id, "pending"
	return &p, nil
}

func pendingFor(ctx context.Context, db *pgxpool.Pool, orgID, clientID,
	party, rs string) (*PendingRequest, error) {

	var p PendingRequest
	var blob []byte
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, resource_server, client_id,
		       requesting_party::text, permissions, state,
		       COALESCE(granted_relation,''), created_at, expires_at
		FROM core.uma_pending_requests
		WHERE org_id = $1::uuid AND client_id = $2 AND requesting_party = $3::uuid
		  AND resource_server = $4 AND state = 'pending' AND expires_at > now()`,
		orgID, clientID, party, rs).
		Scan(&p.ID, &p.OrgID, &p.ResourceServer, &p.ClientID, &p.RequestingParty,
			&blob, &p.State, &p.GrantedRelation, &p.CreatedAt, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPendingUnknown
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(blob, &p.Permissions); err != nil {
		return nil, err
	}
	return &p, nil
}

// PendingRequestByID reads one request by identifier, for an operator deciding.
func PendingRequestByID(ctx context.Context, db TrustMarkDB, id string) (*PendingRequest, error) {
	var p PendingRequest
	var blob []byte
	err := db.QueryRow(ctx, `
		SELECT p.id::text, p.org_id::text, p.resource_server, p.client_id,
		       p.requesting_party::text, COALESCE(u.email,''), p.permissions, p.state,
		       COALESCE(p.granted_relation,''), p.created_at, p.expires_at
		FROM core.uma_pending_requests p
		LEFT JOIN core.users u ON u.id = p.requesting_party
		WHERE p.id = $1::uuid`, id).
		Scan(&p.ID, &p.OrgID, &p.ResourceServer, &p.ClientID, &p.RequestingParty,
			&p.RequestingPartyEmail, &blob, &p.State, &p.GrantedRelation,
			&p.CreatedAt, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPendingUnknown
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(blob, &p.Permissions); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPendingRequests returns the requests awaiting a decision.
func ListPendingRequests(ctx context.Context, db TrustMarkDB, orgID string) ([]*PendingRequest, error) {
	rows, err := db.Query(ctx, `
		SELECT p.id::text, p.org_id::text, p.resource_server, p.client_id,
		       p.requesting_party::text, COALESCE(u.email,''), p.permissions, p.state,
		       COALESCE(p.granted_relation,''), p.created_at, p.expires_at
		FROM core.uma_pending_requests p
		LEFT JOIN core.users u ON u.id = p.requesting_party
		WHERE p.org_id = $1::uuid AND p.state = 'pending' AND p.expires_at > now()
		ORDER BY p.created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*PendingRequest
	for rows.Next() {
		var p PendingRequest
		var blob []byte
		if err := rows.Scan(&p.ID, &p.OrgID, &p.ResourceServer, &p.ClientID,
			&p.RequestingParty, &p.RequestingPartyEmail, &blob, &p.State,
			&p.GrantedRelation, &p.CreatedAt, &p.ExpiresAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(blob, &p.Permissions); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// DecidePendingRequest records an approval or a refusal.
//
// The guard is in the WHERE clause: `state = 'pending'`. Two owners deciding at
// once must not both succeed, because the second would overwrite the first's
// decision and the audit trail would keep only the later one -- and if they
// disagreed, the record would show the wrong answer with nothing to indicate a
// disagreement ever happened.
func DecidePendingRequest(ctx context.Context, e Execer, id, state, decidedBy,
	relation string) error {

	var by, rel any
	if decidedBy != "" {
		by = decidedBy
	}
	if relation != "" {
		rel = relation
	}
	tag, err := e.Exec(ctx, `
		UPDATE core.uma_pending_requests
		SET state = $2, decided_at = now(), decided_by = $3::uuid, granted_relation = $4
		WHERE id = $1::uuid AND state = 'pending'`, id, state, by, rel)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPendingUnknown
	}
	return nil
}

// PurgeExpiredPendingRequests is the janitor's share.
//
// A pending request is a standing offer to grant access. One nobody decided for
// a month should lapse rather than sit there to be approved later by somebody
// who no longer remembers the context.
func PurgeExpiredPendingRequests(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.uma_pending_requests WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RequestingPartyRef returns how the authorization model refers to a person.
//
// The email when there is one, the user id otherwise.
//
// Why the email is preferred: `decide` resolves a subject reference and then
// tries relations under BOTH the reference as given and the resolved user id, in
// that order. Passing the email therefore matches a relation stored either way,
// while passing the id matches only relations stored by id -- and `signari authz
// grant -principal user:alice@example.com` is how an operator actually writes
// one. Handing `decide` the id would silently miss every grant a human typed.
//
// ErrNoSuchSubject rather than an empty string for a person who is not there. A
// ticket bound to a deleted account must fail the grant, not quietly become an
// unidentified request that policy then evaluates for the client instead.
func RequestingPartyRef(ctx context.Context, db Querier, userID string) (string, error) {
	rows, err := db.Query(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", ErrNoSuchSubject
	}
	var email string
	if err := rows.Scan(&email); err != nil {
		return "", err
	}
	if email == "" {
		return userID, rows.Err()
	}
	return email, rows.Err()
}

// ErrNoSuchSubject means the person a request refers to is not in this directory.
var ErrNoSuchSubject = errors.New("no such subject")
