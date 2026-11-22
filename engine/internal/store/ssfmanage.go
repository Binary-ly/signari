package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// What a receiver may do to its own stream (SSF 1.0 §8.1). One stream to a client, so
// its credentials say which. An operator makes a stream and says where it delivers,
// and a receiver changes the rest of it: which events, its note on it, and its status.
// Where events go stays the operator's, or making one being theirs would mean nothing.

// ReceiverStream is a stream as its receiver sees it.
type ReceiverStream struct {
	ID, OrgID, ClientID, Method, Endpoint, Status, Description string
	Events                                                     []string
}

// ReceiverStreamOf reads a client's stream, or nil when it has none.
func ReceiverStreamOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (*ReceiverStream, error) {
	var st ReceiverStream
	err := q.QueryRow(ctx, `
		SELECT id::text, org_id::text, client_id, delivery_method, COALESCE(endpoint_url, ''), status,
		       description, events_requested
		  FROM core.ssf_streams WHERE client_id = $1`, clientID).
		Scan(&st.ID, &st.OrgID, &st.ClientID, &st.Method, &st.Endpoint, &st.Status, &st.Description, &st.Events)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading a client's stream: %w", err)
	}
	return &st, nil
}

// SetReceiverStream writes what a receiver changed, recorded as what an operator would
// want to find out about: it is their stream too, and a plan will show it as drift.
func SetReceiverStream(ctx context.Context, tx pgx.Tx, st *ReceiverStream, events []string, description string) error {
	if err := LockConfigVersion(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.ssf_streams SET events_requested = $2, description = $3
		WHERE id = $1::uuid`, st.ID, events, description); err != nil {
		return fmt.Errorf("updating a stream: %w", err)
	}
	return streamChanged(ctx, tx, st, map[string]any{"events": events})
}

// SetReceiverStreamStatus is SetStreamStatus for the receiver, and recorded likewise.
func SetReceiverStreamStatus(ctx context.Context, tx pgx.Tx, st *ReceiverStream, status, reason string) error {
	if err := LockConfigVersion(ctx, tx); err != nil {
		return err
	}
	if _, err := SetStreamStatus(ctx, tx, st.OrgID, st.ClientID, status, reason); err != nil {
		return err
	}
	return streamChanged(ctx, tx, st, map[string]any{"status": status})
}

func streamChanged(ctx context.Context, tx pgx.Tx, st *ReceiverStream, what map[string]any) error {
	detail := map[string]any{"client_id": st.ClientID, "stream_id": st.ID}
	for name, value := range what {
		detail[name] = value
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "ssf.stream_changed", OrgID: st.OrgID, Detail: detail}); err != nil {
		return fmt.Errorf("auditing a stream's change: %w", err)
	}
	_, err := tx.Exec(ctx, `UPDATE core.config_version SET version = version + 1, bumped_at = now() WHERE id = true`)
	return err
}

// StreamSubject is who an add or remove subject request names: an `iss_sub` subject,
// the form this server's own events take, or an email address.
type StreamSubject struct {
	Format, Issuer, Sub, Email string
}

// PersonOfStreamSubject finds the person a subject names in the stream's organisation,
// or "" for nobody. A subject in any other form names nobody here, and §9.1 is why that
// is no error: an answer that differed would say who has an account.
func PersonOfStreamSubject(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, st *ReceiverStream, issuer string, subject StreamSubject) (string, error) {
	switch {
	case subject.Format == "email":
		return FindLocalUserByEmail(ctx, q, st.OrgID, strings.TrimSpace(subject.Email))
	case subject.Format == "iss_sub" && subject.Issuer == issuer:
	default:
		return "", nil
	}
	person, err := PersonNamedBy(ctx, q, st.ClientID, subject.Sub)
	if errors.Is(err, ErrNoPairwiseSubject) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var id string
	err = q.QueryRow(ctx, `SELECT id::text FROM core.users WHERE id = $1 AND org_id = $2::uuid`,
		ExactUUIDOrNil(person), st.OrgID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SetStreamSubjectRemoved records whether a receiver wants to hear about a person, whom
// its client must have met for it to hear anything at all: adding a subject takes a
// removal back and opens nothing further, since §9.2 has it as a statement of interest,
// not a licence to learn about whoever it names.
func SetStreamSubjectRemoved(ctx context.Context, q Execer, st *ReceiverStream, person string, removed bool) error {
	if removed {
		_, err := q.Exec(ctx, `INSERT INTO core.ssf_removed_subjects (stream_id, org_id, user_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid) ON CONFLICT DO NOTHING`, st.ID, st.OrgID, person)
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM core.ssf_removed_subjects WHERE stream_id = $1::uuid AND user_id = $2::uuid`,
		st.ID, person)
	return err
}
