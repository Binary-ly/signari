package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PairwisePrefix opens a subject that stands for a person to one sector, so a token's
// subject can be told from a person's id or a client's without a read.
const PairwisePrefix = "sgp_"

// ErrNoPairwiseSubject is a subject with the prefix that stands for nobody: the person
// it stood for has gone, and their rows with them.
var ErrNoPairwiseSubject = errors.New("no such pairwise subject")

// SubjectDB is a pool or a transaction. A subject is made as it is first needed, and a
// grant makes it in its own transaction, so it goes if the grant is undone.
type SubjectDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PairwiseSubject is what a sector knows a person by, made the first time it asks. A
// subject that is no person's, a client's own token for one, is answered as it came.
func PairwiseSubject(ctx context.Context, q SubjectDB, orgID, sector, subject string) (string, error) {
	user, person := CanonicalUUID(subject)
	if !person {
		return subject, nil
	}
	var found string
	read := func() error {
		return q.QueryRow(ctx, `SELECT subject FROM core.pairwise_subjects
			WHERE org_id = $1::uuid AND sector = $2 AND user_id = $3::uuid`, orgID, sector, user).Scan(&found)
	}
	err := read()
	if err == nil {
		return found, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("reading a pairwise subject: %w", err)
	}
	id, err := newOpaqueID()
	if err != nil {
		return "", err
	}
	// From core.users, because a client's id can be shaped like a person's. A racing
	// grant's row is as good as this one, and read back below.
	if _, err := q.Exec(ctx, `
		INSERT INTO core.pairwise_subjects (subject, org_id, sector, user_id)
		SELECT $1, $2::uuid, $3, id FROM core.users WHERE id = $4::uuid
		ON CONFLICT (org_id, sector, user_id) DO NOTHING`, PairwisePrefix+id, orgID, sector, user); err != nil {
		return "", fmt.Errorf("making a pairwise subject: %w", err)
	}
	switch err := read(); {
	case err == nil:
		return found, nil
	case errors.Is(err, pgx.ErrNoRows):
		return subject, nil
	default:
		return "", fmt.Errorf("reading a pairwise subject: %w", err)
	}
}

// ClientSubject is how a client knows a person, for a notice that has only the client's id.
func ClientSubject(ctx context.Context, q SubjectDB, clientID, subject string) (string, error) {
	var kind, sector, orgID string
	if err := q.QueryRow(ctx, `SELECT subject_type, sector, org_id::text FROM core.clients
		WHERE client_id = $1`, clientID).Scan(&kind, &sector, &orgID); err != nil {
		return "", fmt.Errorf("reading how client %q names people: %w", clientID, err)
	}
	if kind != "pairwise" {
		return subject, nil
	}
	return PairwiseSubject(ctx, q, orgID, sector, subject)
}

// PersonNamedBy reads a subject in a token issued to clientID back to what the engine
// calls it. Anything but a pairwise subject is that already. One that stands for nobody
// is ErrNoPairwiseSubject and is not passed on, since a check after this one could only
// read it as the name of a client, which is an accident waiting for a client called that.
func PersonNamedBy(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID, subject string) (string, error) {
	if subject == clientID || !strings.HasPrefix(subject, PairwisePrefix) {
		return subject, nil
	}
	var user string
	err := q.QueryRow(ctx, `SELECT user_id::text FROM core.pairwise_subjects WHERE subject = $1`, subject).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoPairwiseSubject
	}
	if err != nil {
		return "", fmt.Errorf("reading a pairwise subject: %w", err)
	}
	return user, nil
}
