package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// A second person for the Admin API's highest-value changes (ASVS 5.0.0 V2.3.5,
// specs/asvs-5.0.0.txt:1570-1573, migration 0296). An organisation names the
// kinds in approvals_required; such a request is kept, pending, until somebody
// else who may make it approves it, or it is rejected, or it expires.

// The kinds of change that can be made to wait.
const (
	ApprovalSubjectErasure = "subject_erasure"
	ApprovalOwnerGrant     = "owner_grant"
	// ApprovalsRelaxed is relaxing approvals_required itself: always waits when
	// it takes a kind away, or one token could turn the rule off and then act
	// alone. Not a kind an organisation names.
	ApprovalsRelaxed = "approvals_relaxed"
)

// ApprovalKinds are what approvals_required may name.
var ApprovalKinds = []string{ApprovalSubjectErasure, ApprovalOwnerGrant}

// ApprovalLifetime is how long a request waits before it expires unapproved.
const ApprovalLifetime = 24 * time.Hour

var (
	// ErrApprovalKind is a kind approvals_required may not name.
	ErrApprovalKind = errors.New("approvals_required names subject_erasure and owner_grant only")
	// ErrApprovalNotPending is an approval that does not exist here, was
	// decided, is being decided, or expired.
	ErrApprovalNotPending = errors.New("no such approval is waiting")
	// ErrApprovalSelf is the one who asked deciding: one person is not two.
	ErrApprovalSelf = errors.New("the one who asked cannot approve it; somebody else has to")
)

// Approval is one request waiting for, or decided by, a second person.
type Approval struct {
	ID, OrgID, Kind, Method, Path, Summary string
	Body                                   []byte
	RequestedBy, RequestedName             string
	RequestedAt, ExpiresAt                 time.Time
	Status                                 string
	DecidedBy, DecidedName                 string
	DecidedAt                              *time.Time
	ResultStatus                           *int
}

// ApprovalsRequired is what an organisation makes wait.
func ApprovalsRequired(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) ([]string, error) {
	var kinds []string
	err := q.QueryRow(ctx, `SELECT approvals_required FROM core.organizations WHERE id = $1::uuid`,
		ExactUUIDOrNil(orgID)).Scan(&kinds)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return kinds, err
}

// SetApprovalsRequired replaces what an organisation makes wait, and returns
// what it was.
func SetApprovalsRequired(ctx context.Context, tx pgx.Tx, orgID string, kinds []string) ([]string, error) {
	for _, k := range kinds {
		if !slices.Contains(ApprovalKinds, k) {
			return nil, fmt.Errorf("%w, not %q", ErrApprovalKind, k)
		}
	}
	kinds = slices.Compact(slices.Sorted(slices.Values(kinds)))
	if kinds == nil {
		kinds = []string{}
	}
	var was []string
	err := tx.QueryRow(ctx, `SELECT approvals_required FROM core.organizations WHERE id = $1::uuid FOR UPDATE`,
		orgID).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOrganizationNotFound
	}
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE core.organizations SET approvals_required = $2 WHERE id = $1::uuid`, orgID, kinds)
	return was, err
}

// RequestApproval keeps a request to wait for a second person, and returns its
// id and when it expires. Bodies of decisions and expiries past are cleared,
// and rows a month old deleted, here, where the table is written anyway.
func RequestApproval(ctx context.Context, tx pgx.Tx, a Approval) (string, time.Time, error) {
	if _, err := tx.Exec(ctx, `
		DELETE FROM core.admin_approvals WHERE org_id = $1::uuid AND requested_at < now() - interval '30 days'`,
		a.OrgID); err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.admin_approvals SET body = ''::bytea
		 WHERE org_id = $1::uuid AND body <> ''::bytea AND expires_at < now()`, a.OrgID); err != nil {
		return "", time.Time{}, err
	}
	var id string
	var expires time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO core.admin_approvals (org_id, kind, method, path, body, summary, requested_by,
		                                  requested_name, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))
		RETURNING id::text, expires_at`,
		a.OrgID, a.Kind, a.Method, a.Path, a.Body, a.Summary, a.RequestedBy, a.RequestedName,
		int(ApprovalLifetime.Seconds())).Scan(&id, &expires)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("keeping a request for approval: %w", err)
	}
	return id, expires, nil
}

// ClaimApproval takes a pending, unexpired approval for deciding by approver:
// it moves to approving, so a second approver at the same moment finds it
// taken. The one who asked may not.
func ClaimApproval(ctx context.Context, tx pgx.Tx, id, approver string) (Approval, error) {
	a, err := pendingApproval(ctx, tx, id)
	if err != nil {
		return a, err
	}
	if a.RequestedBy == approver {
		return a, ErrApprovalSelf
	}
	_, err = tx.Exec(ctx, `UPDATE core.admin_approvals SET status = 'approving' WHERE id = $1::uuid`, id)
	return a, err
}

// FinishApproval records how a claimed approval's replay answered: approved on
// a success, its body cleared; back to pending otherwise, so an approver who
// could not make the change has not used the request up.
func FinishApproval(ctx context.Context, tx pgx.Tx, id, approver, approverName string, status int) error {
	if status >= 200 && status < 300 {
		_, err := tx.Exec(ctx, `UPDATE core.admin_approvals
			SET status = 'approved', body = ''::bytea, decided_by = $2, decided_name = $3, decided_at = now(),
			    result_status = $4
			WHERE id = $1::uuid AND status = 'approving'`, id, approver, approverName, status)
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE core.admin_approvals SET status = 'pending', result_status = $2
		WHERE id = $1::uuid AND status = 'approving'`, id, status)
	return err
}

// RejectApproval turns down an approval PendingApproval read and locked; the
// caller decides who may (the one who asked, withdrawing, or somebody who may
// make the change).
func RejectApproval(ctx context.Context, tx pgx.Tx, id, by, byName string) error {
	_, err := tx.Exec(ctx, `UPDATE core.admin_approvals
		SET status = 'rejected', body = ''::bytea, decided_by = $2, decided_name = $3, decided_at = now()
		WHERE id = $1::uuid AND status = 'pending'`, id, by, byName)
	return err
}

// PendingApproval reads a pending, unexpired approval and locks it.
func PendingApproval(ctx context.Context, tx pgx.Tx, id string) (Approval, error) {
	return pendingApproval(ctx, tx, id)
}

func pendingApproval(ctx context.Context, tx pgx.Tx, id string) (Approval, error) {
	var a Approval
	err := tx.QueryRow(ctx, `
		SELECT id::text, org_id::text, kind, method, path, body, summary, requested_by, requested_name,
		       requested_at, expires_at, status
		  FROM core.admin_approvals
		 WHERE id = $1::uuid AND status = 'pending' AND expires_at > now()
		 FOR UPDATE`, ExactUUIDOrNil(id)).
		Scan(&a.ID, &a.OrgID, &a.Kind, &a.Method, &a.Path, &a.Body, &a.Summary, &a.RequestedBy,
			&a.RequestedName, &a.RequestedAt, &a.ExpiresAt, &a.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrApprovalNotPending
	}
	return a, err
}

// ApprovalOrg is the organisation an approval belongs to, for a caller to be
// held to before it learns anything else of it.
func ApprovalOrg(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) (string, error) {
	var org string
	err := q.QueryRow(ctx, `SELECT org_id::text FROM core.admin_approvals WHERE id = $1::uuid`,
		ExactUUIDOrNil(id)).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrApprovalNotPending
	}
	return org, err
}

// ListApprovals is an organisation's approvals, newest first, without bodies:
// a pending one past its expiry is reported as expired.
func ListApprovals(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]Approval, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, org_id::text, kind, method, path, summary, requested_by, requested_name,
		       requested_at, expires_at,
		       CASE WHEN status = 'pending' AND expires_at <= now() THEN 'expired' ELSE status END,
		       COALESCE(decided_by, ''), COALESCE(decided_name, ''), decided_at, result_status
		  FROM core.admin_approvals WHERE org_id = $1::uuid
		 ORDER BY org_id, requested_at DESC LIMIT 200`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.OrgID, &a.Kind, &a.Method, &a.Path, &a.Summary, &a.RequestedBy,
			&a.RequestedName, &a.RequestedAt, &a.ExpiresAt, &a.Status, &a.DecidedBy, &a.DecidedName,
			&a.DecidedAt, &a.ResultStatus); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
