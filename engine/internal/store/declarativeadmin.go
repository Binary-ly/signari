package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/policy"
)

// An organisation's access policy and sign-in flows, as `signari policy
// apply`, `signari flow apply` and the Admin API install them (6.07).
//
// Each document is parsed BEFORE it is stored. A flow file that reaches the
// table has had its own test cases run and has been proved unable to issue a
// session without authenticating somebody; storing first and validating at
// load would put a document the engine will refuse into a table an operator
// already believes is deployed.

// ErrInvalidDocument is a policy or flow document that will not load. Its
// message is the parser's, which names the line or the failing test case.
var ErrInvalidDocument = errors.New("the document will not load")

type invalidDocument struct{ err error }

func (e invalidDocument) Error() string        { return e.err.Error() }
func (e invalidDocument) Unwrap() error        { return e.err }
func (e invalidDocument) Is(target error) bool { return target == ErrInvalidDocument }

// ApplyAccessPolicy makes doc the organisation's access policy, read on the
// next decision.
func ApplyAccessPolicy(ctx context.Context, q Execer, orgID string, doc []byte) (*policy.File, error) {
	f, err := policy.Parse(doc)
	if err != nil {
		return nil, invalidDocument{err}
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO core.access_policies (org_id, document, applied_at)
		VALUES ($1::uuid, $2, now())
		ON CONFLICT (org_id) DO UPDATE
			SET document = EXCLUDED.document, applied_at = now()`,
		orgID, string(doc)); err != nil {
		return nil, err
	}
	return f, nil
}

// ApplySignInFlow makes doc the organisation's sign-in flows. Engines pick it
// up within thirty seconds (ADR-008's flow cache).
func ApplySignInFlow(ctx context.Context, q Execer, orgID string, doc []byte) (*flow.File, error) {
	f, err := flow.Parse(doc)
	if err != nil {
		return nil, invalidDocument{err}
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO core.sign_in_flows (org_id, document)
		VALUES ($1::uuid, $2)
		ON CONFLICT (org_id) DO UPDATE
			SET document = EXCLUDED.document, applied_at = now()`,
		orgID, string(doc)); err != nil {
		return nil, err
	}
	return f, nil
}

// AppliedDocument is a policy or flow document as stored; AppliedAt is nil
// when the organisation has none.
type AppliedDocument struct {
	Document  string
	AppliedAt *time.Time
}

// AccessPolicyOf returns the access policy in force. None means everything
// is allowed.
func AccessPolicyOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (AppliedDocument, error) {
	return appliedDocument(ctx, q, `SELECT document, applied_at FROM core.access_policies WHERE org_id = $1::uuid`,
		orgID)
}

// SignInFlowOf returns the sign-in flows applied. None means the built-in
// flows.
func SignInFlowOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (AppliedDocument, error) {
	return appliedDocument(ctx, q, `SELECT document, applied_at FROM core.sign_in_flows WHERE org_id = $1::uuid`,
		orgID)
}

func appliedDocument(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, query, orgID string) (AppliedDocument, error) {
	var d AppliedDocument
	var at time.Time
	err := q.QueryRow(ctx, query, orgID).Scan(&d.Document, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return AppliedDocument{}, nil
	}
	if err != nil {
		return AppliedDocument{}, err
	}
	d.AppliedAt = &at
	return d, nil
}
