package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Each organisation's budget (0193, 6.10): what its clients may be issued and
// its pages may take in a minute, counted per organisation, so a noisy tenant
// spends its own and not another's.

// The deployment's defaults, an organisation with no budget of its own.
const (
	DefaultTokenBudget  = 6000
	DefaultSignInBudget = 1200
	MaxOrgBudget        = 1000000
)

// BudgetKind is what a budget counts.
type BudgetKind string

const (
	BudgetTokens  BudgetKind = "tokens"
	BudgetSignIns BudgetKind = "signins"
)

// OrgBudgets is an organisation's budgets as set, nil for the default.
type OrgBudgets struct {
	TokensPerMinute  *int
	SignInsPerMinute *int
}

// Effective is the budget in force for kind.
func (b OrgBudgets) Effective(kind BudgetKind) int {
	if kind == BudgetTokens {
		if b.TokensPerMinute != nil {
			return *b.TokensPerMinute
		}
		return DefaultTokenBudget
	}
	if b.SignInsPerMinute != nil {
		return *b.SignInsPerMinute
	}
	return DefaultSignInBudget
}

// ErrOrgBudget is a budget outside 1 to MaxOrgBudget.
var ErrOrgBudget = fmt.Errorf("a budget is 1 to %d a minute, or none for the deployment's default", MaxOrgBudget)

// ErrOrganizationUnknown is an organisation id with no row.
var ErrOrganizationUnknown = errors.New("no organisation has that id")

// BudgetsOf reads an organisation's budgets.
func BudgetsOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (OrgBudgets, error) {
	var b OrgBudgets
	err := q.QueryRow(ctx, `SELECT token_budget_per_minute, signin_budget_per_minute
		FROM core.organizations WHERE id::text = $1`, orgID).Scan(&b.TokensPerMinute, &b.SignInsPerMinute)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, ErrOrganizationUnknown
	}
	return b, err
}

// SetBudgets replaces an organisation's budgets; nil restores the default.
func SetBudgets(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string, b OrgBudgets) error {
	for _, v := range []*int{b.TokensPerMinute, b.SignInsPerMinute} {
		if v != nil && (*v < 1 || *v > MaxOrgBudget) {
			return ErrOrgBudget
		}
	}
	var id string
	err := q.QueryRow(ctx, `UPDATE core.organizations
		SET token_budget_per_minute = $2, signin_budget_per_minute = $3, updated_at = now()
		WHERE id::text = $1 RETURNING id::text`, orgID, b.TokensPerMinute, b.SignInsPerMinute).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOrganizationUnknown
	}
	return err
}

// AllowOrgBudget counts one request against an organisation's budget for
// kind, read on this request, in a minute's window shared by every instance.
func AllowOrgBudget(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string, kind BudgetKind) (RateResult, error) {
	b, err := BudgetsOf(ctx, q, orgID)
	if err != nil {
		return RateResult{}, err
	}
	return AllowRate(ctx, q, "org:"+orgID+":"+string(kind), b.Effective(kind), time.Minute)
}
