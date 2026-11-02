package httpapi

import (
	"context"
	"math"
	"net/http"
	"strconv"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
)

// Each organisation's budget (6.10), charged where a request is known to be an
// organisation's: at the token endpoint once the client has authenticated, and
// at sign-in once the page or the account names one. Counted per organisation
// in the shared rate table, so one tenant's batch job or sign-in rush spends its
// own budget and leaves every other tenant's whole.

// orgBudgetSpent charges one request to orgID's budget for kind, and reports
// whether it is spent; err is a failed read, which the caller answers as the
// server's.
func (s *Server) orgBudgetSpent(ctx context.Context, w http.ResponseWriter, orgID string,
	kind store.BudgetKind) (spent bool, err error) {
	res, err := store.AllowOrgBudget(ctx, s.db, orgID, kind)
	return s.budgetAnswer(ctx, w, orgID, kind, res, err)
}

// tokenBudgetSpent is orgBudgetSpent for a client, which came with its budget.
func (s *Server) tokenBudgetSpent(ctx context.Context, w http.ResponseWriter, c *clients.Client) (bool, error) {
	res, err := store.ChargeOrgBudget(ctx, s.db, c.OrgID, store.BudgetTokens,
		store.OrgBudgets{TokensPerMinute: c.TokenBudget})
	return s.budgetAnswer(ctx, w, c.OrgID, store.BudgetTokens, res, err)
}

func (s *Server) budgetAnswer(ctx context.Context, w http.ResponseWriter, orgID string, kind store.BudgetKind, res store.RateResult,
	err error) (spent bool, _ error) {
	if err != nil {
		s.log.ErrorContext(ctx, "checking an organisation's budget", "org_id", orgID, "kind", kind, "err", err)
		return false, err
	}
	if !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
		s.log.InfoContext(ctx, "an organisation's budget is spent", "org_id", orgID, "kind", kind, "limit", res.Limit)
		return true, nil
	}
	return false, nil
}
