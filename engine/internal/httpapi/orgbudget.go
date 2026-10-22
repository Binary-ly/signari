package httpapi

import (
	"context"
	"math"
	"net/http"
	"strconv"

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
	if err != nil {
		s.log.Error("checking an organisation's budget", "org_id", orgID, "kind", kind, "err", err)
		return false, err
	}
	if !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
		s.log.Info("an organisation's budget is spent", "org_id", orgID, "kind", kind, "limit", res.Limit)
		return true, nil
	}
	return false, nil
}
