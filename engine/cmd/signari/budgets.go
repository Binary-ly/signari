package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// instanceOrgBudgets shows or sets an organisation's budgets (6.10): tokens
// its clients may be issued and sign-ins its pages may take, a minute. A flag
// not given keeps that budget; 0 restores the deployment's default.
func instanceOrgBudgets(ctx context.Context, conn *pgx.Conn, orgID string,
	tokens, signIns int, tokensGiven, signInsGiven bool) error {
	if orgID == "" {
		return fmt.Errorf("instance org-budgets needs -org")
	}
	b, err := store.BudgetsOf(ctx, conn, orgID)
	if errors.Is(err, store.ErrOrganizationUnknown) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	set := func(given bool, v int, into **int) {
		if !given {
			return
		}
		*into = nil
		if v != 0 {
			*into = &v
		}
	}
	set(tokensGiven, tokens, &b.TokensPerMinute)
	set(signInsGiven, signIns, &b.SignInsPerMinute)
	if tokensGiven || signInsGiven {
		if err := store.SetBudgets(ctx, conn, orgID, b); err != nil {
			return err
		}
	}
	show := func(kind store.BudgetKind, own *int) string {
		if own == nil {
			return fmt.Sprintf("%d (the deployment's default)", b.Effective(kind))
		}
		return fmt.Sprint(*own)
	}
	fmt.Printf("tokens a minute:   %s\nsign-ins a minute: %s\n",
		show(store.BudgetTokens, b.TokensPerMinute), show(store.BudgetSignIns, b.SignInsPerMinute))
	return nil
}
