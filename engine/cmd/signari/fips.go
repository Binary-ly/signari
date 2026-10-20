package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/doctor"
)

// fipsPreflight refuses to serve under GODEBUG=fips140=only with anything
// configured that the module would refuse by panicking a request (3.11):
// doctor.FIPSRefusals, which doctor reports from too, so the two cannot
// disagree.
func fipsPreflight(ctx context.Context, conn *pgx.Conn, getenv func(string) string, enforced bool) error {
	refusals, err := doctor.FIPSRefusals(ctx, conn, getenv, enforced)
	if err != nil {
		return fmt.Errorf("checking what FIPS 140-only mode refuses: %w", err)
	}
	if len(refusals) > 0 {
		return fmt.Errorf("not serving under GODEBUG=fips140=only:\n  - %s",
			strings.Join(refusals, "\n  - "))
	}
	return nil
}
