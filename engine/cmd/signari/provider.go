package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/store"
)

// `signari provider` -- registering an operator's own service to extend a
// decision this engine makes (ADR-011).

func providerHookList() string {
	var out []string
	for _, h := range provider.AllHooks() {
		out = append(out, string(h))
	}
	return strings.Join(out, ", ")
}

func providerAdd(ctx context.Context, conn *pgx.Conn, orgID, hook, url, mode string,
	timeout time.Duration) error {

	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	if hook == "" {
		return fmt.Errorf("-hook is required (%s)", providerHookList())
	}
	if mode == "" {
		// Named as its own error rather than folded into Validate's, because this
		// is the flag an operator is most likely to omit and the consequence is
		// the one they are least likely to guess.
		return fmt.Errorf("-mode is required and has no default: fail_closed refuses " +
			"the journey when the provider cannot be reached, fail_open continues " +
			"without it.\n\nThere is no safe default. An authorization hook that " +
			"fails open stops enforcing exactly when something is wrong; a claims " +
			"hook that fails closed locks everybody out because a directory was slow")
	}

	p := provider.Provider{
		Name:    "provider-" + hook,
		Hook:    provider.Hook(hook),
		URL:     url,
		Mode:    provider.Mode(mode),
		Timeout: timeout,
	}
	if err := p.Validate(); err != nil {
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id, err := store.SaveProvider(ctx, tx, orgID, p)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("\n  registered %s provider %s\n", hook, id)
	fmt.Printf("    endpoint : %s\n", url)
	fmt.Printf("    on failure: %s\n\n", mode)
	if !provider.Hook(hook).Called() {
		// Cannot happen for a hook that passed Validate today, and it is here for
		// the day a hook is DEFINED before it is wired. An operator registering a
		// provider for a hook nothing consults must be told at that moment, not
		// discover it when the control silently never fires.
		fmt.Printf("  NOTE: no decision point consults %q yet, so this provider is\n"+
			"        stored and will not be called.\n\n", hook)
	}
	if p.Mode == provider.FailOpen {
		fmt.Printf("  NOTE: fail_open means that when this service is unreachable the\n" +
			"        decision proceeds WITHOUT it. For an authorization hook that is\n" +
			"        the control switching itself off during an outage.\n\n")
	}
	return nil
}

func providerList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	rows, err := store.ListProviders(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Printf("\n  no extension providers registered for this organisation\n\n")
		return nil
	}
	fmt.Printf("\n  %-12s %-44s %-12s %-8s %s\n", "HOOK", "ENDPOINT", "ON FAILURE", "TIMEOUT", "CALLED")
	for _, r := range rows {
		called := "yes"
		if !provider.Hook(r.Hook).Called() {
			called = "NO -- nothing consults this hook"
		}
		if !r.Enabled {
			called = "no -- disabled"
		}
		fmt.Printf("  %-12s %-44s %-12s %-8s %s\n",
			r.Hook, r.URL, r.Mode, r.Timeout, called)
	}
	fmt.Println()
	return nil
}

func providerRemove(ctx context.Context, conn *pgx.Conn, orgID, hook string) error {
	if orgID == "" || hook == "" {
		return fmt.Errorf("-org and -hook are required")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	removed, err := store.DeleteProvider(ctx, tx, orgID, provider.Hook(hook))
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if !removed {
		fmt.Printf("\n  no %s provider was registered for this organisation\n\n", hook)
		return nil
	}
	fmt.Printf("\n  removed the %s provider. Decisions are now made locally only.\n\n", hook)
	return nil
}
