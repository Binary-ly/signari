package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/safedial"
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

func providerAdd(ctx context.Context, conn *pgx.Conn, orgID, hook, name, url, mode string,
	timeout time.Duration, position int) error {

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

	if name == "" {
		name = provider.Hook(hook).DefaultName()
	}
	p := provider.Provider{
		Name:     name,
		Hook:     provider.Hook(hook),
		Position: position,
		URL:      url,
		Mode:     provider.Mode(mode),
		Timeout:  timeout,
	}
	if err := p.Validate(); err != nil {
		return err
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id, secret, err := store.SaveProvider(ctx, tx, root, orgID, p)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("\n  registered %s provider %s (%s)\n", hook, name, id)
	fmt.Printf("    endpoint : %s\n", url)
	fmt.Printf("    on failure: %s\n\n", mode)
	if secret != "" {
		printProviderSecret(secret)
	} else {
		fmt.Printf("  It keeps the signing secret it had. `signari provider rotate` mints a new one.\n\n")
	}
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

// providerTest calls a registered provider with a request naming nobody, marked as
// a test, and says what came back, so a broken one is found by its operator and
// not by the first person signing in. It goes through the same call a decision
// does, so the signature and the outbound guard apply, and exits non-zero on
// anything a real decision would count as unreachable or as no answer.
func providerTest(ctx context.Context, conn *pgx.Conn, orgID, hook, name string) error {
	if orgID == "" || hook == "" {
		return fmt.Errorf("-org and -hook are both required")
	}
	h := provider.Hook(hook)
	contract, ok := provider.ContractFor(h)
	if !ok {
		return fmt.Errorf("unknown hook %q; one of %s", hook, providerHookList())
	}
	root, err := rootKey()
	if err != nil {
		return err
	}
	found, err := store.LoadProviders(ctx, conn, root, orgID, h)
	if err != nil {
		return err
	}
	var p *provider.Provider
	for _, candidate := range found {
		if name == "" && len(found) > 1 {
			return store.ErrProviderAmbiguous
		}
		if name == "" || candidate.Name == name {
			p = candidate
		}
	}
	if p == nil {
		return fmt.Errorf("no enabled provider is registered for %s in this organisation", hook)
	}
	p.Test = true
	var answer map[string]any
	started := time.Now()
	if err := p.Call(ctx, safedial.Client(p.Timeout), contract.Sample, &answer); err != nil {
		return fmt.Errorf("%s did not answer, so a real decision would go by its %s mode: %w", p.URL, p.Mode, err)
	}
	took := time.Since(started).Round(time.Millisecond)
	verdict, ok := answer[contract.Verdict].(bool)
	if !ok {
		return fmt.Errorf("%s answered in %s with no boolean %s, which contract %s requires",
			p.URL, took, contract.Verdict, provider.ContractVersion)
	}
	fmt.Printf("%s answered in %s under contract %s: %s %v\n", p.URL, took, provider.ContractVersion,
		contract.Verdict, verdict)
	if p.Secret == "" {
		fmt.Println("  NOTE: the call was unsigned. `signari provider rotate` gives this provider a secret.")
	}
	return nil
}

// printProviderSecret shows a signing secret the one time it exists in the clear.
func printProviderSecret(secret string) {
	fmt.Printf("  signing secret (shown once): %s\n\n", secret)
	fmt.Printf("  Every call carries Signari-Signature: t=<unix>,v1=<hex HMAC-SHA256 of\n")
	fmt.Printf("  \"<t>.<body>\" under this secret>, the scheme event deliveries use. Refuse a\n")
	fmt.Printf("  call whose signature does not match or whose t is more than a few minutes\n")
	fmt.Printf("  old, and anybody else who finds the URL is refused with it.\n\n")
}

// providerRotate replaces a provider's signing secret. The old one stops
// verifying at once, so the provider must be given the new one in the same
// change; a provider registered before secrets existed gets its first.
func providerRotate(ctx context.Context, conn *pgx.Conn, orgID, hook, name string) error {
	if orgID == "" || hook == "" {
		return fmt.Errorf("-org and -hook are required")
	}
	root, err := rootKey()
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	secret, err := store.RotateProviderSecret(ctx, tx, root, orgID, provider.Hook(hook), name)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("\n  rotated the %s provider's signing secret; the old one no longer verifies.\n\n", hook)
	printProviderSecret(secret)
	return nil
}

func providerList(ctx context.Context, conn *pgx.Conn, orgID, format string) error {
	out, err := newOutput(format)
	if err != nil {
		return err
	}
	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	rows, err := store.ListProviders(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if !out.text() {
		for _, r := range rows {
			out.add(map[string]any{"hook": r.Hook, "name": r.Name, "position": r.Position, "url": r.URL,
				"mode": r.Mode, "timeout": r.Timeout.String(),
				"signed": r.Signed, "enabled": r.Enabled, "called": provider.Hook(r.Hook).Called() && r.Enabled})
		}
		return out.flush()
	}
	if len(rows) == 0 {
		fmt.Printf("\n  no extension providers registered for this organisation\n\n")
		return nil
	}
	fmt.Printf("\n  %-12s %-24s %-44s %-12s %-8s %-8s %s\n", "HOOK", "NAME", "ENDPOINT", "ON FAILURE", "TIMEOUT", "SIGNED", "CALLED")
	for _, r := range rows {
		called := "yes"
		if !provider.Hook(r.Hook).Called() {
			called = "NO -- nothing consults this hook"
		}
		if !r.Enabled {
			called = "no -- disabled"
		}
		signed := "yes"
		if !r.Signed {
			signed = "NO"
		}
		fmt.Printf("  %-12s %-24s %-44s %-12s %-8s %-8s %s\n",
			r.Hook, r.Name, r.URL, r.Mode, r.Timeout, signed, called)
	}
	fmt.Println()
	return nil
}

func providerRemove(ctx context.Context, conn *pgx.Conn, orgID, hook, name string) error {
	if orgID == "" || hook == "" {
		return fmt.Errorf("-org and -hook are required")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	removed, err := store.DeleteProvider(ctx, tx, orgID, provider.Hook(hook), name)
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
	fmt.Printf("\n  removed the %s provider. It is no longer asked.\n\n", hook)
	return nil
}
