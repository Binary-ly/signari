package doctor

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/passwords"
)

// checkPasswordHashes reports the configured hash cost and pepper (4.08): a
// setting serve would refuse, every pepper a stored hash names that is not
// configured -- those passwords can never verify -- and how many are still to
// move to the current cost or pepper.
func checkPasswordHashes(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("passwords")
	cfg, err := passwords.ConfigFromEnv(os.Getenv)
	if err != nil {
		r.add(Critical, "passwords", err.Error(), "serve refuses to start until it is corrected.")
		return nil
	}
	held := map[string]bool{}
	for _, p := range cfg.Peppers {
		held[p.ID] = true
	}

	rows, err := conn.Query(ctx, `SELECT hash FROM core.password_credentials`)
	if err != nil {
		return err
	}
	byPepper := map[string]int{}
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			rows.Close()
			return err
		}
		byPepper[passwords.PepperID(hash)]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	ids := make([]string, 0, len(byPepper))
	for id := range byPepper {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := byPepper[id]
		switch {
		case id != "" && !held[id]:
			r.add(Critical, "passwords", fmt.Sprintf("%d passwords were hashed with pepper %q, "+
				"which SIGNARI_PASSWORD_PEPPERS does not hold", n, id),
				"None of them can sign in with a password. Put the pepper back, after the current one, "+
					"or have those people reset their passwords.")
		case len(cfg.Peppers) > 0 && id != cfg.Peppers[0].ID:
			what := "no pepper"
			if id != "" {
				what = fmt.Sprintf("pepper %q", id)
			}
			r.add(Info, "passwords", fmt.Sprintf("%d passwords are still hashed with %s", n, what),
				fmt.Sprintf("Each moves to pepper %q at its next sign-in. Keep an old pepper configured "+
					"until no hash names it.", cfg.Peppers[0].ID))
		}
	}
	return nil
}
