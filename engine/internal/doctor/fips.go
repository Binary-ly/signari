package doctor

import (
	"context"
	"crypto/fips140"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

// FIPSRefusals lists what is configured that can only run through an algorithm
// Go's FIPS module refuses, when enforced is true (GODEBUG=fips140=only), each
// with what to do about it (3.11). serve refuses to start on any of them and
// doctor reports them as critical: each failed by panicking a request at the
// moment somebody used it.
//
//   - RADIUS: MD5 by specification.
//   - The breached-password check: its corpus is keyed by SHA-1.
//   - People with TOTP as a second factor: TOTP is HMAC-SHA1, so none of them
//     could finish signing in.
func FIPSRefusals(ctx context.Context, conn *pgx.Conn, getenv func(string) string, enforced bool) ([]string, error) {
	if !enforced {
		return nil, nil
	}
	var out []string
	if getenv("SIGNARI_RADIUS_ADDR") != "" {
		out = append(out, "SIGNARI_RADIUS_ADDR is set, and RADIUS is MD5 by its specification, "+
			"which the module refuses. Unset it; 802.1X needs a RADIUS server outside this module")
	}
	if getenv("SIGNARI_PASSWORD_BREACH_CHECK") == "1" || getenv("SIGNARI_PASSWORD_BREACH_LIST") != "" {
		out = append(out, "the breached-password check is configured, and its corpus is keyed by "+
			"SHA-1, which the module refuses. Unset SIGNARI_PASSWORD_BREACH_CHECK and "+
			"SIGNARI_PASSWORD_BREACH_LIST")
	}
	var totp int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM core.totp_credentials WHERE confirmed_at IS NOT NULL`).Scan(&totp); err != nil {
		return nil, err
	}
	if totp > 0 {
		out = append(out, fmt.Sprintf("%d people have TOTP as a second factor, and TOTP is HMAC-SHA1, "+
			"which the module refuses, so none of them could finish signing in. Have them enrol a "+
			"passkey, then remove their TOTP factor (DELETE /admin/users/{id}/factors/totp)", totp))
	}
	return out, nil
}

// checkFIPS reports the FIPS 140-3 mode this process runs in, what that mode
// would refuse, and how many passwords are still hashed outside the module.
func checkFIPS(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("fips")
	refusals, err := FIPSRefusals(ctx, conn, os.Getenv, fips140.Enforced())
	if err != nil {
		return err
	}
	for _, x := range refusals {
		r.add(Critical, "fips", x, "serve refuses to start under GODEBUG=fips140=only until it is resolved.")
	}
	if !fips140.Enabled() {
		return nil
	}
	if !fips140.Enforced() {
		r.add(Info, "fips", "FIPS 140-3 mode is on but not enforced (GODEBUG=fips140=on): approved "+
			"algorithms run through the module and everything else still runs", "Run with "+
			"GODEBUG=fips140=only if the requirement is that nothing else does; docs/fips.md says which.")
	}
	var outside int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM core.password_credentials
		WHERE hash NOT LIKE '$pbkdf2-sha256$%'`).Scan(&outside); err != nil {
		return err
	}
	if outside > 0 {
		r.add(Info, "fips", fmt.Sprintf("%d passwords are still hashed outside the FIPS module", outside),
			"Each moves to PBKDF2-SHA256 at its next sign-in; a password nobody signs in with stays as it is.")
	}
	return nil
}
