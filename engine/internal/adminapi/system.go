package adminapi

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"

	"signari.dev/engine/internal/migrate"
)

// What the deployment is, for the automation that manages it (6.08): which
// release and commit serves this API, which schema it runs against and which
// the binary carries, whether the binary is pinned to a schema fingerprint,
// how many issuers and organisations it holds, and the limits this listener
// applies. A deployment-wide token only, since the count of tenants is not one
// tenant's to read. Until it existed an operator's tooling learned the
// release from `signari version` on the host, and the rest from SQL.

// SetRelease names the release this binary was built as, for /admin/system.
func (s *Server) SetRelease(release string) { s.release = release }

func (s *Server) getSystem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := requireOrg(ctx, ""); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_organisation",
			"detail": "only a deployment-wide token may read the deployment"})
		return
	}
	commit, toolchain := "unknown", "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		toolchain = bi.GoVersion
		for _, st := range bi.Settings {
			if st.Key == "vcs.revision" {
				commit = st.Value
			}
		}
	}
	release := s.release
	if release == "" {
		release = "unreleased"
	}
	carried := 0
	if all, err := migrate.Load(); err == nil && len(all) > 0 {
		carried = all[len(all)-1].Version
	}
	var applied, instances, orgs, suspended int
	if err := s.db.QueryRow(ctx, `
		SELECT (SELECT COALESCE(max(version), 0) FROM core.schema_migrations),
		       (SELECT count(*) FROM core.instances),
		       (SELECT count(*) FROM core.organizations),
		       (SELECT count(*) FROM core.organizations WHERE status = 'suspended')`).
		Scan(&applied, &instances, &orgs, &suspended); err != nil {
		s.log.Error("reading the deployment", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, map[string]any{
		"release": release, "commit": commit, "go": toolchain,
		"schema": map[string]any{"applied": applied, "binary": carried,
			"fingerprint_pinned": migrate.ExpectedFingerprint != ""},
		"instances": instances, "organizations": orgs, "suspended_organizations": suspended,
		"rate_limits": map[string]any{"arrivals_per_second": s.limits.arrivals,
			"per_token_per_second": s.limits.perToken},
	})
}

// adminLimits are the listener's rates, per second; the bursts are twice.
type adminLimits struct{ arrivals, perToken int }

// limitsFromEnv reads SIGNARI_ADMIN_RATE and SIGNARI_ADMIN_TOKEN_RATE, the
// listener's arrivals and one token's, each 1 to 100000 a second. Fixed until
// October 2026 (6.08), so a provisioning run larger than they allowed could
// only be slowed down, and a value that does not parse is refused at startup
// rather than replaced by a default nobody chose.
func limitsFromEnv() (adminLimits, error) {
	l := adminLimits{arrivals: adminArrivalsPerSecond, perToken: adminPerTokenPerSecond}
	for _, e := range []struct {
		name string
		dst  *int
	}{{"SIGNARI_ADMIN_RATE", &l.arrivals}, {"SIGNARI_ADMIN_TOKEN_RATE", &l.perToken}} {
		raw := os.Getenv(e.name)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100000 {
			return l, fmt.Errorf("%s is requests a second, 1 to 100000, not %q", e.name, raw)
		}
		*e.dst = n
	}
	if l.perToken > l.arrivals {
		return l, fmt.Errorf("SIGNARI_ADMIN_TOKEN_RATE (%d) exceeds SIGNARI_ADMIN_RATE (%d): one token "+
			"cannot be allowed more than the listener", l.perToken, l.arrivals)
	}
	return l, nil
}
