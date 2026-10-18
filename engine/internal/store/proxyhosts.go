package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ProxyHost is one application protected by forward authentication.
type ProxyHost struct {
	Host    string `json:"host"`
	Enabled bool   `json:"enabled"`
}

// NormaliseProxyHost accepts what an operator types for a protected
// application -- a host name, with a port when it is not the default -- and
// refuses anything else. One rule for the CLI, the admin API and `apply`, so a
// host registered one way matches a request the same way.
func NormaliseProxyHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case host == "":
		return "", fmt.Errorf("a protected host is required, e.g. grafana.example.com")
	case strings.Contains(host, "://"):
		return "", fmt.Errorf("a protected host is a host name, not a URL: drop the scheme from %q", raw)
	case strings.ContainsAny(host, "/?#@ \t"):
		return "", fmt.Errorf("%q has a path, query, user or space in it; give the host alone", raw)
	}
	return strings.TrimSuffix(host, "."), nil
}

// ProxyHosts lists one organisation's protected hosts.
func ProxyHosts(ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]ProxyHost, error) {
	rows, err := db.Query(ctx, `
		SELECT host, enabled FROM core.proxy_hosts WHERE org_id = $1::uuid ORDER BY host`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyHost{}
	for rows.Next() {
		var h ProxyHost
		if err := rows.Scan(&h.Host, &h.Enabled); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
