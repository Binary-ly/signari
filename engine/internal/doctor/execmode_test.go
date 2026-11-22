package doctor

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The two query modes the engine fails in are critical, and the three it
// works in say nothing (3.06). Read from the connection the DSN opened, which
// is where the setting takes effect.
func TestAQueryModeTheEngineFailsInIsCritical(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	for mode, critical := range map[string]bool{
		"exec": true, "simple_protocol": true,
		"cache_statement": false, "cache_describe": false, "describe_exec": false,
	} {
		q := u.Query()
		q.Set("default_query_exec_mode", mode)
		u.RawQuery = q.Encode()
		conn, err := pgx.Connect(context.Background(), u.String())
		if err != nil {
			t.Fatal(err)
		}
		r := findingsFor(t, func(r *Report) { checkQueryExecMode(conn, r) })
		_ = conn.Close(context.Background())
		if got := r.Count(Critical) == 1; got != critical {
			t.Errorf("default_query_exec_mode=%s: critical = %v, want %v (%v)", mode, got, critical, r.Findings)
		}
	}
}
