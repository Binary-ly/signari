package httpapi

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The operator's token provider was asked with the redemption's transaction
// open, so every redemption held a pool connection and the code's row lock for
// as long as the provider took to answer. Here the pool has one connection, and
// the provider itself tries to take it: it can only if the engine is not
// holding it while asking.
func TestTheTokenProviderIsAskedWithNoConnectionHeld(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	single, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(single.Close)

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'hold-check', 'token_issue', 'https://provider.test/decide', 'fail_closed', 2000)`,
		f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.providers WHERE org_id = $1::uuid AND name = 'hold-check'`, f.orgID)
	})

	asked := 0
	f.srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			asked++
			actx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
			defer cancel()
			answer := `{"decision":true}`
			if conn, err := single.Acquire(actx); err != nil {
				answer = `{"decision":false,"reason":"the engine held the only connection while asking"}`
			} else {
				conn.Release()
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
				"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(answer))}, nil
		})}
	}

	verifier := strings.Repeat("h", 64)
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	f.srv.db = single

	status, body := f.post(t, f.redeem(code, verifier))
	if asked == 0 {
		t.Fatal("the provider was never asked, so this test proved nothing")
	}
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d %v: the provider could not take a connection while it "+
			"was being asked, so the engine was holding it", status, body)
	}
}
