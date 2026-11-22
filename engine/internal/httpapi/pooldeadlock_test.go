package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oidc"
)

// Minting a token with the `groups` scope read the groups from the pool while
// holding the redemption's transaction. With as many concurrent redemptions as
// the pool has connections, each held one and waited for a second that only
// another's completion could free: nothing crashed, everything stopped.
func TestTwiceThePoolInConcurrentGroupsRedemptionsAllComplete(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	const maxConns = 2

	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = maxConns
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	small, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.client_group_release (client_id, org_id, only_groups)
		VALUES ($1, $2::uuid, ARRAY[]::text[])
		ON CONFLICT (client_id) DO NOTHING`, f.clientID, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.client_group_release WHERE client_id = $1`, f.clientID)
	})

	const n = 2 * maxConns
	verifier := strings.Repeat("g", 64)
	codes := make([]string, n)
	for i := range codes {
		codes[i] = f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "groups"})
	}
	f.srv.db = small

	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A deadline on every request, so a deadlock fails the test instead
			// of hanging it, and the pool's Close does not wait forever.
			rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req := httptest.NewRequest(http.MethodPost, oidc.PathToken,
				strings.NewReader(f.redeem(codes[i], verifier).Encode())).WithContext(rctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)
			statuses[i] = rec.Code
		}(i)
	}
	wg.Wait()
	for i, s := range statuses {
		if s != http.StatusOK {
			t.Errorf("redemption %d of %d against a pool of %d gave %d: %s", i+1, n, maxConns, s,
				fmt.Sprint(statuses))
		}
	}
}
