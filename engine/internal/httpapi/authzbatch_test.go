package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// countStatements points the server at a pool that counts, from here on.
func countStatements(t *testing.T, f *tokenFixture) *statementCount {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	queries := &statementCount{}
	cfg.ConnConfig.Tracer = queries
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Connections opened now, or a new one's SET ROLE counts as the request's.
	var held []*pgxpool.Conn
	for range 3 {
		c, err := pool.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	for _, c := range held {
		c.Release()
	}
	f.srv.db = pool
	return queries
}

func (a *authzProviderFixture) post(t *testing.T, path, body string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)
	rec := httptest.NewRecorder()
	a.f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s answered %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

// A hundred questions about one subject read the model, the subject and the
// relations once each. Each entry used to read them for itself, six statements a
// time, and the batch limit made that about 1,500 for one request.
func TestAHundredEvaluationsAskTheDatabaseOnce(t *testing.T) {
	a := newAuthzProviderFixture(t)
	ctx := context.Background()
	var person string
	if err := a.f.pool.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, a.f.userID).Scan(&person); err != nil {
		t.Fatal(err)
	}
	if _, err := a.f.pool.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation,
		object_type, object_id) SELECT $1::uuid, 'user', $2, 'owner', 'doc', 'batch-' || i
		FROM generate_series(1, 50) i`, a.f.orgID, a.f.userID); err != nil {
		t.Fatal(err)
	}
	var entries []string
	for i := 1; i <= 100; i++ {
		entries = append(entries, fmt.Sprintf(`{"resource":{"type":"doc","id":"batch-%d"}}`, i))
	}
	body := fmt.Sprintf(`{"subject":{"type":"user","id":%q},"action":{"name":"can_edit"},"evaluations":[%s]}`,
		person, strings.Join(entries, ","))

	// What being let in costs, which is not the evaluations': a body refused after
	// the caller is known, once the pool has its connection.
	queries := countStatements(t, a.f)
	refused := func() {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", strings.NewReader(`{"evaluations":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		rec := httptest.NewRecorder()
		a.f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("the refused body answered %d", rec.Code)
		}
	}
	// The last-seen stamp is written behind the request, so each is left to land
	// before counting starts or stops.
	settle := func() { time.Sleep(200 * time.Millisecond) }
	refused()
	settle()
	queries.n.Store(0)
	refused()
	settle()
	entry := queries.n.Load()

	queries.n.Store(0)
	raw := a.post(t, "/access/v1/evaluations", body)
	settle()
	spent := queries.n.Load() - entry

	var got struct {
		Evaluations []struct {
			Decision bool `json:"decision"`
		} `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Evaluations) != 100 {
		t.Fatalf("%d answers", len(got.Evaluations))
	}
	for i, e := range got.Evaluations {
		if want := i < 50; e.Decision != want {
			t.Errorf("batch-%d decided %v, want %v", i+1, e.Decision, want)
		}
	}
	if spent > 5 {
		t.Errorf("a hundred evaluations took %d statements beyond the %d that let the caller in", spent, entry)
	}
}

// Answering from one read must not change an answer. A relation held through a
// group, by a person asked about by address, on a resource somebody else owns,
// and one that has expired, each come out as a single evaluation has them.
func TestABatchDecidesWhatEachQuestionAloneWould(t *testing.T) {
	a := newAuthzProviderFixture(t)
	ctx := context.Background()
	var person string
	if err := a.f.pool.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, a.f.userID).Scan(&person); err != nil {
		t.Fatal(err)
	}
	var group string
	if err := a.f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'batch-readers', 'B') RETURNING id::text`, a.f.orgID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = a.f.pool.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, group)
	})
	if _, err := a.f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		group, a.f.userID, a.f.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.f.pool.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id, expires_at)
		VALUES ($1::uuid, 'group', 'batch-readers', 'owner', 'doc', 'by-group', NULL),
		       ($1::uuid, 'user', $2, 'owner', 'doc', 'by-id', NULL),
		       ($1::uuid, 'user', $3, 'owner', 'doc', 'by-address', NULL),
		       ($1::uuid, 'user', $2, 'owner', 'doc', 'expired', now() - interval '1 minute')`,
		a.f.orgID, a.f.userID, person); err != nil {
		t.Fatal(err)
	}

	subjects := []string{person, a.f.userID, a.subject, "nobody-we-know"}
	resources := []string{"by-group", "by-id", "by-address", "expired", a.resource, "absent"}
	var entries []string
	var alone []bool
	for _, sub := range subjects {
		for _, res := range resources {
			entries = append(entries, fmt.Sprintf(`{"subject":{"type":"user","id":%q},"resource":{"type":"doc","id":%q}}`, sub, res))
			decided, _ := a.evaluate(t, sub, res)
			alone = append(alone, decided)
		}
	}
	raw := a.post(t, "/access/v1/evaluations", fmt.Sprintf(`{"action":{"name":"can_edit"},"evaluations":[%s]}`,
		strings.Join(entries, ",")))
	var got struct {
		Evaluations []struct {
			Decision bool `json:"decision"`
		} `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Evaluations) != len(alone) {
		t.Fatalf("%d answers to %d questions", len(got.Evaluations), len(alone))
	}
	yes := 0
	for i, e := range got.Evaluations {
		if e.Decision != alone[i] {
			t.Errorf("%s in a batch decided %v, alone %v", entries[i], e.Decision, alone[i])
		}
		if alone[i] {
			yes++
		}
	}
	// By address the person reaches all three grants. By id, the one stored by
	// address stays out of reach, as it does alone. The fixture's subject has its own.
	if yes != 6 {
		t.Errorf("%d questions were allowed, want 6", yes)
	}
}

// A sampled decision reaches the trail, and with it whatever sink is streaming it.
// A person is recorded by their id, not the address the caller asked about them
// with; nothing at all is recorded with the sample at nothing.
func TestASampledDecisionReachesTheTrail(t *testing.T) {
	a := newAuthzProviderFixture(t)
	ctx := context.Background()
	var person string
	if err := a.f.pool.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, a.f.userID).Scan(&person); err != nil {
		t.Fatal(err)
	}
	recorded := func() int {
		t.Helper()
		var n int
		if err := a.f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
			WHERE event_type = 'authz.decision' AND org_id = $1::uuid`, a.f.orgID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := recorded()
	a.evaluate(t, person, a.resource)
	if got := recorded(); got != before {
		t.Fatalf("with no sample the trail gained %d", got-before)
	}

	a.f.srv.SetDecisionLogRate(1)
	a.evaluate(t, person, a.resource)
	if got := recorded(); got != before+1 {
		t.Fatalf("a whole sample recorded %d", got-before)
	}
	var subject, detail string
	if err := a.f.pool.QueryRow(ctx, `SELECT COALESCE(subject_id::text, ''), detail::text FROM core.audit_events
		WHERE event_type = 'authz.decision' AND org_id = $1::uuid ORDER BY id DESC LIMIT 1`, a.f.orgID).Scan(&subject, &detail); err != nil {
		t.Fatal(err)
	}
	if subject != a.f.userID {
		t.Errorf("the record names %q, want the person's id", subject)
	}
	if strings.Contains(detail, person) {
		t.Errorf("the record carries the address: %s", detail)
	}
	if !strings.Contains(detail, `"can_edit"`) || !strings.Contains(detail, a.resource) {
		t.Errorf("the record says %s", detail)
	}

	a.post(t, "/access/v1/evaluations", fmt.Sprintf(`{"subject":{"type":"user","id":%q},"action":{"name":"can_edit"},
		"evaluations":[{"resource":{"type":"doc","id":"a"}},{"resource":{"type":"doc","id":"b"}}]}`, person))
	if got := recorded(); got != before+3 {
		t.Errorf("a batch of two recorded %d", got-before-1)
	}

	// An address nobody here holds is still somebody's, and the trail is not
	// erased with anyone, so it is left out. A service is named: it is not a person.
	last := func() string {
		t.Helper()
		var detail string
		if err := a.f.pool.QueryRow(ctx, `SELECT detail::text FROM core.audit_events
			WHERE event_type = 'authz.decision' AND org_id = $1::uuid ORDER BY id DESC LIMIT 1`, a.f.orgID).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		return detail
	}
	a.evaluate(t, "stranger@elsewhere.test", a.resource)
	if got := last(); strings.Contains(got, "stranger") {
		t.Errorf("the record carries an address nobody here holds: %s", got)
	}
	a.post(t, "/access/v1/evaluation", fmt.Sprintf(`{"subject":{"type":"service","id":"billing"},
		"action":{"name":"can_edit"},"resource":{"type":"doc","id":%q}}`, a.resource))
	if got := last(); !strings.Contains(got, "service:billing") {
		t.Errorf("the record does not name the service: %s", got)
	}
}

func TestADecisionLogRateIsAShare(t *testing.T) {
	for value, want := range map[string]float64{"": 0, "0": 0, "0.01": 0.01, "1": 1} {
		if got, err := ParseDecisionLogRate(value); err != nil || got != want {
			t.Errorf("%q read as %v, %v", value, got, err)
		}
	}
	for _, value := range []string{"-0.1", "1.5", "half", "NaN"} {
		if _, err := ParseDecisionLogRate(value); err == nil {
			t.Errorf("%q was accepted", value)
		}
	}
}
