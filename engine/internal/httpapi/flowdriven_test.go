package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/flow"
)

// The flow file actually driving the sign-in journey.
//
// # Why these tests are the ones that matter
//
// The journey tests in signinjourney_test.go all still pass after the sequence
// moved into a file, which is the compatibility claim -- and it is exactly what
// a wiring that did NOTHING would also produce. The built-in flow reproduces the
// old behaviour, so "unchanged" is consistent with the flow being loaded,
// consulted and ignored.
//
// These tests close that hole from the other side: apply a flow that says
// something different, and check the journey differs. A pair of tests where one
// proves the default is preserved and the other proves a custom file changes it
// is the only combination that establishes both.

// applyFlow installs a flow document for the fixture's organisation.
//
// Through flow.Parse first, exactly as `signari flow apply` does, so a test
// cannot install a document the CLI would have refused -- which would make the
// test a claim about behaviour no operator can actually reach.
func (f *signInFixture) applyFlow(t *testing.T, doc string) {
	t.Helper()
	if _, err := flow.Parse([]byte(doc)); err != nil {
		t.Fatalf("the test's own flow document does not load: %v", err)
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sign_in_flows (org_id, document) VALUES ($1::uuid, $2)
		ON CONFLICT (org_id) DO UPDATE SET document = EXCLUDED.document, applied_at = now()`,
		f.orgID, doc); err != nil {
		t.Fatalf("applying the flow: %v", err)
	}
	// Reloaded synchronously. Poking loadedAt instead would only mark the cache
	// stale, and a stale cache is refreshed in the BACKGROUND -- so the test would
	// read the previous document and fail, or not, depending on scheduling.
	f.srv.reloadFlows(ctx)

	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.sign_in_flows WHERE org_id = $1::uuid`, f.orgID)
	})
}

// TestAFlowWithoutAPromptStageSkipsThePrompt.
//
// The default holds the sign-in for an outstanding prompt -- TestAnOutstanding-
// PromptStopsTheSession asserts exactly that. A flow file that does not mention
// prompts must not, or the file is decorative.
func TestAFlowWithoutAPromptStageSkipsThePrompt(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, body, fields, once, enabled)
		VALUES ($1::uuid, 'terms-'||substr(gen_random_uuid()::text,1,8), 'Terms', 'Agree',
		        '[{"name":"agree","type":"checkbox","label":"I agree","required":true}]'::jsonb,
		        true, true)`, f.orgID); err != nil {
		t.Skipf("could not create a prompt in this schema: %v", err)
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: no-prompts-here
    on: authentication
    stages:
      - password
      - session
    tests:
      - name: straight through
        given: {}
        expect: [password, session]
`)

	got := f.attempt(t, f.email, signInTestPassword)
	if !got.signedIn() {
		t.Fatalf("the flow lists no prompt stage, yet the sign-in was held for a "+
			"prompt anyway -- the file is not driving the journey (status %d)", got.status)
	}
	if n := f.sessionRows(t); n != 1 {
		t.Fatalf("expected one session row, found %d", n)
	}
}

// TestAFlowCanDemandASecondFactorOfEveryone is the capability an operator gains.
//
// The old journey asked for a second factor only when one was enrolled, and
// there was no way to say otherwise without editing Go. An unconditional mfa
// stage says it of everybody -- and for an account with nothing enrolled that
// has to be a refusal, not a shrug, or the requirement holds for every account
// except the ones it was written to catch.
func TestAFlowCanDemandASecondFactorOfEveryone(t *testing.T) {
	f := newSignInFixture(t)

	f.applyFlow(t, `
version: 1
flows:
  - name: mfa-for-everyone
    on: authentication
    stages:
      - password
      - mfa
      - session
    tests:
      - name: always challenged
        given: {}
        expect: [password, mfa, session]
`)

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("an account with no second factor signed in under a flow that demands " +
			"one of everybody; the requirement is doing nothing for exactly the " +
			"accounts it was written to catch")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("%d session row(s) created despite an unmet mfa stage", n)
	}
}

// TestAFlowCanStopDemandingASecondFactor is the same lever in the other
// direction, and it is the one that could go badly.
//
// A flow with no mfa stage must NOT challenge a user who has one enrolled --
// otherwise the file cannot express what its author wrote. That this weakens the
// journey is the point: it is the operator's decision, taken in a file that
// diffs in a pull request, rather than an emergent property of the code.
func TestAFlowCanStopDemandingASecondFactor(t *testing.T) {
	f := newSignInFixture(t)

	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`,
		f.userID, f.orgID); err != nil {
		t.Fatalf("enrolling a second factor: %v", err)
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: password-only
    on: authentication
    stages:
      - password
      - session
    tests:
      - name: no second factor asked for
        given: {}
        expect: [password, session]
`)

	got := f.attempt(t, f.email, signInTestPassword)
	if !got.signedIn() {
		t.Fatalf("a flow with no mfa stage still challenged an enrolled user; the file "+
			"cannot express what its author wrote (status %d)", got.status)
	}
}

// TestAStoredFlowThatWillNotLoadDoesNotSilentlyChangeTheJourney.
//
// A document written straight to the table with psql has bypassed `flow apply`
// and its safety analysis. The loader must keep the previous flow rather than
// dropping to none -- because "none" means the built-in journey, which is a
// different journey than the operator believes is running, arriving without a
// word.
func TestAStoredFlowThatWillNotLoadDoesNotSilentlyChangeTheJourney(t *testing.T) {
	f := newSignInFixture(t)

	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`,
		f.userID, f.orgID); err != nil {
		t.Fatalf("enrolling a second factor: %v", err)
	}

	// A good flow first, so there is a previous one to keep.
	f.applyFlow(t, `
version: 1
flows:
  - name: password-only
    on: authentication
    stages:
      - password
      - session
    tests:
      - name: no second factor asked for
        given: {}
        expect: [password, session]
`)
	if got := f.attempt(t, f.email, signInTestPassword); !got.signedIn() {
		t.Fatal("the good flow did not take effect, so this test cannot check what " +
			"happens when it is replaced by a bad one")
	}
	if _, err := f.pool.Exec(context.Background(),
		`DELETE FROM core.sessions WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}

	// Now a document that would never have passed `flow apply`: it reaches a
	// session having proved nothing.
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.sign_in_flows SET document = $2 WHERE org_id = $1::uuid`, f.orgID, `
version: 1
flows:
  - name: broken
    on: authentication
    stages:
      - identify
      - session
    tests:
      - name: x
        given: {}
        expect: [identify, session]
`); err != nil {
		t.Fatal(err)
	}
	f.srv.reloadFlows(context.Background())

	// The previous flow is still in force, so this still signs in without a
	// challenge. What must NOT happen is the unsafe document taking effect, or
	// the org silently reverting to the built-in journey.
	got := f.attempt(t, f.email, signInTestPassword)
	if !got.signedIn() {
		t.Error("an unparseable stored flow reverted the org to a different journey; " +
			"the previous flow should have stayed in force")
	}
}

// TestTheFlowIsConsultedAtAllPinsTheWiring.
//
// The narrow question: does the server read the table? Asserted directly, so a
// refactor that stops consulting it fails here with a message that says so,
// rather than by whichever behavioural test happens to notice first.
func TestTheFlowIsConsultedAtAll(t *testing.T) {
	f := newSignInFixture(t)

	// Before: the built-in flow.
	if fl := f.srv.flowFor(context.Background(), f.orgID, flow.Authentication); fl == nil ||
		fl.Name != "default-sign-in" {
		t.Fatalf("expected the built-in flow with no document applied, got %v", fl)
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: something-else-entirely
    on: authentication
    stages:
      - password
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`)

	fl := f.srv.flowFor(context.Background(), f.orgID, flow.Authentication)
	if fl == nil || fl.Name != "something-else-entirely" {
		t.Fatalf("the applied flow is not what the server resolved: %v", fl)
	}
}

// TestAStaleFlowCacheDoesNotStarveTheConnectionPool is a regression test for a
// deadlock this wiring introduced and very nearly shipped.
//
// flowFor is called from completeSignIn, which holds an open transaction. The
// first version reloaded synchronously when the cache went stale -- taking a
// SECOND pool connection while the first was still held. Because loadedAt is
// shared, every concurrent sign-in sees the cache expire in the same instant, so
// under load every in-flight transaction would wait for a connection that only
// another in-flight transaction could release. Nothing would progress, and it
// would happen on a thirty-second cycle, only under concurrency, which is the
// worst combination of properties a bug can have.
//
// The fix serves the stale entry and refreshes in the background. This test runs
// more concurrent flow lookups-inside-a-transaction than the pool has
// connections, with the cache stale, and requires them all to finish.
func TestAStaleFlowCacheDoesNotStarveTheConnectionPool(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	// Warm it, so everLoaded is set and the stale path is what gets exercised.
	f.srv.reloadFlows(ctx)
	f.srv.flows.mu.Lock()
	f.srv.flows.loadedAt = f.srv.flows.loadedAt.Add(-flowRefresh * 2)
	f.srv.flows.mu.Unlock()

	// More workers than the pool has connections, each holding a transaction
	// across the lookup exactly as completeSignIn does.
	workers := int(f.pool.Config().MaxConns) + 4
	done := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				done <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// The lookup that used to want a second connection.
			if fl := f.srv.flowFor(ctx, f.orgID, flow.Authentication); fl == nil {
				done <- context.Canceled
				return
			}
			done <- nil
		}()
	}

	deadline := time.After(20 * time.Second)
	for i := 0; i < workers; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("worker failed: %v", err)
			}
		case <-deadline:
			t.Fatalf("only %d of %d flow lookups completed; the rest are waiting for a "+
				"pool connection held by a transaction that is itself waiting", i, workers)
		}
	}
}

// countingReader records how many queries a sign-in makes.
type countingReader struct {
	inner   signInReader
	queries int
}

func (c *countingReader) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	c.queries++
	return c.inner.Query(ctx, sql, args...)
}

func (c *countingReader) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	c.queries++
	return c.inner.QueryRow(ctx, sql, args...)
}

// TestAFlowPaysOnlyForTheConditionsItMentions.
//
// The straightforward implementation evaluates every condition up front: three
// queries on a path that previously ran one, on every sign-in in the product,
// most of them for facts the flow never consults. This asserts the queries are
// driven by the file instead.
//
// Worth a test rather than a comment because the lazy version and the eager one
// are behaviourally identical -- every other test in this package passes under
// both, so nothing else would notice the regression.
func TestAFlowPaysOnlyForTheConditionsItMentions(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	for _, c := range []struct {
		name      string
		doc       string
		wantMax   int
		rationale string
	}{
		{
			name: "no conditions at all",
			doc: `
version: 1
flows:
  - name: straight
    on: authentication
    stages: [password, session]
    tests: [{name: x, given: {}, expect: [password, session]}]
`,
			wantMax:   0,
			rationale: "a flow that branches on nothing has nothing to look up",
		},
		{
			name: "one condition",
			doc: `
version: 1
flows:
  - name: one
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_second_factor}
      - session
    tests:
      - {name: x, given: {}, expect: [password, session]}
`,
			wantMax:   1,
			rationale: "one condition is one lookup",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			parsed, err := flow.Parse([]byte(c.doc))
			if err != nil {
				t.Fatalf("the test's own document does not load: %v", err)
			}
			fl, _ := parsed.For(flow.Authentication)

			counter := &countingReader{inner: f.pool}
			facts := &signInFacts{
				s: f.srv, ctx: ctx, db: counter, orgID: f.orgID, userID: f.userID,
			}
			facts.state(fl, false)

			if counter.queries > c.wantMax {
				t.Errorf("%s: made %d queries, expected at most %d (%s)",
					c.name, counter.queries, c.wantMax, c.rationale)
			}
		})
	}
}

// TestThePromptListIsReadOnce -- the condition and the stage both want it, and
// reading it twice inside one sign-in is a query nobody asked for.
func TestThePromptListIsReadOnce(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	counter := &countingReader{inner: f.pool}
	facts := &signInFacts{
		s: f.srv, ctx: ctx, db: counter, orgID: f.orgID, userID: f.userID,
	}
	facts.pendingPrompts()
	after := counter.queries
	facts.pendingPrompts()
	if counter.queries != after {
		t.Errorf("the prompt list was read again on the second call (%d -> %d queries)",
			after, counter.queries)
	}
}
