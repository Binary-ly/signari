package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/oauth"
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
		{
			name:      "the built-in flow",
			doc:       string(flow.DefaultDocument()),
			wantMax:   3,
			rationale: "second factor, prompts, password change -- captcha is settled at the form",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			parsed, err := flow.Parse([]byte(c.doc))
			if err != nil {
				t.Fatalf("the test's own document does not load: %v", err)
			}
			fl, ok := parsed.For(flow.Authentication)
			if !ok {
				t.Fatalf("%s: no authentication flow in the document", c.name)
			}

			counter := &countingReader{inner: f.pool}
			facts := &signInFacts{
				s: f.srv, ctx: ctx, db: counter, orgID: f.orgID, userID: f.userID,
			}
			// Walked, not evaluated in bulk. The cost that matters is what one
			// journey through this flow actually asks for.
			facts.setKnown(flow.CondCaptchaRequired, false)
			cur := fl.Cursor()
			for {
				if _, ok := cur.Next(facts); !ok {
					break
				}
			}

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

// TestTheBuiltInFlowLogsNothingOnAnOrdinarySignIn.
//
// A warning that is always present is one operators learn to scroll past. The
// first version of the lazy evaluator warned about a condition the BUILT-IN flow
// mentions -- captcha_required -- so every successful login of every deployment
// emitted a warning about the default configuration. Found by asserting on the
// log rather than by reading the code.
func TestTheBuiltInFlowLogsNothingOnAnOrdinarySignIn(t *testing.T) {
	f := newSignInFixture(t)
	var buf bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	def, err := flow.Default()
	if err != nil {
		t.Fatal(err)
	}
	fl, _ := def.For(flow.Authentication)

	facts := &signInFacts{
		s: f.srv, ctx: context.Background(), db: f.pool, orgID: f.orgID, userID: f.userID,
	}
	facts.setKnown(flow.CondCaptchaRequired, false)
	cur := fl.Cursor()
	for {
		if _, ok := cur.Next(facts); !ok {
			break
		}
	}

	if buf.Len() > 0 {
		t.Errorf("an ordinary sign-in under the built-in flow logged at info or above:\n%s",
			buf.String())
	}
}

// TestAConditionTheEngineCannotAnswerIsReportedOnce.
//
// The gap has to be visible somewhere, or an operator configures a control that
// silently does nothing. Reported at load, once per document -- not per sign-in,
// and not per thirty-second cache refresh.
func TestAConditionTheEngineCannotAnswerIsReportedOnce(t *testing.T) {
	f := newSignInFixture(t)
	var buf bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	const doc = `
version: 1
flows:
  - name: uses-a-signal-we-do-not-wire
    on: authentication
    stages:
      - password
      - {stage: mfa, when: risk_elevated}
      - session
    tests:
      - {name: x, given: {}, expect: [password, session]}
`
	parsed, err := flow.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("the test's own document does not load: %v", err)
	}

	f.srv.reportInertConditions(f.orgID, doc, parsed)
	first := buf.String()
	if !strings.Contains(first, "risk_elevated") {
		t.Fatalf("a condition the sign-in path does not evaluate was not reported:\n%s", first)
	}

	// Reloading the same document must not say it again.
	buf.Reset()
	f.srv.reportInertConditions(f.orgID, doc, parsed)
	if buf.Len() > 0 {
		t.Errorf("the same document was reported twice; the cache reloads every %s, so "+
			"this would repeat forever:\n%s", flowRefresh, buf.String())
	}
}

// TestTheSecondFactorDecisionCostsOneQuery.
//
// FlowDemandsMFA runs on every password sign-in, before the transaction opens.
// The sequence it replaced ran exactly one query there -- HasSecondFactor -- and
// this pins that it still does. An earlier version evaluated every condition the
// file mentioned and cost three.
func TestTheSecondFactorDecisionCostsOneQuery(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	counter := &countingReader{inner: f.pool}
	f.srv.FlowDemandsMFA(ctx, counter, f.orgID, f.userID, "", []string{"pwd"})

	if counter.queries > 1 {
		t.Errorf("the second-factor decision made %d queries; the fixed sequence it "+
			"replaced made 1", counter.queries)
	}
}

// TestAFlowWithNoSecondFactorStageAsksNothing -- if the file never demands a
// factor, the server should not look one up to find that out.
func TestAFlowWithNoSecondFactorStageAsksNothing(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	f.applyFlow(t, `
version: 1
flows:
  - name: password-only
    on: authentication
    stages: [password, session]
    tests: [{name: x, given: {}, expect: [password, session]}]
`)

	counter := &countingReader{inner: f.pool}
	demanded, _ := f.srv.FlowDemandsMFA(ctx, counter, f.orgID, f.userID, "", []string{"pwd"})
	if demanded {
		t.Fatal("a flow with no mfa stage demanded a second factor")
	}
	if counter.queries != 0 {
		t.Errorf("a flow that never mentions a second factor still made %d query(ies) "+
			"to decide it did not need one", counter.queries)
	}
}

// TestAFlowEndingInDenyIssuesNoSession.
//
// `deny` is how an operator closes a journey — a maintenance window, an
// organisation being wound down, a designation they have not finished building.
// It has to actually refuse, and it has to leave nothing behind: reaching it
// means the subject WAS authenticated, so a half-authenticated cookie left in
// the browser is a live credential we have just declined to honour.
func TestAFlowEndingInDenyIssuesNoSession(t *testing.T) {
	f := newSignInFixture(t)

	f.applyFlow(t, `
version: 1
flows:
  - name: closed-for-maintenance
    on: authentication
    stages:
      - password
      - deny
    tests:
      - name: nobody gets in
        given: {}
        expect: [password, deny]
`)

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("a flow ending in deny issued a session")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("a denying flow created %d session row(s)", n)
	}
	if got.pendingCookie != "" {
		t.Error("a denied sign-in left a live half-authenticated cookie in the browser")
	}
}

// TestAFlowEndingInDoneIssuesNoSessionAndDoesNotRefuse.
//
// `done` is a journey that succeeded without issuing a session. It must be
// distinguishable from `deny` at the boundary, or the two words mean the same
// thing and one of them is a lie in whichever direction it is read.
func TestAFlowEndingInDoneIssuesNoSessionAndDoesNotRefuse(t *testing.T) {
	f := newSignInFixture(t)

	f.applyFlow(t, `
version: 1
flows:
  - name: verify-only
    on: authentication
    stages:
      - password
      - done
    tests:
      - name: proves who they are and stops there
        given: {}
        expect: [password, done]
`)

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("a flow ending in done issued a session")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("a flow ending in done created %d session row(s)", n)
	}
	if got.status != 200 {
		t.Errorf("a flow that finished successfully answered %d; done is not a refusal",
			got.status)
	}
}

// TestClientRequiresMFAReadsAcrValues.
//
// This function is the entire implementation of the `client_requires_mfa`
// condition. If it silently answered false, a flow written to demand a second
// factor when a relying party asks for one would never demand anything -- and
// every behavioural test would still pass, because no test asserts on a
// condition nothing sets.
func TestClientRequiresMFAReadsAcrValues(t *testing.T) {
	for _, c := range []struct {
		name  string
		authz string
		want  bool
	}{
		{"no parked request", "", false},
		{"a request asking for nothing in particular",
			"?client_id=a&scope=openid", false},
		{"acr_values=2", "?client_id=a&acr_values=2", true},
		{"acr_values with a leading question mark omitted",
			"client_id=a&acr_values=2", true},
		{"the PAPE URN, which OIDC treats as a synonym for 2",
			"?acr_values=" + url.QueryEscape(
				"http://schemas.openid.net/pape/policies/2007/06/multi-factor"), true},
		{"space-separated, multi-factor second — the parameter is a preference " +
			"list, so it counts wherever it appears",
			"?acr_values=" + url.QueryEscape("1 2"), true},
		{"single-factor only", "?acr_values=1", false},
		{"an acr nobody defines", "?acr_values=gold", false},
		// A malformed query must not be read as a demand for MFA, and must not
		// panic: this string comes off a URL somebody else controls.
		{"malformed", "?%zz", false},
	} {
		if got := clientRequiresMFA(c.authz); got != c.want {
			t.Errorf("%s: clientRequiresMFA(%q) = %v, want %v", c.name, c.authz, got, c.want)
		}
	}
}

// TestHasSecondFactorAMRRecognisesEveryFactorThatSatisfiesMFA.
//
// The amr is the record of what actually happened, and this function decides
// whether an mfa stage has already been satisfied by it. A factor missing from
// here means somebody who has just proved a second factor is asked for another
// one; a factor wrongly present means an mfa stage is skipped for a journey that
// never had one, which is the direction that matters.
func TestHasSecondFactorAMRRecognisesEveryFactorThatSatisfiesMFA(t *testing.T) {
	for _, c := range []struct {
		amr  []string
		want bool
	}{
		{nil, false},
		{[]string{oauth.AMRPassword}, false},
		{[]string{"krb"}, false},
		{[]string{oauth.AMRPassword, oauth.AMROTP}, true},
		{[]string{oauth.AMRPassword, oauth.AMRHardwareKey}, true},
		{[]string{oauth.AMRPassword, oauth.AMRSMS}, true},
		{[]string{oauth.AMRMFA}, true},
		// A PIN is a knowledge factor, like the password. Counting it would let
		// password-then-PIN satisfy a stage that exists to demand a second KIND
		// of evidence.
		{[]string{oauth.AMRPassword, oauth.AMRPIN}, false},

		// The passkey cases, which the hand-written version of this function got
		// wrong. amrForPasskey reports "user" plus a key type, and adds "mfa"
		// ONLY when the authenticator verified the user. Without that
		// verification it is one possession factor, however many amr values it
		// produces.
		{[]string{oauth.AMRUserPresence, oauth.AMRHardwareKey}, false},
		{[]string{oauth.AMRUserPresence, "swk"}, false},
		{[]string{oauth.AMRUserPresence, oauth.AMRHardwareKey, oauth.AMRMFA}, true},
		// Presence entirely alone proves somebody touched something.
		{[]string{oauth.AMRUserPresence}, false},
	} {
		if got := hasSecondFactorAMR(c.amr); got != c.want {
			t.Errorf("hasSecondFactorAMR(%v) = %v, want %v", c.amr, got, c.want)
		}
	}
}
