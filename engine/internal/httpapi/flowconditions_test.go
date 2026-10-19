package httpapi

import (
	"context"
	"sort"
	"testing"

	"signari.dev/engine/internal/flow"
)

// Parse lets a flow branch only on the conditions its journey evaluates
// (flow.Answered), and these are the evaluators. The two must name the same
// set. A condition listed there and answered by nothing here reads false while
// the flow naming it believes it is guarded -- the failure 2.20 removed, when
// ten of fifteen did exactly that. One answered here and missing there is
// refused at parse for no reason.
func TestEveryConditionAFlowCanUseIsAnswered(t *testing.T) {
	signIn := map[flow.Condition]bool{}
	for c := range signInConditions {
		signIn[c] = true
	}
	compare(t, flow.Authentication, signIn)

	s := &Server{}
	ctx := context.Background()
	compare(t, flow.Enrolment, stateKeys(s.enrolmentFacts(ctx, "192.0.2.1:1")))
	compare(t, flow.Recovery, stateKeys(s.recoveryFacts(ctx, "192.0.2.1:1")))
}

// user_has_passkey is answered from the person's credentials, and a flow that
// demands a second factor of passkey holders demands it once they hold one.
// Before 2.20 it read false for everybody.
func TestUserHasPasskeyIsAnsweredFromTheDatabase(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	f.applyFlow(t, `
version: 1
flows:
  - name: passkey-holders-step-up
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_passkey}
      - session
    tests:
      - {name: no passkey, given: {}, expect: [password, session]}
      - {name: a passkey, given: {user_has_passkey: true}, expect: [password, mfa, session]}
`)
	if demanded, _ := f.srv.FlowDemandsMFA(ctx, f.pool, f.orgID, f.userID, "", []string{"pwd"}); demanded {
		t.Fatal("a second factor was demanded of somebody with no passkey")
	}

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, rp_id, is_discoverable)
		VALUES ($1::uuid, $2::uuid, decode(md5(gen_random_uuid()::text),'hex'),
		        '\x02'::bytea, 'localhost', true)`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.webauthn_credentials WHERE user_id = $1::uuid`, f.userID)
	})
	if demanded, _ := f.srv.FlowDemandsMFA(ctx, f.pool, f.orgID, f.userID, "", []string{"pwd"}); !demanded {
		t.Fatal("a passkey holder was not asked for the second factor the flow demands of them; " +
			"user_has_passkey read false")
	}
}

func stateKeys(st flow.State) map[flow.Condition]bool {
	out := map[flow.Condition]bool{}
	for k := range st {
		out[flow.Condition(k)] = true
	}
	return out
}

func compare(t *testing.T, on flow.Designation, evaluated map[flow.Condition]bool) {
	t.Helper()
	listed := map[flow.Condition]bool{}
	for _, c := range flow.Answered(on) {
		listed[c] = true
		if !evaluated[c] {
			t.Errorf("on %s, flow.Answered lets a flow branch on %s and nothing here "+
				"evaluates it, so it reads false while the flow believes it is guarded", on, c)
		}
	}
	var extra []string
	for c := range evaluated {
		if !listed[c] {
			extra = append(extra, string(c))
		}
	}
	sort.Strings(extra)
	for _, c := range extra {
		t.Errorf("on %s, %s is evaluated here and refused at parse; add it to flow.answered", on, c)
	}
}
