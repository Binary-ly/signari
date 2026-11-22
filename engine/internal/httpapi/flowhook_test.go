package httpapi

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/provider"
)

// signedInBy says whether a sign-in got a session.
func signedInBy(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

// A flow's two branches, decided by the operator's service (10.02): told who and how, asked
// once however often the walk asks, and with no answer from a service registered
// fail_closed the sign-in is refused rather than guessed at.
func TestAFlowBranchesOnTheOperatorsService(t *testing.T) {
	f := newSignInFixture(t)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookFlowCondition)
	f.applyFlow(t, `
version: 1
flows:
  - name: the-service-decides
    on: authentication
    stages:
      - password
      - {stage: mfa, when: device_managed}
      - {stage: mfa, when: provider_condition}
      - session
    tests:
      - {name: it asks for more, given: {provider_condition: true}, expect: [password, mfa, session]}
      - {name: it does not, given: {}, expect: [password, session]}
`)

	service.says(`{"decision":false}`)
	if !signedInBy(f.postLogin(t, nil)) {
		t.Fatal("the branch straight to a session was not taken")
	}
	asked := service.lastAsked()
	if asked["subject"] != f.userID || asked["org_id"] != f.orgID || fmt.Sprint(asked["amr"]) != "[pwd]" {
		t.Errorf("the service was told %v", asked)
	}
	if got := service.times(); got != 1 {
		t.Errorf("one request asked %d times", got)
	}

	service.says(`{"decision":true}`)
	if signedInBy(f.postLogin(t, nil)) {
		t.Error("the branch to a second factor was not taken")
	}

	service.says("")
	if signedInBy(f.postLogin(t, nil)) {
		t.Error("a fail_closed service that was down let a sign-in through on a guess")
	}
	var reason string
	if err := f.pool.QueryRow(context.Background(), `SELECT detail->>'reason' FROM core.audit_events
		WHERE event_type = 'login.failed' AND org_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`,
		f.orgID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "flow_provider_down" {
		t.Errorf("recorded %q", reason)
	}

	// fail_open reads false, and walks on.
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.providers SET mode = 'fail_open'
		WHERE org_id = $1::uuid AND hook = 'flow_condition'`, f.orgID); err != nil {
		t.Fatal(err)
	}
	if !signedInBy(f.postLogin(t, nil)) {
		t.Error("a fail_open service that was down refused the sign-in")
	}
}

// What the language has always named and nothing could answer, now said by the service,
// and a fact it does not mention reads false.
func TestTheOperatorsServiceSaysWhatItKnows(t *testing.T) {
	f := newSignInFixture(t)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookFlowCondition)
	f.applyFlow(t, `
version: 1
flows:
  - name: managed-devices-only
    on: authentication
    stages:
      - password
      - {stage: mfa, when: not device_compliant}
      - session
    tests:
      - {name: compliant, given: {device_compliant: true}, expect: [password, session]}
      - {name: otherwise, given: {}, expect: [password, mfa, session]}
`)
	service.says(`{"decision":false,"facts":{"device_managed":true,"device_compliant":true}}`)
	if !signedInBy(f.postLogin(t, nil)) {
		t.Error("a compliant device was asked for more")
	}
	service.says(`{"decision":false,"facts":{"device_managed":true}}`)
	if signedInBy(f.postLogin(t, nil)) {
		t.Error("a device nobody called compliant went straight in")
	}
}

// A flow naming nothing the hook answers costs no call, and the service's risk signal
// joins this engine's own.
func TestTheServiceIsOnlyAskedWhatAFlowAsks(t *testing.T) {
	f := newSignInFixture(t)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookFlowCondition)
	if !signedInBy(f.postLogin(t, nil)) {
		t.Fatal("the built-in flow refused the sign-in")
	}
	if service.times() != 0 {
		t.Errorf("the built-in flow asked the service %d times", service.times())
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: risky-stop-here
    on: authentication
    stages:
      - password
      - {stage: mfa, when: risk_elevated}
      - session
    tests:
      - {name: risky, given: {risk_elevated: true}, expect: [password, mfa, session]}
      - {name: calm, given: {}, expect: [password, session]}
`)
	service.says(`{"decision":false,"facts":{"risk_elevated":true}}`)
	if signedInBy(f.postLogin(t, nil)) {
		t.Error("the service's risk signal was not heard")
	}
	service.says(`{"decision":false}`)
	if !signedInBy(f.postLogin(t, nil)) {
		t.Error("a calm sign-in was asked for more")
	}
}

// With nothing registered to answer, the conditions read false: every one guards an
// additional stage, so a `not` asks for more rather than less.
func TestNoProviderReadsFalse(t *testing.T) {
	file, err := flow.Parse([]byte(`
version: 1
flows:
  - name: asks
    on: authentication
    stages:
      - password
      - {stage: mfa, when: not device_managed}
      - session
    tests:
      - {name: managed, given: {device_managed: true}, expect: [password, session]}
      - {name: unmanaged, given: {}, expect: [password, mfa, session]}
`))
	if err != nil {
		t.Fatalf("a flow on what the hook answers: %v", err)
	}
	if !file.Flows[0].AsksProvider() {
		t.Error("the flow does not say it asks a provider")
	}
	branched, err := flow.Parse([]byte(`
version: 1
flows:
  - name: on-a-branch
    on: authentication
    stages:
      - one_of:
          - {stage: passkey, when: device_managed}
          - {stage: password}
      - session
    tests:
      - {name: managed, given: {device_managed: true}, expect: [passkey, session]}
      - {name: unmanaged, given: {}, expect: [password, session]}
`))
	if err != nil {
		t.Fatalf("a flow branching on what the hook answers: %v", err)
	}
	if !branched.Flows[0].AsksProvider() {
		t.Error("a condition on a one_of branch was not seen")
	}

	f := newSignInFixture(t)
	f.applyFlow(t, `
version: 1
flows:
  - name: needs-a-compliant-device
    on: authentication
    stages:
      - password
      - {stage: mfa, when: not network_trusted}
      - session
    tests:
      - {name: trusted, given: {network_trusted: true}, expect: [password, session]}
      - {name: not, given: {}, expect: [password, mfa, session]}
`)
	if signedInBy(f.postLogin(t, nil)) {
		t.Error("with nothing to say the network is trusted, it was")
	}
}
