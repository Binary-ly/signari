package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
)

// The external authorization provider hook (ADR-011).
//
// # What is tested where, and why it is split
//
// The hook is deliberately hard to point at a local test server, and that is a
// security control working rather than an inconvenience to route around:
// `safedial` refuses loopback and private addresses, and `provider.Validate`
// refuses a non-https URL. An httptest server is `http://127.0.0.1:PORT`, which
// fails both. Disabling either to make a test convenient would remove the
// defence that stops a registered provider URL becoming a server-side request
// forgery.
//
// So the coverage is split, and both halves are real:
//
//   - The UNREACHABLE paths run through the entire production code path -- the
//     database row, LoadProvider, Validate, safedial, the dial, Decide -- using
//     192.0.2.1, which RFC 5737 reserves as unroutable and which safedial
//     permits (verified: Blocked(192.0.2.1) is false).
//   - The ANSWER paths are tested against combineProviderAnswer, the pure
//     function holding the composition rule.
//   - The HTTP mechanics -- timeouts, status handling, unknown fields, the
//     single ErrUnreachable -- are covered in internal/provider against a real
//     httptest server, which is legitimate there because that package takes the
//     client as a parameter.
//
// What is NOT covered end to end is a successful veto over real HTTPS. Saying so
// is better than a test that reaches it by turning off the SSRF guard.

// unroutable is an address that will never connect, and which the SSRF guard
// permits, so the failure under test is the provider being unreachable rather
// than the request being refused before it is made.
const unroutable = "https://192.0.2.1/decide"

type authzProviderFixture struct {
	f        *tokenFixture
	token    string
	subject  string
	resource string
}

func newAuthzProviderFixture(t *testing.T) *authzProviderFixture {
	t.Helper()
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)
	ctx := context.Background()

	model := authzen.Model{Types: map[string]authzen.Type{
		"doc": {
			Relations:   map[string][]string{"owner": nil},
			Permissions: map[string][]string{"can_edit": {"owner"}},
		},
	}}
	compiled, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.authorization_models (org_id, source, compiled)
		VALUES ($1::uuid, $2, $3::jsonb)
		ON CONFLICT (org_id) DO UPDATE SET source = $2, compiled = $3::jsonb`,
		f.orgID, "# provider hook test\n", compiled); err != nil {
		t.Fatalf("storing the model: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.authorization_models WHERE org_id = $1::uuid`, f.orgID)
	})

	subject := fmt.Sprintf("subj-%d", time.Now().UnixNano())
	resource := fmt.Sprintf("doc-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'user', $2, 'owner', 'doc', $3)`,
		f.orgID, subject, resource); err != nil {
		t.Fatalf("storing the relation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.relations WHERE org_id = $1::uuid`, f.orgID)
	})

	return &authzProviderFixture{f: f, token: token, subject: subject, resource: resource}
}

// registerProvider installs an authorize provider. The timeout is short so the
// unreachable tests do not spend seconds waiting.
func (a *authzProviderFixture) registerProvider(t *testing.T, url, mode string) {
	t.Helper()
	if _, err := a.f.pool.Exec(context.Background(), `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'test-pdp', 'authorize', $2, $3, 400)
		ON CONFLICT (org_id, hook) DO UPDATE SET
			url = EXCLUDED.url, mode = EXCLUDED.mode, enabled = true`,
		a.f.orgID, url, mode); err != nil {
		t.Fatalf("registering the provider: %v", err)
	}
	t.Cleanup(func() {
		_, _ = a.f.pool.Exec(context.Background(),
			`DELETE FROM core.providers WHERE org_id = $1::uuid`, a.f.orgID)
	})
}

func (a *authzProviderFixture) evaluate(t *testing.T, subject, resource string) (bool, string) {
	t.Helper()
	body := fmt.Sprintf(`{
		"subject":{"type":"user","id":%q},
		"action":{"name":"can_edit"},
		"resource":{"type":"doc","id":%q}}`, subject, resource)

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)
	rec := httptest.NewRecorder()
	a.f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("evaluation gave %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Decision bool `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding the decision: %v", err)
	}
	return resp.Decision, rec.Body.String()
}

// Baseline. Every claim below is relative to this, so a fixture that denied for
// an unrelated reason would make them all vacuous.
func TestWithoutAProviderTheLocalModelDecides(t *testing.T) {
	a := newAuthzProviderFixture(t)
	if ok, body := a.evaluate(t, a.subject, a.resource); !ok {
		t.Fatalf("the local model denied its own fixture: %s", body)
	}
}

// Unreachable + fail_closed denies, through the whole real path.
//
// This also proves the hook is WIRED: the only difference from the baseline
// above is a provider row, and the outcome flips.
func TestAnUnreachableProviderDeniesWhenFailClosed(t *testing.T) {
	a := newAuthzProviderFixture(t)
	a.registerProvider(t, unroutable, "fail_closed")

	ok, body := a.evaluate(t, a.subject, a.resource)
	if ok {
		t.Fatalf("a fail_closed provider was unreachable and access was allowed "+
			"anyway. An authorization hook that fails open stops enforcing exactly "+
			"when something is wrong: %s", body)
	}
}

// Unreachable + fail_open allows, because the operator declared that.
func TestAnUnreachableProviderAllowsWhenFailOpen(t *testing.T) {
	a := newAuthzProviderFixture(t)
	a.registerProvider(t, unroutable, "fail_open")

	ok, body := a.evaluate(t, a.subject, a.resource)
	if !ok {
		t.Fatalf("a fail_open provider was unreachable and the request was denied; "+
			"the declared mode was not honoured: %s", body)
	}
}

// A request the model already denies is unaffected, and costs no round trip.
//
// Measured by TIME rather than by a flag: the provider is unreachable with a
// 400ms timeout, so a call would take at least that. Returning promptly is
// evidence no call was made.
func TestAModelDenialIsNotSentToTheProvider(t *testing.T) {
	a := newAuthzProviderFixture(t)
	a.registerProvider(t, unroutable, "fail_closed")

	stranger := fmt.Sprintf("stranger-%d", time.Now().UnixNano())

	start := time.Now()
	ok, body := a.evaluate(t, stranger, a.resource)
	elapsed := time.Since(start)

	if ok {
		t.Fatalf("a subject holding no relation was allowed: %s", body)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("the denial took %s, which is long enough to have waited on the "+
			"provider. A request the model refuses should cost no network call",
			elapsed)
	}
}

// The composition rule, exhaustively.
//
// This is where the security argument lives, so every combination is enumerated
// rather than sampled.
func TestCombineProviderAnswerAppliesTheCompositionRule(t *testing.T) {
	boom := errors.New("connection refused")

	for _, tc := range []struct {
		name       string
		proceed    bool // p.Decide(callErr)
		callErr    error
		answer     providerAnswer
		wantVeto   bool
		wantAllow  bool // meaningful only when wantVeto
		wantReason string
	}{
		{
			name:    "provider refused -> veto",
			proceed: true, callErr: nil,
			answer:   providerAnswer{Decision: false},
			wantVeto: true, wantReason: "refused",
		},
		{
			name:    "provider allowed -> no veto, local allow stands",
			proceed: true, callErr: nil,
			answer:   providerAnswer{Decision: true},
			wantVeto: false,
		},
		{
			name:    "unreachable + fail_closed -> veto",
			proceed: false, callErr: boom,
			wantVeto: true, wantReason: "fail_closed",
		},
		{
			name:    "unreachable + fail_open -> no veto",
			proceed: true, callErr: boom,
			wantVeto: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, vetoed := combineProviderAnswer("test-pdp", tc.proceed, tc.callErr,
				tc.answer, "owner")
			if vetoed != tc.wantVeto {
				t.Fatalf("vetoed = %v, want %v", vetoed, tc.wantVeto)
			}
			if !vetoed {
				return
			}
			if resp.Decision {
				t.Error("a veto returned decision:true, which would allow the request " +
					"it was supposed to stop")
			}
			if tc.wantReason != "" {
				blob, _ := json.Marshal(resp.Context)
				if !strings.Contains(string(blob), tc.wantReason) {
					t.Errorf("the reason does not mention %q: %s", tc.wantReason, blob)
				}
			}
		})
	}
}

// The rule that cannot be broken: a provider answer is never consulted for a
// request the model denied, so "allow" can never become access.
//
// Asserted structurally. combineProviderAnswer is only ever reached after a
// local allow, and it has no branch that returns an ALLOW -- it returns either
// "no veto" (keep the local allow) or a denial. There is no input for which it
// produces a grant.
func TestCombineProviderAnswerCanNeverProduceAGrant(t *testing.T) {
	boom := errors.New("unreachable")
	for _, proceed := range []bool{true, false} {
		for _, callErr := range []error{nil, boom} {
			for _, decision := range []bool{true, false} {
				resp, vetoed := combineProviderAnswer("p", proceed, callErr,
					providerAnswer{Decision: decision}, "owner")
				if vetoed && resp.Decision {
					t.Fatalf("proceed=%v callErr=%v decision=%v produced a veto that "+
						"ALLOWS. The hook must only ever be able to deny",
						proceed, callErr, decision)
				}
			}
		}
	}
}
