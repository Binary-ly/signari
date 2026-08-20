package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The first test anywhere that drives the AuthZEN endpoints over HTTP.
//
// Five routes are registered — evaluation, evaluations and three searches — and
// until now the only coverage was a rule model in internal/authzen and a test
// that reads this file's source looking for a `continue`. Both were written
// because building a fixture "would be a large amount of machinery around a
// small fact". The machinery turns out to be an INSERT.
//
// What that gap hid is below: we answered 400 to a request §7.1 defines exactly.
func newPDPCaller(t *testing.T, f *tokenFixture) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	// A fresh outpost per test: the rate limiter buckets on the outpost id, so
	// sharing one would make these tests throttle each other. That exact
	// collision — a shared bucket keyed on something two tests had in common —
	// has already produced three flakes in this suite.
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.outposts (org_id, kind, name, token_hash, enabled)
		VALUES ($1::uuid, 'pdp', $2, $3, true)`,
		f.orgID, "authzen-wire-"+t.Name(), sum[:]); err != nil {
		t.Fatalf("creating a pdp outpost: %v", err)
	}
	return token
}

func postAuthz(t *testing.T, f *tokenFixture, token, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s returned %d with a body that is not JSON: %s",
				path, rec.Code, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestEvaluationsFallsBackToASingleEvaluation(t *testing.T) {
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "an empty evaluations array",
			body: `{"subject":{"type":"user","id":"alice"},
			        "resource":{"type":"document","id":"1"},
			        "action":{"name":"read"},
			        "evaluations":[]}`,
		},
		{
			name: "no evaluations key at all",
			body: `{"subject":{"type":"user","id":"alice"},
			        "resource":{"type":"document","id":"1"},
			        "action":{"name":"read"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postAuthz(t, f, token, "/access/v1/evaluations", tc.body)
			if code != http.StatusOK {
				t.Fatalf("got %d, want 200: §7.1 defines this request, so refusing "+
					"it as malformed is wrong. Body: %v", code, body)
			}
			// The SINGLE shape, per "backwards-compatible manner with the
			// (single) Access Evaluation API Request".
			if _, wrapped := body["evaluations"]; wrapped {
				t.Errorf("the response carries an `evaluations` array; §7.1 says this "+
					"behaves as the single Access Evaluation Request, whose response "+
					"is a bare decision: %v", body)
			}
			if _, ok := body["decision"]; !ok {
				t.Errorf("no `decision` key in the response: %v", body)
			}
		})
	}
}

// A malformed defaults-only request must still be a 400, not a denial.
//
// The fallback must not become a way to get `decision: false` for a request that
// never named a subject — which is the failure the handler's own comment calls
// out: "a PDP that returns false for both teaches callers that a denial might
// just mean they sent the wrong shape".
func TestTheFallbackStillRejectsAMalformedRequest(t *testing.T) {
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)

	code, body := postAuthz(t, f, token, "/access/v1/evaluations",
		`{"resource":{"type":"document","id":"1"},"action":{"name":"read"},"evaluations":[]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for a request with no subject: %v", code, body)
	}
}

// §7.1.2.1.1's worked example shows the entry that stops the batch carrying the
// semantic that stopped it:
//
//	{"decision": false, "context": {"code": "200", "reason": "deny_on_first_deny"}}
//
// Without it a PEP cannot tell "the batch short-circuited" from "the batch was
// this short" except by counting against what it sent.
func TestDenyOnFirstDenyMarksTheEntryThatStoppedTheBatch(t *testing.T) {
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)

	// Three questions, no policy granting any of them, so the first denies and
	// the batch must stop there.
	code, body := postAuthz(t, f, token, "/access/v1/evaluations",
		`{"subject":{"type":"user","id":"alice"},
		  "action":{"name":"read"},
		  "options":{"evaluations_semantic":"deny_on_first_deny"},
		  "evaluations":[{"resource":{"type":"document","id":"1"}},
		                 {"resource":{"type":"document","id":"2"}},
		                 {"resource":{"type":"document","id":"3"}}]}`)
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200: %v", code, body)
	}
	list, ok := body["evaluations"].([]any)
	if !ok {
		t.Fatalf("no evaluations array in the response: %v", body)
	}
	if len(list) != 1 {
		t.Fatalf("got %d results for 3 questions under deny_on_first_deny; the "+
			"batch must stop at the first denial: %v", len(list), body)
	}
	first, _ := list[0].(map[string]any)
	if first["decision"] != false {
		t.Errorf("the entry that stopped the batch is not a denial: %v", first)
	}
	ctx, _ := first["context"].(map[string]any)
	if ctx == nil || ctx["reason"] != "deny_on_first_deny" {
		t.Errorf("context.reason = %v, want \"deny_on_first_deny\" — §7.1.2.1.1's "+
			"example carries it, and without it a PEP cannot tell a short-circuit "+
			"from a short batch: %v", ctx["reason"], first)
	}
}

// execute_all is the default and must run every entry.
//
// The counterpart to the test above: if the short-circuit fired unconditionally
// the batch would return one answer to three questions, and a PEP boxcarring
// twenty permission checks would silently act on the first.
func TestExecuteAllRunsEveryEntry(t *testing.T) {
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)

	code, body := postAuthz(t, f, token, "/access/v1/evaluations",
		`{"subject":{"type":"user","id":"alice"},
		  "action":{"name":"read"},
		  "evaluations":[{"resource":{"type":"document","id":"1"}},
		                 {"resource":{"type":"document","id":"2"}},
		                 {"resource":{"type":"document","id":"3"}}]}`)
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200: %v", code, body)
	}
	list, _ := body["evaluations"].([]any)
	if len(list) != 3 {
		t.Fatalf("got %d results for 3 questions under the default semantic; "+
			"execute_all must answer all of them: %v", len(list), body)
	}
	// And none of them carries the short-circuit marker.
	for i, e := range list {
		m, _ := e.(map[string]any)
		if c, _ := m["context"].(map[string]any); c != nil && c["reason"] == "deny_on_first_deny" {
			t.Errorf("entry %d is marked deny_on_first_deny under execute_all: %v", i, m)
		}
	}
}

// A denial is 200 with {"decision": false}, never 403.
//
// The package comment calls this "the one thing implementations get wrong": a
// PDP answering 403 for "no" is indistinguishable from one refusing to talk to
// the caller, and a PEP cannot tell an authorization decision from an
// authentication failure.
func TestADenialIs200NotForbidden(t *testing.T) {
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)

	code, body := postAuthz(t, f, token, "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"nobody"},
		  "resource":{"type":"document","id":"secret"},
		  "action":{"name":"read"}}`)
	if code != http.StatusOK {
		t.Fatalf("a denial came back as %d; it must be 200 carrying "+
			"{\"decision\": false}: %v", code, body)
	}
	if body["decision"] != false {
		t.Errorf("decision = %v, want false for a subject with no relations: %v",
			body["decision"], body)
	}
}

// An outpost token issued for something else must not reach the PDP.
func TestTheAuthorizationAPIRefusesANonPDPToken(t *testing.T) {
	f := newTokenFixture(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.outposts (org_id, kind, name, token_hash, enabled)
		VALUES ($1::uuid, 'ldap', $2, $3, true)`,
		f.orgID, "authzen-wrong-kind-"+t.Name(), sum[:]); err != nil {
		t.Fatalf("creating an ldap outpost: %v", err)
	}

	code, _ := postAuthz(t, f, token, "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"alice"},
		  "resource":{"type":"document","id":"1"},
		  "action":{"name":"read"}}`)
	if code != http.StatusForbidden {
		t.Errorf("an ldap outpost token got %d from the authorization API; it "+
			"would otherwise be able to ask about every relation in the "+
			"organisation", code)
	}
}
