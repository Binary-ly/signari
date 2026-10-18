package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The access policy is asked of the database on every decision. It was a
// thirty-second reload, so a deny rule written to shut a client out kept
// letting it in for up to half a minute on each node.

func (f *signInFixture) decision(t *testing.T) bool {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	return f.srv.checkAccessPolicy(context.Background(), r, f.orgID, f.clientID, f.userID,
		"openid", false, []string{"pwd"}) == nil
}

func TestANewDenyRuleAppliesOnTheNextRequest(t *testing.T) {
	f := newSignInFixture(t)
	// A policy in force and parsed, so anything held in memory is warm.
	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient("someone-else"))
	if !f.decision(t) {
		t.Fatal("a policy naming another client refused this one")
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	if f.decision(t) {
		t.Fatal("a deny rule written a moment ago was not applied to the next request")
	}

	removePolicy(t, f.srv, f.pool, f.orgID)
	if !f.decision(t) {
		t.Fatal("a removed policy was still refusing")
	}
}

// A broken policy must never become an absent one: absent means allow
// everything. Only a document written to the database directly, bypassing
// `policy apply`, can be broken.
func TestABrokenStoredPolicyKeepsThePreviousOneOrRefuses(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	breakIt := func() {
		t.Helper()
		if _, err := f.pool.Exec(ctx,
			`UPDATE core.access_policies SET document = 'version: 1\npolicies: [{name: x, nonsense: 1}]'
			  WHERE org_id = $1::uuid`, f.orgID); err != nil {
			t.Fatal(err)
		}
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	if f.decision(t) {
		t.Fatal("the deny rule did not apply")
	}
	breakIt()
	if f.decision(t) {
		t.Fatal("a broken stored policy dropped the deny rule that was in force before it")
	}

	// No predecessor: a server that has never seen a good version of it.
	fresh := newSignInFixture(t)
	applyPolicy(t, fresh.srv, fresh.pool, fresh.orgID, denyClient("someone-else"))
	if _, err := fresh.pool.Exec(ctx,
		`UPDATE core.access_policies SET document = 'version: 1\npolicies: [{name: x, nonsense: 1}]'
		  WHERE org_id = $1::uuid`, fresh.orgID); err != nil {
		t.Fatal(err)
	}
	if fresh.decision(t) {
		t.Fatal("a broken stored policy with nothing before it allowed everything")
	}
}
