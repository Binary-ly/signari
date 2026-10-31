package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/policy"
	"signari.dev/engine/internal/store"
)

// A rule on a person's attributes, from the operator declaring one to a decision that turns
// when the value does (11.08). Read on each decision, as who somebody is always is, and a
// rule that could not be met or should not read what it names is refused when it is stored.
func TestARuleAsksAboutAPersonsAttributes(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	centre, secret := "cost_centre_"+suffix, "salary_band_"+suffix

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, a := range []store.Attribute{
		{Name: centre, ValueType: "string"},
		{Name: secret, ValueType: "string", Personal: true},
	} {
		if _, err := store.DeclareAttribute(ctx, tx, f.orgID, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetUserAttribute(ctx, tx, f.userID, f.orgID, centre, "4100", root); err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserAttribute(ctx, tx, f.userID, f.orgID, secret, "9", root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.user_attribute_schema
			WHERE org_id = $1::uuid AND name = ANY($2)`, f.orgID, []string{centre, secret})
	})

	document := func(name, values string, want string) string {
		return fmt.Sprintf(`
version: 1
policies:
  - name: only-its-own
    require:
      user_attributes:
        %s: %s
tests:
  - name: as written
    given: {client: x, attributes: {%s: "4100"}}
    expect: %s
`, name, values, name, want)
	}

	// What cannot be met, and what must not be read, does not get stored.
	for _, c := range []struct{ name, doc, want string }{
		{"a typo", document("cost_centr", `["4100"]`, "allow"), "not declared"},
		{"a sealed value", document(secret, `["4100"]`, "allow"), "personal"},
	} {
		if _, err := store.ApplyAccessPolicy(ctx, f.pool, f.orgID, []byte(c.doc)); !errors.Is(err, store.ErrInvalidDocument) ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("a policy on %s: %v, want a refusal naming %q", c.name, err, c.want)
		}
	}
	model := func(name string) *authzen.Model {
		t.Helper()
		m, err := authzen.ParseModel([]byte(fmt.Sprintf(`types:
  document:
    relations:
      owner: []
    permissions:
      read: [owner]
    require:
      read: {user_attributes: {%s: ["4100"]}}
tests:
  - name: an owner in the cost centre
    subject: user:alice
    action: read
    resource: document:1
    relations: [owner]
    attributes: {%s: "4100"}
    allow: true
`, name, name)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if err := store.SaveModel(ctx, f.pool, f.orgID, "source", model(secret), ""); !errors.Is(err, store.ErrInvalidDocument) {
		t.Errorf("a model reading a sealed attribute: %v", err)
	}
	if err := store.SaveModel(ctx, f.pool, f.orgID, "source", model("not_declared"), ""); !errors.Is(err, store.ErrInvalidDocument) {
		t.Errorf("a model reading an undeclared attribute: %v", err)
	}

	// Stored the way an operator stores it, and asked the way a sign-in asks.
	doc := document(centre, `["4100", "4200"]`, "allow")
	if _, err := store.ApplyAccessPolicy(ctx, f.pool, f.orgID, []byte(doc)); err != nil {
		t.Fatalf("a policy on a declared attribute: %v", err)
	}
	t.Cleanup(func() { removePolicy(t, f.srv, f.pool, f.orgID) })
	decide := func() *policy.Decision {
		t.Helper()
		return f.srv.checkAccessPolicyUnobserved(ctx, f.orgID, f.clientID, f.userID, "openid", false, nil)
	}
	if d := decide(); d != nil && !d.Allowed {
		t.Fatalf("somebody in the cost centre was refused by %+v", d)
	}
	set := func(value string) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if value == "" {
			if err := store.ClearUserAttribute(ctx, tx, f.userID, f.orgID, centre); err != nil {
				t.Fatal(err)
			}
		} else if err := store.SetUserAttribute(ctx, tx, f.userID, f.orgID, centre, value, root); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	set("9999")
	if d := decide(); d == nil || d.Allowed {
		t.Errorf("after moving to another cost centre the decision was %+v, from the next request", d)
	}
	set("4200")
	if d := decide(); d != nil && !d.Allowed {
		t.Errorf("back in a listed cost centre: %+v", d)
	}
	set("")
	if d := decide(); d == nil || d.Allowed {
		t.Errorf("with the attribute gone: %+v; somebody who holds nothing does not meet it", d)
	}

	// The same facts reach the authorization model, and the sealed value does not.
	set("4100")
	facts, err := store.SubjectFacts(ctx, f.pool, f.orgID, f.userID, "")
	if err != nil {
		t.Fatal(err)
	}
	if facts.Attributes[centre] != "4100" {
		t.Errorf("the model was given %v", facts.Attributes)
	}
	if _, leaked := facts.Attributes[secret]; leaked {
		t.Error("a personal attribute reached a decision")
	}
	allow, err := authzen.ParseModel([]byte(fmt.Sprintf(`types:
  document:
    relations:
      owner: []
    permissions:
      read: [owner]
    require:
      read: {user_attributes: {%s: ["4100"]}}
tests:
  - name: an owner in the cost centre
    subject: user:alice
    action: read
    resource: document:1
    relations: [owner]
    attributes: {%s: "4100"}
    allow: true
`, centre, centre)))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveModel(ctx, f.pool, f.orgID, "source", allow, ""); err != nil {
		t.Errorf("a model on a declared attribute: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.authorization_models WHERE org_id = $1::uuid`, f.orgID)
	})
	c, _ := allow.ConditionFor("document", "read")
	if !c.SatisfiedBy(facts) {
		t.Errorf("the condition %q was not met by %v", c.Summary(), facts.Attributes)
	}
	if got := c.Unmet(authzen.Facts{}); !strings.Contains(got, centre) {
		t.Errorf("a refusal said %q, which does not name the attribute", got)
	}
}
