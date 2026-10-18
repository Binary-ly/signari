package httpapi

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// A signup rule's default groups go to anyone at an allowed domain, so one
// whose members may impersonate would give that to whoever signs up. Self-signup
// skips it; an invitation, which names one person and comes from the
// operator, does not.
func TestSelfSignupNeverJoinsAGroupThatMayImpersonate(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	suffix := fmt.Sprint(time.Now().UnixNano())
	support, staff := "support-"+suffix, "staff-"+suffix
	for _, g := range []struct {
		name string
		flag bool
	}{{support, true}, {staff, false}} {
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
			VALUES ($1::uuid, $2, $2, $3)`, f.orgID, g.name, g.flag); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.groups WHERE org_id = $1::uuid AND name = ANY($2)`,
			f.orgID, []string{support, staff})
	})

	create := func(selfSignup bool) (string, []string) {
		t.Helper()
		email := fmt.Sprintf("signup-%d@example.test", time.Now().UnixNano())
		userID, joined, err := f.srv.createAccount(ctx, f.orgID, email,
			"correct horse battery staple", []string{support, staff}, selfSignup)
		if err != nil {
			t.Fatalf("createAccount: %v", err)
		}
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, userID)
		})
		return userID, joined
	}
	inSupport := func(userID string) bool {
		t.Helper()
		var in bool
		if err := f.pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM core.group_members m JOIN core.groups g ON g.id = m.group_id
			                WHERE m.user_id = $1::uuid AND g.name = $2)`, userID, support).Scan(&in); err != nil {
			t.Fatal(err)
		}
		return in
	}

	user, joined := create(true)
	if inSupport(user) {
		t.Fatal("a self-signup joined a group whose members may impersonate")
	}
	if !slices.Equal(joined, []string{staff}) {
		t.Errorf("joined = %v, want only %s: the audit record must say what happened", joined, staff)
	}

	invited, joined := create(false)
	if !inSupport(invited) || len(joined) != 2 {
		t.Errorf("an invitation's groups were not all joined: %v", joined)
	}
}
