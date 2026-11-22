package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Groups inside groups (11.09), against a real database: what a person is in, what an
// application is told, what they may do, and the loops nobody can make.

func groupName(t *testing.T, conn *pgx.Conn, id string) string {
	t.Helper()
	var name string
	must(t, conn.QueryRow(t.Context(), `SELECT name FROM core.groups WHERE id = $1::uuid`, id).Scan(&name))
	return name
}

func nest(t *testing.T, conn *pgx.Conn, orgID, group, parent string) {
	t.Helper()
	added, err := NestGroup(t.Context(), conn, orgID, group, parent, "")
	if err != nil || !added {
		t.Fatalf("nesting: added %v, %v", added, err)
	}
}

// A person put in the bottom group is in every group above it, for claims and decisions
// alike; a release naming a group above releases it; taking a nesting away takes it all
// away on the next read.
func TestMembershipFollowsGroupsInsideGroups(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, clientID, _ := fixture(t, conn)
	a, b, c := groupFixture(t, orgID, false), groupFixture(t, orgID, false), groupFixture(t, orgID, false)
	an, bn, cn := groupName(t, conn, a), groupName(t, conn, b), groupName(t, conn, c)
	must(t, AddGroupMember(ctx, conn, orgID, an, userID, ""))
	nest(t, conn, orgID, a, b)
	nest(t, conn, orgID, b, c)

	all, err := AllGroupsForUser(ctx, conn, userID)
	must(t, err)
	if want := sortedNames(an, bn, cn); !slices.Equal(all, want) {
		t.Errorf("in %v, want %v: a member of a group inside others is in them", all, want)
	}

	must(t, ReleaseGroupsToClient(ctx, conn, orgID, clientID, []string{cn}))
	told, err := GroupsForUser(ctx, conn, userID, clientID)
	must(t, err)
	if !slices.Equal(told, []string{cn}) {
		t.Errorf("an application released only the top group was told %v, want [%s]", told, cn)
	}

	removed, err := UnnestGroup(ctx, conn, orgID, b, c)
	must(t, err)
	if !removed {
		t.Fatal("the nesting was not there to take away")
	}
	told, err = GroupsForUser(ctx, conn, userID, clientID)
	must(t, err)
	if len(told) != 0 {
		t.Errorf("still told %v once the group was taken out of the one released", told)
	}
	all, err = AllGroupsForUser(ctx, conn, userID)
	must(t, err)
	if want := sortedNames(an, bn); !slices.Equal(all, want) {
		t.Errorf("in %v after the nesting went, want %v", all, want)
	}
}

func sortedNames(n ...string) []string {
	slices.Sort(n)
	return n
}

// A group cannot end up inside itself, directly or through others, and both groups are
// the organisation's.
func TestANestingThatMakesALoopIsRefused(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, _, _ := fixture(t, conn)
	otherOrg, _, _, _ := fixture(t, conn)
	a, b, c := groupFixture(t, orgID, false), groupFixture(t, orgID, false), groupFixture(t, orgID, false)
	elsewhere := groupFixture(t, otherOrg, false)
	nest(t, conn, orgID, a, b)
	nest(t, conn, orgID, b, c)

	for _, tc := range []struct {
		name          string
		group, parent string
		want          error
	}{
		{"the top inside the bottom", c, a, ErrNestingLoop},
		{"one step back", b, a, ErrNestingLoop},
		{"inside itself", a, a, ErrNestingLoop},
		{"another organisation's group", a, elsewhere, ErrNestingGroupUnknown},
		{"into this one from another", elsewhere, a, ErrNestingGroupUnknown},
	} {
		if _, err := NestGroup(ctx, conn, orgID, tc.group, tc.parent, ""); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if added, err := NestGroup(ctx, conn, orgID, a, b, ""); err != nil || added {
		t.Errorf("nesting again: added %v, %v; want nothing done and no error", added, err)
	}
}

// Two nestings that each look fine alone and close a loop together: the second waits for
// the first and is refused once it can see it.
func TestTwoNestingsThatCloseALoopTogetherCannotBothPass(t *testing.T) {
	ctx := context.Background()
	conn, other := connect(t), connect(t)
	orgID, _, _, _ := fixture(t, conn)
	a, b := groupFixture(t, orgID, false), groupFixture(t, orgID, false)

	first, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = first.Rollback(ctx) }()
	if _, err := NestGroup(ctx, first, orgID, a, b, ""); err != nil {
		t.Fatal(err)
	}
	// Answered once the transaction is over, rollback and all: it answered before its
	// deferred rollback ran, and the test's cleanup closed the connection under it (a data
	// race, go test -race, 19 Nov).
	second := make(chan error, 1)
	go func() {
		second <- func() error {
			tx, err := other.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := NestGroup(ctx, tx, orgID, b, a, ""); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
	}()
	select {
	case err := <-second:
		t.Fatalf("the second nesting did not wait for the first: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	must(t, first.Commit(ctx))
	if err := <-second; !errors.Is(err, ErrNestingLoop) {
		t.Fatalf("the second nesting, once the first was committed: %v, want a refused loop", err)
	}
}

// A group inside one that may impersonate grants it: to its members, and to whoever is
// added to it, so every check guarding the flag sees it there.
func TestImpersonationComesThroughAGroupAbove(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	helpers, admins := groupFixture(t, orgID, false), groupFixture(t, orgID, true)
	must(t, AddGroupMember(ctx, conn, orgID, groupName(t, conn, helpers), userID, ""))

	check := func(want bool) {
		t.Helper()
		may, err := MayImpersonate(ctx, conn, orgID, userID)
		must(t, err)
		_, person, _, err := PrivilegedUser(ctx, conn, userID)
		must(t, err)
		_, group, _, err := PrivilegedGroup(ctx, conn, helpers)
		must(t, err)
		named, err := GroupMayImpersonate(ctx, conn, orgID, groupName(t, conn, helpers))
		must(t, err)
		if may != want || person != want || group != want || named != want {
			t.Errorf("may impersonate %v, privileged person %v, privileged group %v, group may %v; want all %v",
				may, person, group, named, want)
		}
	}
	check(false)
	nest(t, conn, orgID, helpers, admins)
	check(true)
	if _, err := UnnestGroup(ctx, conn, orgID, helpers, admins); err != nil {
		t.Fatal(err)
	}
	check(false)
}
