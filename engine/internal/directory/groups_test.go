package directory

import "testing"

// Group membership sync, and the three rules that keep it from granting access
// nobody asked for.

var mappings = []GroupMapping{
	{RemoteGroup: "Engineering", GroupID: "g-eng", GroupName: "Engineers"},
	{RemoteGroup: "Finance", GroupID: "g-fin", GroupName: "Finance"},
}

// An unmapped remote group grants nothing.
//
// A sync that auto-created local groups from remote names would be an external
// system granting application access by inventing a group.
func TestAnUnmappedRemoteGroupGrantsNothing(t *testing.T) {
	p := BuildGroupPlan(mappings,
		map[string][]string{"u1": {"Engineering", "Executives", "Board"}},
		map[string][]string{}, 50)

	if !p.Safe() {
		t.Fatalf("refused: %s", p.Refused)
	}
	join, _ := p.Counts()
	if join != 1 {
		t.Fatalf("joined %d groups, want 1. Only the mapped remote group may "+
			"grant anything; the others must produce nothing at all.", join)
	}
	if p.Actions[0].GroupID != "g-eng" {
		t.Errorf("joined %q, want g-eng", p.Actions[0].GroupID)
	}
}

// A membership in a group this source does not map is left alone.
//
// The directory governs the groups an operator mapped to it and nothing else. A
// person hand-added to an unrelated group must not be removed by a sync that has
// no opinion about it.
func TestASyncDoesNotTouchGroupsItDoesNotGovern(t *testing.T) {
	p := BuildGroupPlan(mappings,
		map[string][]string{"u1": {"Engineering"}},
		map[string][]string{"u1": {"g-eng", "g-handmade"}}, 50)

	if !p.Safe() {
		t.Fatalf("refused: %s", p.Refused)
	}
	for _, a := range p.Actions {
		if a.GroupID == "g-handmade" {
			t.Fatalf("the sync proposed to %s a group it does not govern", a.Kind)
		}
	}
}

// Losing a remote group removes the local membership it granted.
func TestLosingARemoteGroupRemovesTheMembership(t *testing.T) {
	p := BuildGroupPlan(mappings,
		map[string][]string{"u1": {"Engineering"}},
		map[string][]string{"u1": {"g-eng", "g-fin"}}, 50)

	if !p.Safe() {
		t.Fatalf("refused: %s", p.Refused)
	}
	_, leave := p.Counts()
	if leave != 1 {
		t.Fatalf("leave count = %d, want 1", leave)
	}
	if p.Actions[0].Kind != "leave" || p.Actions[0].GroupID != "g-fin" {
		t.Errorf("unexpected action: %+v", p.Actions[0])
	}
}

// A user the fetch did not mention is not stripped.
//
// Absence from a fetch is not evidence of removal. Treating it as such is how a
// truncated page takes access away from everybody it failed to mention.
func TestAUserMissingFromTheFetchIsNotStripped(t *testing.T) {
	p := BuildGroupPlan(mappings,
		map[string][]string{}, // the fetch returned nobody
		map[string][]string{"u1": {"g-eng"}, "u2": {"g-fin"}}, 50)

	if len(p.Actions) != 0 {
		t.Fatalf("an empty fetch proposed %d changes. Absence from a fetch is "+
			"not evidence of removal.", len(p.Actions))
	}
}

// A cliff of removals is refused, like the deactivation ceiling.
func TestARemovalCliffIsRefused(t *testing.T) {
	remote := map[string][]string{}
	current := map[string][]string{}
	for _, u := range []string{"u1", "u2", "u3", "u4"} {
		remote[u] = []string{}         // the directory now reports no groups
		current[u] = []string{"g-eng"} // everybody is currently in one
	}

	p := BuildGroupPlan(mappings, remote, current, 50)
	if p.Safe() {
		t.Fatal("a sync removing every membership was accepted. Group membership " +
			"decides which applications people reach, so this takes access away " +
			"from everybody at once — and it is almost always a bad fetch.")
	}
	if p.Refused == "" {
		t.Error("refused with no explanation")
	}
}

// Additions are deliberately not bounded.
func TestAdditionsAreNotSubjectToTheCeiling(t *testing.T) {
	remote := map[string][]string{}
	for _, u := range []string{"u1", "u2", "u3", "u4"} {
		remote[u] = []string{"Engineering", "Finance"}
	}
	p := BuildGroupPlan(mappings, remote, map[string][]string{}, 1)
	if !p.Safe() {
		t.Fatalf("a sync that only adds memberships was refused: %s. Refusing to "+
			"add people to groups protects nobody from anything.", p.Refused)
	}
	if join, _ := p.Counts(); join != 8 {
		t.Errorf("join count = %d, want 8", join)
	}
}

// A steady state proposes nothing, so a second run is quiet.
func TestASteadyStateProposesNothing(t *testing.T) {
	p := BuildGroupPlan(mappings,
		map[string][]string{"u1": {"Engineering", "Finance"}},
		map[string][]string{"u1": {"g-eng", "g-fin"}}, 50)
	if len(p.Actions) != 0 {
		t.Fatalf("a steady state proposed %d changes: %+v", len(p.Actions), p.Actions)
	}
}
