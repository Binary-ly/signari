package directory

import (
	"strings"
	"testing"
)

func remote(id, email string, suspended bool) RemoteUser {
	return RemoteUser{ID: id, Email: email, Name: email, Suspended: suspended}
}

func local(userID, remoteID, email string, active bool) LocalUser {
	return LocalUser{UserID: userID, RemoteID: remoteID, Email: email, Name: email, Active: active}
}

// TestAnEmptyDirectoryIsRefused is the failure this whole design exists for.
//
// An upstream outage, a bad filter, or a truncated first page all look exactly
// like "everybody left the company". A reconciler that believes it deactivates
// the entire organisation.
func TestAnEmptyDirectoryIsRefused(t *testing.T) {
	var localUsers []LocalUser
	for i := 0; i < 50; i++ {
		localUsers = append(localUsers, local("u", "r", "p@x.test", true))
		localUsers[i].UserID = string(rune('a' + i%26))
		localUsers[i].RemoteID = "remote-" + localUsers[i].UserID
	}

	p := BuildPlan(nil, localUsers, "deactivate", 20)

	if p.Safe() {
		t.Fatal("a sync that deactivates every user was allowed")
	}
	if !strings.Contains(p.Refused, "bad fetch") {
		t.Errorf("the refusal should explain the likely cause; got %q", p.Refused)
	}
	// And nothing is partially applicable: the caller checks Safe() and stops.
	_, _, deactivate, _ := p.Counts()
	if deactivate == 0 {
		t.Error("the plan should still SHOW what it would have done")
	}
}

// TestOrdinaryAttritionIsAllowed. The ceiling must not block real life: a couple
// of leavers out of fifty is a Tuesday, not an incident.
func TestOrdinaryAttritionIsAllowed(t *testing.T) {
	var localUsers []LocalUser
	var remoteUsers []RemoteUser
	for i := 0; i < 50; i++ {
		id := string(rune('a'+i%26)) + string(rune('0'+i/26))
		localUsers = append(localUsers, local("u"+id, "r"+id, id+"@x.test", true))
		if i >= 2 { // two people gone
			remoteUsers = append(remoteUsers, remote("r"+id, id+"@x.test", false))
		}
	}

	p := BuildPlan(remoteUsers, localUsers, "deactivate", 20)
	if !p.Safe() {
		t.Fatalf("two leavers out of fifty was refused: %s", p.Refused)
	}
	_, _, deactivate, _ := p.Counts()
	if deactivate != 2 {
		t.Errorf("deactivate = %d, want 2", deactivate)
	}
}

// TestReportModeProposesNothingDestructive is the default, and the reason a new
// source cannot hurt anybody on its first run.
func TestReportModeProposesNothingDestructive(t *testing.T) {
	localUsers := []LocalUser{local("u1", "r1", "a@x.test", true)}
	p := BuildPlan(nil, localUsers, "report", 20)

	if !p.Safe() {
		t.Errorf("report mode was refused by the ceiling: %s", p.Refused)
	}
	_, _, deactivate, _ := p.Counts()
	if deactivate != 0 {
		t.Error("report mode proposed a deactivation")
	}
	// It still names who WOULD go -- that number is what tells an operator
	// whether their filter is right.
	found := false
	for _, a := range p.Actions {
		if a.Kind == "report-missing" && a.Email == "a@x.test" {
			found = true
		}
	}
	if !found {
		t.Error("report mode hid who would have been deactivated")
	}
}

// TestMatchingIsOnRemoteIDNotEmail.
//
// Somebody changes their surname and their email with it. Matching on email
// would read that as a departure plus an arrival: one account deactivated, one
// created, and the person locked out of everything they owned.
func TestMatchingIsOnRemoteIDNotEmail(t *testing.T) {
	localUsers := []LocalUser{local("u1", "r1", "old.name@x.test", true)}
	remoteUsers := []RemoteUser{remote("r1", "new.name@x.test", false)}

	p := BuildPlan(remoteUsers, localUsers, "deactivate", 20)
	create, update, deactivate, _ := p.Counts()

	if deactivate != 0 || create != 0 {
		t.Fatalf("a rename produced create=%d deactivate=%d; it must be an update",
			create, deactivate)
	}
	if update != 1 {
		t.Fatalf("update = %d, want 1", update)
	}
	if p.Actions[0].Was != "old.name@x.test" || p.Actions[0].Now != "new.name@x.test" {
		t.Errorf("the diff does not show the change: %+v", p.Actions[0])
	}
}

func TestSuspendedUpstreamDeactivatesHere(t *testing.T) {
	localUsers := []LocalUser{local("u1", "r1", "a@x.test", true)}
	remoteUsers := []RemoteUser{remote("r1", "a@x.test", true)}

	p := BuildPlan(remoteUsers, localUsers, "report", 20)
	_, _, deactivate, _ := p.Counts()
	if deactivate != 1 {
		t.Errorf("a user suspended upstream was not deactivated: %d", deactivate)
	}
	// Note this happens even in report mode: "suspended upstream" is a positive
	// statement from the directory, not an absence that might mean a bad fetch.
}

func TestReactivationIsNotBlockedByTheCeiling(t *testing.T) {
	var localUsers []LocalUser
	var remoteUsers []RemoteUser
	for i := 0; i < 10; i++ {
		id := string(rune('a' + i))
		localUsers = append(localUsers, local("u"+id, "r"+id, id+"@x.test", false))
		remoteUsers = append(remoteUsers, remote("r"+id, id+"@x.test", false))
	}

	p := BuildPlan(remoteUsers, localUsers, "deactivate", 20)
	if !p.Safe() {
		t.Fatalf("restoring everybody was refused: %s", p.Refused)
	}
	_, _, _, reactivate := p.Counts()
	if reactivate != 10 {
		t.Errorf("reactivate = %d, want 10", reactivate)
	}
}

// TestRemoteUserWithNoIDIsSkipped. Without an immutable id there is nothing to
// track across a rename, and falling back to email is the bug.
func TestRemoteUserWithNoIDIsSkipped(t *testing.T) {
	p := BuildPlan([]RemoteUser{{Email: "ghost@x.test"}}, nil, "report", 20)
	if len(p.Actions) != 0 {
		t.Errorf("a record with no remote id produced %d actions", len(p.Actions))
	}
}

func TestDescribePutsDestructiveActionsFirst(t *testing.T) {
	localUsers := []LocalUser{
		local("u1", "r1", "leaver@x.test", true),
		local("u2", "r2", "renamed@x.test", true),
	}
	remoteUsers := []RemoteUser{
		remote("r2", "changed@x.test", false),
		remote("r3", "newbie@x.test", false),
	}
	p := BuildPlan(remoteUsers, localUsers, "deactivate", 90)
	out := p.Describe()

	di := strings.Index(out, "deactivate")
	ci := strings.Index(out, "create")
	if di < 0 || ci < 0 || di > ci {
		t.Errorf("deactivations are not listed before creations:\n%s", out)
	}
}
