package directory

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Synchronising group membership from a directory.
//
// # Nothing is joined that an operator did not map
//
// A group here decides which applications its members reach, which is why the
// admin API gives groups their own scope pair rather than letting `users:write`
// edit them. A sync that could create local groups from remote names would
// therefore be an external system granting application access by inventing a
// group.
//
// So the mapping is explicit and the direction is deny: remote group
// "Engineering" reaches local group X because somebody declared it, and a
// remote group with no mapping produces nothing at all — not a warning, not an
// auto-created group, nothing.
//
// # A removal ceiling, for the same reason as the deactivation ceiling
//
// `checkCeiling` refuses a plan that would deactivate too much of an
// organisation at once, because a cliff is almost always a bad fetch rather
// than that many people leaving. Membership removal has exactly the same
// failure: a filter matching too little, a truncated page, or an upstream
// outage returns a user with no groups, and applying it strips their access
// everywhere.
//
// The ceiling is on REMOVALS only. Additions are not bounded, because the
// failure mode they represent — a fetch returning too MUCH — is not something a
// percentage can distinguish from a genuine reorganisation, and refusing to add
// people to groups does not protect anybody from anything.

// GroupAction is one membership change.
type GroupAction struct {
	Kind    string // "join" | "leave"
	UserID  string
	GroupID string
	// GroupName and RemoteGroup are carried for the plan description, so an
	// operator reading it sees names rather than two uuids.
	GroupName   string
	RemoteGroup string
}

// GroupPlan is what a membership sync would do.
type GroupPlan struct {
	Actions []GroupAction
	// MembershipsBefore is what the ceiling is measured against.
	MembershipsBefore int
	Refused           string
}

// Safe reports whether the plan may be applied.
func (p *GroupPlan) Safe() bool { return p.Refused == "" }

// Counts returns joins and leaves.
func (p *GroupPlan) Counts() (join, leave int) {
	for _, a := range p.Actions {
		switch a.Kind {
		case "join":
			join++
		case "leave":
			leave++
		}
	}
	return join, leave
}

// GroupMapping is one declared remote-to-local mapping.
type GroupMapping struct {
	RemoteGroup string
	GroupID     string
	GroupName   string
}

// LoadGroupMappings reads what a source is allowed to grant.
func LoadGroupMappings(ctx context.Context, db *pgxpool.Pool, sourceID string) ([]GroupMapping, error) {
	rows, err := db.Query(ctx, `
		SELECT m.remote_group, m.group_id::text, g.name
		FROM core.directory_group_map m
		JOIN core.groups g ON g.id = m.group_id
		WHERE m.source_id = $1::uuid
		ORDER BY m.remote_group`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("loading the directory's group mappings: %w", err)
	}
	defer rows.Close()

	out := []GroupMapping{}
	for rows.Next() {
		var m GroupMapping
		if err := rows.Scan(&m.RemoteGroup, &m.GroupID, &m.GroupName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// BuildGroupPlan works out the membership changes a sync would make.
//
// `remoteGroups` is keyed by local user id and holds the remote group names the
// directory reported for that person. `current` is keyed the same way and holds
// the local group ids they are in TODAY, restricted to groups this source maps —
// a membership in a group the source does not map is none of its business and
// must never be removed by it.
func BuildGroupPlan(mappings []GroupMapping, remoteGroups map[string][]string,
	current map[string][]string, maxRemovalPercent int) *GroupPlan {

	// remote group name -> the local groups it grants.
	grants := map[string][]GroupMapping{}
	for _, m := range mappings {
		grants[m.RemoteGroup] = append(grants[m.RemoteGroup], m)
	}
	// The local groups this source governs at all. Anything outside it is left
	// alone, in both directions.
	governed := map[string]GroupMapping{}
	for _, m := range mappings {
		governed[m.GroupID] = m
	}

	p := &GroupPlan{}
	for _, ids := range current {
		p.MembershipsBefore += len(ids)
	}

	// Users the directory reported. A user absent from remoteGroups entirely is
	// NOT treated as "in no groups" -- absence from a fetch is not evidence of
	// removal, and treating it as such is how a partial page strips everybody.
	for userID, names := range remoteGroups {
		want := map[string]GroupMapping{}
		for _, name := range names {
			for _, m := range grants[name] {
				want[m.GroupID] = m
			}
		}

		have := map[string]bool{}
		for _, gid := range current[userID] {
			have[gid] = true
		}

		for gid, m := range want {
			if !have[gid] {
				p.Actions = append(p.Actions, GroupAction{
					Kind: "join", UserID: userID, GroupID: gid,
					GroupName: m.GroupName, RemoteGroup: m.RemoteGroup,
				})
			}
		}
		for gid := range have {
			if _, still := want[gid]; still {
				continue
			}
			m, isGoverned := governed[gid]
			if !isGoverned {
				// Not this source's group. Leaving it alone is the whole reason
				// `current` is restricted, and this is the second guard.
				continue
			}
			p.Actions = append(p.Actions, GroupAction{
				Kind: "leave", UserID: userID, GroupID: gid,
				GroupName: m.GroupName, RemoteGroup: m.RemoteGroup,
			})
		}
	}

	sort.Slice(p.Actions, func(i, j int) bool {
		if p.Actions[i].UserID != p.Actions[j].UserID {
			return p.Actions[i].UserID < p.Actions[j].UserID
		}
		return p.Actions[i].GroupID < p.Actions[j].GroupID
	})

	p.checkRemovalCeiling(maxRemovalPercent)
	return p
}

// checkRemovalCeiling refuses a plan that strips too much access at once.
func (p *GroupPlan) checkRemovalCeiling(maxPercent int) {
	_, leave := p.Counts()
	if leave == 0 || p.MembershipsBefore == 0 || maxPercent <= 0 {
		return
	}
	share := leave * 100 / p.MembershipsBefore
	if share <= maxPercent {
		return
	}
	p.Refused = fmt.Sprintf(
		"this sync would remove %d of %d memberships (%d%%), over the %d%% ceiling. "+
			"Nothing has been applied. Group membership decides which applications "+
			"people reach, so a cliff like this takes access away from everybody at "+
			"once -- and it is almost always a bad fetch rather than a real "+
			"reorganisation. Check the plan, and raise the ceiling deliberately if "+
			"it is genuinely correct",
		leave, p.MembershipsBefore, share, maxPercent)
}

// Describe renders the plan for an operator to read before applying it.
func (p *GroupPlan) Describe() string {
	if !p.Safe() {
		return "REFUSED: " + p.Refused
	}
	join, leave := p.Counts()
	if join == 0 && leave == 0 {
		return "no membership changes"
	}
	return fmt.Sprintf("%d to join, %d to leave, of %d memberships",
		join, leave, p.MembershipsBefore)
}
