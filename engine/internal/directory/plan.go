// Package directory synchronises users from Google Workspace and Microsoft
// Entra ID.
//
// # Reconciled, not replayed
//
// The sync computes a PLAN from desired state and current state, and the plan is
// inspectable before anything is written. That is the same shape as the SCIM
// provisioning in this engine, and for the same reason: an event queue drifts
// silently when an event is missed, while a reconciler converges from whatever
// state it finds.
//
// # The plan is refused, not truncated
//
// Directory sync is where data loss lives. A filter that matches too little, a
// paginated fetch that stops early, an API that returns an empty page during an
// outage -- each looks identical to "everybody left the company", and a naive
// reconciler deactivates them all.
//
// So a plan that would deactivate more than a configured share of the
// organisation is refused ENTIRELY. Not applied partially, not truncated to the
// first N: the number itself is the evidence that the input was wrong, and
// applying any of it would be acting on input we have just decided not to
// believe.
package directory

import (
	"fmt"
	"sort"
	"strings"
)

// RemoteUser is one person as the upstream directory describes them.
type RemoteUser struct {
	// ID is the remote's immutable identifier. Never an email address: people
	// change those, and matching on one makes a rename look like a departure
	// followed by an arrival.
	ID        string
	Email     string
	Name      string
	Suspended bool
}

// LocalUser is one person as this engine currently has them.
type LocalUser struct {
	UserID   string
	RemoteID string
	Email    string
	Name     string
	Active   bool
}

// Action is one change the plan proposes.
type Action struct {
	Kind     string // "create" | "update" | "deactivate" | "reactivate"
	RemoteID string
	Email    string
	// Was and Now describe an update, for showing a diff before applying it.
	Was string
	Now string
	// UserID is set for anything touching an existing local user.
	UserID string
	// Name is the remote display name, carried so Apply stores what was actually
	// seen.
	//
	// Without it the stored name defaulted to the email address, so every later
	// run compared "Alice" against "alice@example.test" and proposed the same
	// update forever. That churn is invisible on a first run and only appears on
	// the second, which is why the test syncs twice.
	Name string
}

// Plan is what a sync would do.
type Plan struct {
	Actions []Action
	// ActiveBefore is how many active users the organisation had, which is what
	// the deactivation ceiling is measured against.
	ActiveBefore int
	// Refused explains why the plan must not be applied, when it must not.
	Refused string
}

// Counts summarises a plan.
func (p *Plan) Counts() (create, update, deactivate, reactivate int) {
	for _, a := range p.Actions {
		switch a.Kind {
		case "create":
			create++
		case "update":
			update++
		case "deactivate":
			deactivate++
		case "reactivate":
			reactivate++
		}
	}
	return
}

// Safe reports whether the plan may be applied.
func (p *Plan) Safe() bool { return p.Refused == "" }

// BuildPlan compares a remote directory against local state.
//
// onMissing is "report" or "deactivate". maxDeactivatePercent is the ceiling; a
// plan exceeding it is refused whole.
func BuildPlan(remote []RemoteUser, local []LocalUser, onMissing string,
	maxDeactivatePercent int) *Plan {

	p := &Plan{}
	byRemoteID := map[string]LocalUser{}
	for _, l := range local {
		if l.Active {
			p.ActiveBefore++
		}
		if l.RemoteID != "" {
			byRemoteID[l.RemoteID] = l
		}
	}

	seen := map[string]bool{}

	for _, r := range remote {
		if r.ID == "" {
			// A remote record with no immutable id cannot be tracked across a
			// rename. Skipped rather than matched on email, which is the mistake
			// this whole design exists to avoid.
			continue
		}
		seen[r.ID] = true
		l, known := byRemoteID[r.ID]

		switch {
		case !known:
			if r.Suspended {
				// Suspended upstream and unknown here: creating them would be
				// creating a disabled account nobody asked for.
				continue
			}
			p.Actions = append(p.Actions, Action{
				Kind: "create", RemoteID: r.ID, Email: r.Email, Now: r.Email,
				Name: r.Name,
			})

		case r.Suspended && l.Active:
			p.Actions = append(p.Actions, Action{
				Kind: "deactivate", RemoteID: r.ID, Email: l.Email, UserID: l.UserID,
				Was: "active", Now: "suspended upstream",
			})

		case !r.Suspended && !l.Active:
			// Reactivation is proposed but is NOT counted against the ceiling:
			// the ceiling exists to stop mass removal, and refusing to restore
			// people because too many are being restored would be the opposite of
			// its purpose.
			p.Actions = append(p.Actions, Action{
				Kind: "reactivate", RemoteID: r.ID, Email: l.Email, UserID: l.UserID,
				Was: "inactive", Now: "active upstream",
			})

		default:
			if !strings.EqualFold(r.Email, l.Email) || r.Name != l.Name {
				was := l.Email
				now := r.Email
				if strings.EqualFold(r.Email, l.Email) {
					was, now = l.Name, r.Name
				}
				p.Actions = append(p.Actions, Action{
					Kind: "update", RemoteID: r.ID, Email: r.Email, UserID: l.UserID,
					Was: was, Now: now, Name: r.Name,
				})
			}
		}
	}

	// People we have who the directory did not return.
	for _, l := range local {
		if l.RemoteID == "" || seen[l.RemoteID] || !l.Active {
			continue
		}
		kind := "deactivate"
		if onMissing != "deactivate" {
			// Reported rather than acted on. The action is still in the plan so
			// an operator can see exactly who would go, which is the number that
			// tells them whether the filter is right.
			kind = "report-missing"
		}
		p.Actions = append(p.Actions, Action{
			Kind: kind, RemoteID: l.RemoteID, Email: l.Email, UserID: l.UserID,
			Was: "active", Now: "absent from the directory",
		})
	}

	sort.SliceStable(p.Actions, func(i, j int) bool {
		return p.Actions[i].Kind < p.Actions[j].Kind
	})

	p.checkCeiling(maxDeactivatePercent)
	return p
}

// checkCeiling refuses a plan that removes too much.
func (p *Plan) checkCeiling(maxPercent int) {
	_, _, deactivate, _ := p.Counts()
	if deactivate == 0 || p.ActiveBefore == 0 {
		return
	}

	share := deactivate * 100 / p.ActiveBefore
	if share <= maxPercent {
		return
	}

	p.Refused = fmt.Sprintf(
		"this sync would deactivate %d of %d active users (%d%%), over the %d%% ceiling. "+
			"Nothing has been applied. A cliff like this is almost always a bad fetch "+
			"-- a filter matching too little, a truncated page, an upstream outage -- "+
			"rather than that many people leaving at once. Check the plan, and raise "+
			"the ceiling deliberately if it is genuinely correct",
		deactivate, p.ActiveBefore, share, maxPercent)
}

// Describe renders a plan for a human, deactivations first.
//
// Ordered that way because the destructive actions are the ones somebody needs
// to read, and a list that buries eleven deactivations under four hundred
// updates is a list nobody reads to the end.
func (p *Plan) Describe() string {
	var b strings.Builder
	create, update, deactivate, reactivate := p.Counts()

	order := map[string]int{"deactivate": 0, "report-missing": 1, "reactivate": 2,
		"create": 3, "update": 4}
	acts := append([]Action(nil), p.Actions...)
	sort.SliceStable(acts, func(i, j int) bool {
		return order[acts[i].Kind] < order[acts[j].Kind]
	})

	shown := 0
	for _, a := range acts {
		if shown >= 40 {
			fmt.Fprintf(&b, "  ... and %d more\n", len(acts)-shown)
			break
		}
		switch a.Kind {
		case "update":
			fmt.Fprintf(&b, "  %-14s %s: %q -> %q\n", a.Kind, a.Email, a.Was, a.Now)
		default:
			fmt.Fprintf(&b, "  %-14s %s\n", a.Kind, a.Email)
		}
		shown++
	}

	fmt.Fprintf(&b, "\n  create %d   update %d   deactivate %d   reactivate %d\n",
		create, update, deactivate, reactivate)
	if !p.Safe() {
		fmt.Fprintf(&b, "\n  REFUSED: %s\n", p.Refused)
	}
	return b.String()
}
