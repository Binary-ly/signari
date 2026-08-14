package scim

import (
	"context"
	"fmt"
	"net/http"
	"sort"
)

// Severity ranks a drift finding.
type Severity int

const (
	// Critical: somebody who should have no access has it.
	Critical Severity = iota
	// Warning: somebody who should have access does not, or state disagrees in a
	// way that is not a security problem.
	Warning
	// Info: worth knowing, not worth acting on.
	Info
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case Warning:
		return "warning"
	default:
		return "info"
	}
}

// Finding is one disagreement between what we believe and what is true.
type Finding struct {
	Severity Severity
	RemoteID string
	UserName string
	Summary  string
	// Fix names the action, because a drift report nobody can act on is a report
	// nobody reads twice.
	Fix string
}

// Expected is our intent for one user at one target.
type Expected struct {
	UserID   string
	RemoteID string
	UserName string
	Active   bool
	// Synced is false when we have a link row but never confirmed a send.
	Synced bool
}

// VerifyReport is the result of reconciling one target.
type VerifyReport struct {
	Target      string
	Checked     int
	RemoteTotal int
	Findings    []Finding
	Unreachable bool
	UnreachErr  string
}

// Critical returns only the findings that mean somebody has access they should
// not.
func (r *VerifyReport) CriticalFindings() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == Critical {
			out = append(out, f)
		}
	}
	return out
}

// Verify reads the target's actual state and compares it with our intent.
//
// # Why this exists
//
// Everything else in provisioning records what we MEANT to happen. A row saying
// `should_be_active = false` means an administrator pressed deactivate and the
// request did not return an error. It does not mean the account is gone.
//
// Between the two sit: a target that returned 200 and ignored the patch, a
// queue entry that failed after its last retry and was parked, an account
// recreated by a local administrator at the target, an integration disabled
// months ago that nobody re-enabled. Each leaves a live account for somebody
// who has left, and none of them is visible from our own tables.
//
// So this asks the target.
func Verify(ctx context.Context, c *Client, expected []Expected, hc *http.Client) (*VerifyReport, error) {
	rep := &VerifyReport{Target: c.target.Slug}

	remote, err := c.ListUsers(ctx, 100)
	if err != nil {
		// Reported rather than returned as a plain error: a target we cannot
		// reach is itself a finding, and a verify that stops at the first
		// unreachable target tells you nothing about the others.
		rep.Unreachable = true
		rep.UnreachErr = err.Error()
		return rep, nil
	}
	rep.RemoteTotal = len(remote)

	byID := make(map[string]User, len(remote))
	for _, u := range remote {
		byID[u.ID] = u
	}

	seen := map[string]bool{}
	for _, e := range expected {
		rep.Checked++
		seen[e.RemoteID] = true

		u, present := byID[e.RemoteID]
		switch {
		case !present && !e.Active:
			// Deactivated here, absent there. The desired end state.

		case !present && e.Active:
			rep.Findings = append(rep.Findings, Finding{
				Severity: Warning, RemoteID: e.RemoteID, UserName: e.UserName,
				Summary: "should have access and the remote account does not exist",
				Fix:     "re-run provisioning for this user; they cannot sign in to this application",
			})

		case present && !e.Active && u.Active:
			// THE finding this whole package exists to surface.
			rep.Findings = append(rep.Findings, Finding{
				Severity: Critical, RemoteID: e.RemoteID, UserName: u.UserName,
				Summary: "was deactivated here and is STILL ACTIVE at the target",
				Fix: "this person retains access they should not have. Deactivate them " +
					"at the target now, then find out why the change did not arrive " +
					"-- check the parked provisioning queue.",
			})

		case present && e.Active && !u.Active:
			rep.Findings = append(rep.Findings, Finding{
				Severity: Warning, RemoteID: e.RemoteID, UserName: u.UserName,
				Summary: "is active here and deactivated at the target",
				Fix:     "somebody deactivated them at the target directly; re-provision or deactivate here too",
			})

		case present && !e.Synced:
			rep.Findings = append(rep.Findings, Finding{
				Severity: Info, RemoteID: e.RemoteID, UserName: u.UserName,
				Summary: "linked but never confirmed synced",
				Fix:     "run a provisioning pass to bring the target up to date",
			})
		}
	}

	// Remote accounts we have no record of. Not automatically wrong -- a target
	// may legitimately hold accounts that do not come from us -- so it is
	// reported as information rather than treated as drift to correct. Deleting
	// what we do not recognise is how a provisioning integration destroys
	// somebody's service account.
	var orphans []User
	for _, u := range remote {
		if !seen[u.ID] && u.Active {
			orphans = append(orphans, u)
		}
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].UserName < orphans[j].UserName })
	for _, u := range orphans {
		rep.Findings = append(rep.Findings, Finding{
			Severity: Info, RemoteID: u.ID, UserName: u.UserName,
			Summary: "active at the target and not provisioned by Signari",
			Fix: "left alone deliberately -- it may be a service account or predate " +
				"this integration. Remove it at the target if it should not be there.",
		})
	}

	// Most severe first: the one line an operator reads is the first one.
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		return rep.Findings[i].Severity < rep.Findings[j].Severity
	})
	return rep, nil
}

// Summary is a one-line verdict.
func (r *VerifyReport) Summary() string {
	if r.Unreachable {
		return fmt.Sprintf("%s: UNREACHABLE (%s)", r.Target, r.UnreachErr)
	}
	crit := len(r.CriticalFindings())
	if crit > 0 {
		return fmt.Sprintf("%s: %d user(s) retain access they should not have",
			r.Target, crit)
	}
	if len(r.Findings) > 0 {
		return fmt.Sprintf("%s: %d checked, %d finding(s), none critical",
			r.Target, r.Checked, len(r.Findings))
	}
	return fmt.Sprintf("%s: %d checked, no drift", r.Target, r.Checked)
}
