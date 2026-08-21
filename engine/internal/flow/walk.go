package flow

import (
	"fmt"
	"strings"
)

// Plan returns the stages that run under a fixed state.
//
// A snapshot: conditions are read once. That is right for a test case, which is
// making a claim about one situation, and wrong for the server, which is why the
// server uses Cursor.
func (fl *Flow) Plan(st State) []StageName {
	var out []StageName
	c := fl.Cursor()
	for {
		name, ok := c.Next(st)
		if !ok {
			return out
		}
		out = append(out, name)
	}
}

// Cursor is a position in a flow.
//
// Holds an index and nothing else. No copy of the conditions, no accumulated
// context, no user: a cursor that remembered what it decided earlier would be a
// second source of truth about the request, and the whole point of re-evaluating
// is that the first one is out of date.
type Cursor struct {
	fl *Flow
	i  int
}

// Cursor starts at the beginning of a flow.
func (fl *Flow) Cursor() *Cursor { return &Cursor{fl: fl} }

// At returns the cursor's position, for storing between requests.
//
// A flow spans several HTTP round trips -- the password form, then the second
// factor, then a prompt -- so the position has to survive in the pending
// authentication row rather than in memory.
func (c *Cursor) At() int { return c.i }

// Resume places a cursor at a stored position.
//
// Out-of-range positions clamp to the end rather than panicking. A stored index
// can outlive the file it indexed into: an operator edits the flow while
// somebody is halfway through it. Clamping ends that person's journey with no
// further stages, which the caller treats as a failed flow and restarts --
// annoying, and the alternative is running whatever stage happens to sit at that
// index in the new file, which could be the session.
func (fl *Flow) Resume(i int) *Cursor {
	if i < 0 {
		i = 0
	}
	if i > len(fl.Stages) {
		i = len(fl.Stages)
	}
	return &Cursor{fl: fl, i: i}
}

// Next returns the next stage to run, evaluating conditions against st NOW.
//
// Reports false when the flow is finished. Skipped stages are consumed, so a
// caller that stores At() after each call resumes past them.
func (c *Cursor) Next(ev Evaluator) (StageName, bool) {
	for c.i < len(c.fl.Stages) {
		step := c.fl.Stages[c.i]
		c.i++

		if len(step.OneOf) > 0 {
			// The first branch whose condition holds. The last branch has no
			// condition -- validateGroup insists -- so this always selects one,
			// which is the property safety.go relies on.
			for _, b := range step.OneOf {
				if holds(ev, b.When) {
					return b.Stage, true
				}
			}
			// Unreachable while validateGroup holds. Falling through rather than
			// panicking: a File built in Go rather than parsed could reach here,
			// and ending the flow with no stage is refused by the caller, whereas
			// a panic in the sign-in path is an outage.
			continue
		}

		if holds(ev, step.When) {
			return step.Stage, true
		}
	}
	return "", false
}

// Path is one journey a flow admits, and a set of conditions that produces it.
type Path struct {
	Stages []StageName
	// Given is the assignment that produced this path. Only the conditions the
	// flow actually mentions appear, and only those that must be true -- so it
	// reads as the situation a person would be in, rather than as a bit pattern.
	Given State
}

// Conditions lists the conditions a flow branches on, in the order they first
// appear. A flow with none has exactly one path.
func (fl *Flow) Conditions() []string {
	var out []string
	seen := map[string]bool{}
	note := func(expr string) {
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expr), "not "))
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, st := range fl.Stages {
		note(st.When)
		for _, b := range st.OneOf {
			note(b.When)
		}
	}
	return out
}

func (fl *Flow) Paths() ([]Path, error) {
	conds := fl.Conditions()
	if len(conds) > maxEnumeratedConditions {
		return nil, fmt.Errorf("this flow branches on %d conditions, so it admits up to %d "+
			"journeys; that is more than can be enumerated, and more than can be reviewed",
			len(conds), 1<<len(conds))
	}

	var out []Path
	seen := map[string]bool{}
	for mask := 0; mask < 1<<len(conds); mask++ {
		st := State{}
		for i, c := range conds {
			st[c] = mask&(1<<i) != 0
		}
		stages := fl.Plan(st)
		key := joinStages(stages)
		if seen[key] {
			continue
		}
		seen[key] = true
		// Only the conditions that are TRUE, so the printed situation is the
		// short one: "with a second factor" rather than a list of everything that
		// is not the case.
		given := State{}
		for _, c := range conds {
			if st[c] {
				given[c] = true
			}
		}
		out = append(out, Path{Stages: stages, Given: given})
	}
	return out, nil
}

// maxEnumeratedConditions bounds Paths. 2^20 is a million journeys; a flow near
// that is unreviewable whatever this number is.
const maxEnumeratedConditions = 20

// Summary describes a file in one line, for a CLI that has just loaded it.
func (f *File) Summary() string {
	if len(f.Flows) == 1 {
		fl := f.Flows[0]
		return fmt.Sprintf("1 flow (%s, %d steps)", fl.On, len(fl.Stages))
	}
	kinds := make([]string, 0, len(f.Flows))
	for _, fl := range f.Flows {
		kinds = append(kinds, string(fl.On))
	}
	return fmt.Sprintf("%d flows (%s)", len(f.Flows), strings.Join(kinds, ", "))
}

// WillRun reports whether a given stage runs on the journey this evaluator
// describes.
//
// Cheaper than walking, and the difference is not micro-optimisation. Walking to
// answer "is an mfa stage on this path" evaluates the condition of every stage it
// passes, including the ones guarding steps the question has nothing to do with
// -- on the sign-in path each of those is a database round trip, paid on every
// login, to answer something already known.
//
// It is exact because stages are a list: a plain stage runs iff its own `when`
// holds, independently of anything before it. A one_of runs the first branch
// whose condition holds, so only that group's branches are consulted, and only
// up to the one that matches.
//
// Returns false for a stage the flow does not mention, having evaluated nothing.
func (fl *Flow) WillRun(name StageName, ev Evaluator) bool {
	for _, step := range fl.Stages {
		if len(step.OneOf) > 0 {
			if !stepMentions(step, name) {
				// Nothing in this group is the stage being asked about, so which
				// branch would be taken does not matter and is not evaluated.
				continue
			}
			for _, b := range step.OneOf {
				if holds(ev, b.When) {
					if b.Stage == name {
						return true
					}
					break
				}
			}
			continue
		}
		if step.Stage != name {
			continue
		}
		if holds(ev, step.When) {
			return true
		}
	}
	return false
}

func stepMentions(s Step, name StageName) bool {
	for _, n := range s.stageNames() {
		if n == name {
			return true
		}
	}
	return false
}
