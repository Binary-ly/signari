package flow


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
func (c *Cursor) Next(st State) (StageName, bool) {
	for c.i < len(c.fl.Stages) {
		step := c.fl.Stages[c.i]
		c.i++

		if len(step.OneOf) > 0 {
			// The first branch whose condition holds. The last branch has no
			// condition -- validateGroup insists -- so this always selects one,
			// which is the property safety.go relies on.
			for _, b := range step.OneOf {
				if st.holds(b.When) {
					return b.Stage, true
				}
			}
			// Unreachable while validateGroup holds. Falling through rather than
			// panicking: a File built in Go rather than parsed could reach here,
			// and ending the flow with no stage is refused by the caller, whereas
			// a panic in the sign-in path is an outage.
			continue
		}

		if st.holds(step.When) {
			return step.Stage, true
		}
	}
	return "", false
}
