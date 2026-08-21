package flow

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is a parsed flow document.
type File struct {
	Version int    `yaml:"version"`
	Flows   []Flow `yaml:"flows"`
}

// Designation is what a flow is for.
//
// It is not decoration: it selects which safety rule applies. An authentication
// flow must prove who somebody is; an enrolment flow, by definition, runs before
// there is anybody to prove.
type Designation string

const (
	// Authentication is the sign-in journey. Subject to the proof rule.
	Authentication Designation = "authentication"
	// Enrolment creates an account. NOT subject to the proof rule -- there is no
	// existing subject to prove -- but it may not reach a session either, so a
	// self-service sign-up cannot hand out a live session on its own.
	Enrolment Designation = "enrolment"
	// Recovery restores access to an account whose credential is lost. Subject
	// to the proof rule, with a deliberately narrower set of stages that count:
	// see provingStages. A recovery flow that accepts the very factor it exists
	// to replace is a bypass with a friendly name.
	Recovery Designation = "recovery"
	// Unenrolment deletes an account. Subject to the proof rule: deletion is an
	// action taken on a subject, so the subject must be proven.
	Unenrolment Designation = "unenrolment"
)

// Driven reports whether this engine actually EXECUTES flows of a designation.
//
// # Why this exists
//
// The flow language defines four designations and the engine drives one.
// `flowFor` has exactly two callers and both pass Authentication; `/signup` and
// `/recover` are hardcoded journeys that never consult a flow file.
//
// So an operator can write a recovery flow, have it parsed, have its safety
// analysed by rules written specifically for it -- `recoveryProving` exists so a
// recovery flow cannot accept the very factor it is replacing -- watch its tests
// pass, install it with `signari flow apply`, and it will govern nothing.
//
// The tests pass because they exercise the walker, which genuinely works. What
// does not exist is a driver that consults it at those endpoints.
//
// This predicate does not fix that. It exists so that nothing in this codebase
// can claim otherwise by omission: every place that accepts a flow file asks
// this question and says the answer out loud. A promise that is unenforced is
// worse than an absent feature, because the operator stops looking.
//
// See item 9q in TODO-FOR-YOU.md. Closing the gap properly -- driving enrolment,
// then recovery -- is a scope decision rather than a technical one, and it is not
// this file's to make.
func (d Designation) Driven() bool { return d == Authentication }

// Undriven returns the designations this engine parses and does not execute.
func Undriven() []Designation {
	var out []Designation
	for _, d := range []Designation{Authentication, Enrolment, Recovery, Unenrolment} {
		if !d.Driven() {
			out = append(out, d)
		}
	}
	return out
}

// Flow is one journey.
type Flow struct {
	Name string `yaml:"name"`
	// On is the designation. Named `on` in the file because it reads as the
	// occasion the flow runs on.
	On Designation `yaml:"on"`
	// Stages are walked in order. A stage whose condition does not hold is
	// skipped, not failed.
	Stages []Step `yaml:"stages"`
	// Tests are run by Parse. Required.
	Tests []TestCase `yaml:"tests"`
}

// Step is one position in a flow.
//
// Exactly one of Stage and OneOf is set. YAML admits three spellings, because
// the common case should be one word:
//
//   - password                       a stage, unconditional
//   - {stage: mfa, when: ...}        a stage, conditional
//   - {one_of: [...]}                a choice between branches
type Step struct {
	Stage StageName `yaml:"stage,omitempty"`
	When  string    `yaml:"when,omitempty"`
	// OneOf is a set of branches of which exactly one runs. The engine takes the
	// first whose condition holds; the last branch must be unconditional, so
	// that "exactly one" is a fact rather than a hope.
	//
	// This exists for a specific reason, and it is not sugar. Written as two
	// conditional stages --
	//
	//	- {stage: passkey,  when: user_has_passkey}
	//	- {stage: password, when: not user_has_passkey}
	//
	// -- the safety analysis must consider the path where both conditions are
	// false, because it cannot know the two are exhaustive. That path reaches a
	// session having proved nothing, so the flow would be refused, correctly but
	// uselessly. A one_of group is the author stating that the branches are
	// exhaustive, in a form the analysis can verify rather than take on trust:
	// the required default branch is what makes the group total.
	OneOf []Branch `yaml:"one_of,omitempty"`
}

// Branch is one alternative inside a one_of.
type Branch struct {
	Stage StageName `yaml:"stage"`
	// When empty, this is the default branch: it runs when no earlier branch
	// matched. Exactly one branch must have an empty When, and it must be last.
	When string `yaml:"when,omitempty"`
}

// TestCase is a case the file makes about itself.
type TestCase struct {
	Name string `yaml:"name"`
	// Given sets the conditions. A condition not named here is false.
	Given map[string]bool `yaml:"given"`
	// Expect is the exact ordered list of stages that should run.
	//
	// Exact, not "contains": a flow that runs an extra stage nobody expected is
	// as wrong as one that skips a required stage, and the second kind is the
	// kind that gets somebody in.
	Expect []StageName `yaml:"expect"`
}

// UnmarshalYAML accepts a bare stage name as well as a mapping.
//
// `- password` and `- {stage: password}` mean the same thing. Without this the
// unconditional case -- which is most of a flow -- would be five extra
// characters of punctuation per line, and a file people find noisy is a file
// they keep in a browser instead.
func (s *Step) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var name string
		if err := n.Decode(&name); err != nil {
			return err
		}
		s.Stage = StageName(name)
		return nil
	}
	if err := checkKeys(n, "stage", "when", "one_of"); err != nil {
		return err
	}
	// A named type, so decoding the mapping does not re-enter this method.
	type raw Step
	var r raw
	if err := n.Decode(&r); err != nil {
		return err
	}
	*s = Step(r)
	return nil
}

// UnmarshalYAML exists on Branch only to reject unknown keys. See checkKeys.
func (b *Branch) UnmarshalYAML(n *yaml.Node) error {
	if err := checkKeys(n, "stage", "when"); err != nil {
		return err
	}
	type raw Branch
	var r raw
	if err := n.Decode(&r); err != nil {
		return err
	}
	*b = Branch(r)
	return nil
}

// checkKeys refuses a mapping with keys outside the allowed set.
//
// The decoder's KnownFields(true) does NOT reach inside a custom UnmarshalYAML:
// yaml.Node.Decode has no equivalent setting, so every field of a type with its
// own unmarshaller silently loses the strictness the rest of the file has. That
// is how `{stage: mfa, whn: user_has_second_factor}` parsed happily as an
// unconditional stage -- the exact class of failure the strictness exists to
// prevent, hiding in the code that implements the terse spelling.
//
// Found by a test asserting the misspelling was refused, which it was not.
func checkKeys(n *yaml.Node, allowed ...string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a stage name or a mapping", n.Line)
	}
	ok := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		ok[a] = true
	}
	// Mapping content alternates key, value.
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if !ok[k] {
			return fmt.Errorf("line %d: %q is not a field here (expected one of: %s)",
				n.Content[i].Line, k, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// Parse reads a flow file, validates it, and RUNS ITS TESTS.
//
// All three, or none: a file that fails any of them does not parse. The safety
// analysis in particular is not a lint that can be waived, because the failure
// it prevents is somebody being signed in without authenticating.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// Unknown fields are an ERROR. A misspelled `when` would otherwise become an
	// unconditional stage -- a condition that appears to restrict and does not,
	// which is the same failure internal/policy guards against and has worse
	// consequences here.
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the flow file did not parse: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("flow version %d is not supported (expected 1)", f.Version)
	}
	if len(f.Flows) == 0 {
		return nil, fmt.Errorf("this file defines no flows")
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	if err := f.RunTests(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *File) validate() error {
	seen := map[string]bool{}
	for i := range f.Flows {
		fl := &f.Flows[i]
		if fl.Name == "" {
			return fmt.Errorf("flow %d has no name; a flow that refuses somebody must be "+
				"findable in this file by the name in the error", i+1)
		}
		if seen[fl.Name] {
			return fmt.Errorf("two flows are named %q", fl.Name)
		}
		seen[fl.Name] = true
		if err := fl.validate(); err != nil {
			return fmt.Errorf("flow %q: %w", fl.Name, err)
		}
	}
	return nil
}

func (fl *Flow) validate() error {
	switch fl.On {
	case Authentication, Enrolment, Recovery, Unenrolment:
	case "":
		return fmt.Errorf("no `on:`; state what this flow is for (%s)", designations())
	default:
		return fmt.Errorf("`on: %s` is not a designation (%s)", fl.On, designations())
	}
	if len(fl.Stages) == 0 {
		return fmt.Errorf("has no stages")
	}

	for i, st := range fl.Stages {
		switch {
		case st.Stage != "" && len(st.OneOf) > 0:
			return fmt.Errorf("step %d sets both `stage` and `one_of`; it can be one or the other", i+1)
		case st.Stage == "" && len(st.OneOf) == 0:
			return fmt.Errorf("step %d names no stage", i+1)
		case st.Stage != "":
			if !st.Stage.known() {
				return fmt.Errorf("step %d: %q is not a stage (%s)", i+1, st.Stage, knownStages())
			}
			if err := checkCondition(st.When); err != nil {
				return fmt.Errorf("step %d (%s): %w", i+1, st.Stage, err)
			}
		default:
			if err := validateGroup(st.OneOf); err != nil {
				return fmt.Errorf("step %d: %w", i+1, err)
			}
		}
	}

	// Terminal stages end a flow and may not appear anywhere else. A stage after
	// `session` is a stage that never runs, and an author who wrote one believes
	// something false about their own flow.
	for i, st := range fl.Stages {
		for _, name := range st.stageNames() {
			if !name.terminal() {
				continue
			}
			if i != len(fl.Stages)-1 {
				return fmt.Errorf("step %d is %s, which ends a flow, but %d step(s) follow it",
					i+1, name, len(fl.Stages)-i-1)
			}
			if st.When != "" {
				return fmt.Errorf("the final step (%s) is conditional; a flow whose last "+
					"step can be skipped has paths that end in nothing at all", name)
			}
		}
	}
	last := fl.Stages[len(fl.Stages)-1]
	for _, name := range last.stageNames() {
		if !name.terminal() {
			return fmt.Errorf("ends with %s, which is not a terminal stage; a flow must "+
				"end in %s, %s or %s so that every path has a stated outcome",
				name, StageSession, StageDone, StageDeny)
		}
	}

	if len(fl.Tests) == 0 {
		return fmt.Errorf("has no tests. Add cases under `tests:` stating which stages " +
			"should run -- they run every time this file is loaded, so a flow that stops " +
			"doing what you meant cannot deploy")
	}
	return fl.checkSafety()
}

func validateGroup(bs []Branch) error {
	if len(bs) < 2 {
		return fmt.Errorf("a one_of with %d branch(es) is not a choice; write the stage directly",
			len(bs))
	}
	for i, b := range bs {
		if b.Stage == "" {
			return fmt.Errorf("one_of branch %d names no stage", i+1)
		}
		if !b.Stage.known() {
			return fmt.Errorf("one_of branch %d: %q is not a stage (%s)", i+1, b.Stage, knownStages())
		}
		if b.Stage.terminal() {
			return fmt.Errorf("one_of branch %d is %s, which ends a flow; a terminal stage "+
				"cannot be one arm of a choice the flow continues past", i+1, b.Stage)
		}
		if err := checkCondition(b.When); err != nil {
			return fmt.Errorf("one_of branch %d (%s): %w", i+1, b.Stage, err)
		}
		if b.When == "" && i != len(bs)-1 {
			return fmt.Errorf("one_of branch %d (%s) has no `when`, so it always matches, "+
				"and %d later branch(es) can never run", i+1, b.Stage, len(bs)-i-1)
		}
	}
	// The default branch is what makes the group total, and totality is what
	// lets safety.go treat the group as one thing that definitely happens. A
	// group without it is just conditional stages wearing a hat.
	if bs[len(bs)-1].When != "" {
		return fmt.Errorf("the last one_of branch (%s) is conditional, so every branch can "+
			"be skipped and the choice is not a choice. Give the last branch no `when`, "+
			"making it the default", bs[len(bs)-1].Stage)
	}
	return nil
}

// stageNames lists the stages a step can run.
func (s Step) stageNames() []StageName {
	if s.Stage != "" {
		return []StageName{s.Stage}
	}
	out := make([]StageName, 0, len(s.OneOf))
	for _, b := range s.OneOf {
		out = append(out, b.Stage)
	}
	return out
}

// RunTests evaluates every case in every flow.
func (f *File) RunTests() error {
	var failures []string
	for i := range f.Flows {
		fl := &f.Flows[i]
		names := map[string]bool{}
		for _, tc := range fl.Tests {
			if tc.Name == "" {
				return fmt.Errorf("flow %q has a test with no name", fl.Name)
			}
			if names[tc.Name] {
				return fmt.Errorf("flow %q has two tests named %q", fl.Name, tc.Name)
			}
			names[tc.Name] = true
			// A condition the file never mentions is almost always a typo, and a
			// typo here makes the case prove nothing: it sets a condition no
			// stage reads, and passes for the wrong reason.
			for k := range tc.Given {
				if !isCondition(k) {
					return fmt.Errorf("flow %q, test %q: %q is not a condition (%s)",
						fl.Name, tc.Name, k, knownConditions())
				}
			}
			got := fl.Plan(State(tc.Given))
			if !sameStages(got, tc.Expect) {
				failures = append(failures, fmt.Sprintf("  %s / %s: expected %s, got %s",
					fl.Name, tc.Name, joinStages(tc.Expect), joinStages(got)))
			}
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return fmt.Errorf("these flows do not do what their tests say:\n%s",
			strings.Join(failures, "\n"))
	}
	return nil
}

// Flow finds a flow by name.
func (f *File) Flow(name string) (*Flow, bool) {
	for i := range f.Flows {
		if f.Flows[i].Name == name {
			return &f.Flows[i], true
		}
	}
	return nil, false
}

// For finds the flow for a designation. The first one wins, so a file with two
// authentication flows uses the first -- which validate() permits deliberately,
// because a deployment may keep a second one to switch to.
func (f *File) For(d Designation) (*Flow, bool) {
	for i := range f.Flows {
		if f.Flows[i].On == d {
			return &f.Flows[i], true
		}
	}
	return nil, false
}

func sameStages(a, b []StageName) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinStages(s []StageName) string {
	if len(s) == 0 {
		return "(no stages)"
	}
	parts := make([]string, len(s))
	for i, n := range s {
		parts[i] = string(n)
	}
	return strings.Join(parts, " -> ")
}

func designations() string {
	return fmt.Sprintf("%s, %s, %s, %s", Authentication, Enrolment, Recovery, Unenrolment)
}
