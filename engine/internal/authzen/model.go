package authzen

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The authorization model: which relations imply which, and what each permits.
//
// # Why it is a file with tests in it
//
// The same reason the access policy is. A model is a security control, and a
// security control nobody can check is a security control nobody has checked.
// Parse RUNS the tests -- a model whose own examples fail does not load, so it
// cannot be deployed and discovered wrong later.
//
// # The shape
//
//	types:
//	  document:
//	    relations:
//	      owner: []
//	      editor: [owner]          # an owner is an editor
//	      viewer: [editor]         # an editor is a viewer
//	    permissions:
//	      read:  [viewer]
//	      write: [editor]
//	      delete: [owner]
//	    require:                   # conditions on top of the relation
//	      delete: {mfa: true}
//
// Relations compose transitively, so `owner` grants `read` through
// editor → viewer without anybody writing that edge.

// Model is a parsed authorization model.
type Model struct {
	Types map[string]Type `yaml:"types" json:"types"`
	// Tests are run at parse time and are not optional.
	Tests []ModelTest `yaml:"tests" json:"tests,omitempty"`
}

// Type is one kind of object.
type Type struct {
	// Relations maps a relation to the relations that IMPLY it.
	//
	// `editor: [owner]` reads "an owner is also an editor". The arrow points
	// from the weaker to the stronger, which is the direction a reader checks:
	// to answer "is Alice an editor" you look at what makes somebody one.
	Relations map[string][]string `yaml:"relations" json:"relations"`
	// Permissions maps an action to the relations that grant it.
	Permissions map[string][]string `yaml:"permissions" json:"permissions"`
	// Require adds conditions an action must also satisfy.
	//
	// This is what a relation graph alone cannot express and what makes this
	// worth building inside an identity provider: "delete needs a second
	// factor" is a fact about the SESSION, and only whoever authenticated the
	// session knows it.
	Require map[string]Condition `yaml:"require" json:"require,omitempty"`
}

// Condition is an extra requirement on an action.
type Condition struct {
	// MFA requires that the session actually proved a second factor.
	MFA bool `yaml:"mfa" json:"mfa,omitempty"`
	// DeviceManaged and DeviceCompliant require device posture that was checked.
	DeviceManaged   bool `yaml:"device_managed" json:"device_managed,omitempty"`
	DeviceCompliant bool `yaml:"device_compliant" json:"device_compliant,omitempty"`
	// AnyGroup requires membership of at least one of these.
	AnyGroup []string `yaml:"any_group" json:"any_group,omitempty"`
	// MaxRisk refuses when the session's risk score is above this.
	MaxRisk int `yaml:"max_risk" json:"max_risk,omitempty"`
}

func (c Condition) isEmpty() bool {
	return !c.MFA && !c.DeviceManaged && !c.DeviceCompliant &&
		len(c.AnyGroup) == 0 && c.MaxRisk == 0
}

// ModelTest is an example the model must satisfy.
type ModelTest struct {
	Name      string   `yaml:"name" json:"name"`
	Subject   string   `yaml:"subject" json:"subject"`
	Action    string   `yaml:"action" json:"action"`
	Resource  string   `yaml:"resource" json:"resource"`
	Relations []string `yaml:"relations" json:"relations"`
	// Session facts the test asserts.
	MFA             bool     `yaml:"mfa" json:"mfa,omitempty"`
	Groups          []string `yaml:"groups" json:"groups,omitempty"`
	DeviceManaged   bool     `yaml:"device_managed" json:"device_managed,omitempty"`
	DeviceCompliant bool     `yaml:"device_compliant" json:"device_compliant,omitempty"`
	Risk            int      `yaml:"risk" json:"risk,omitempty"`

	Allow bool `yaml:"allow" json:"allow"`
}

// ParseModel reads a model and RUNS ITS TESTS.
func ParseModel(data []byte) (*Model, error) {
	var m Model
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// Unknown fields are an error. A misspelled `permisions` would otherwise be
	// silently dropped and the type would grant nothing, which reads at a glance
	// exactly like a type that grants everything it should.
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("the authorization model did not parse: %w", err)
	}
	if len(m.Types) == 0 {
		return nil, fmt.Errorf("the model defines no types")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if err := m.RunTests(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Model) validate() error {
	for name, t := range m.Types {
		if !plainName(name) {
			return fmt.Errorf("type %q: names must be lowercase letters, digits, "+
				"_ or -", name)
		}
		for rel, implies := range t.Relations {
			if !plainName(rel) {
				return fmt.Errorf("%s.%s: relation names must be lowercase letters, "+
					"digits, _ or -", name, rel)
			}
			for _, from := range implies {
				if _, ok := t.Relations[from]; !ok {
					return fmt.Errorf("%s.%s is implied by %q, which is not a "+
						"relation on %s", name, rel, from, name)
				}
			}
		}
		for act, grants := range t.Permissions {
			if !plainName(act) {
				return fmt.Errorf("%s: action %q must be lowercase letters, digits, "+
					"_ or -", name, act)
			}
			if len(grants) == 0 {
				// A permission granted by nothing is not a restriction, it is a
				// permission nobody has -- almost always a half-finished edit.
				return fmt.Errorf("%s.%s is granted by no relation, so nobody can "+
					"ever do it", name, act)
			}
			for _, rel := range grants {
				if _, ok := t.Relations[rel]; !ok {
					return fmt.Errorf("%s.%s is granted to %q, which is not a "+
						"relation on %s", name, act, rel, name)
				}
			}
		}
		for act := range t.Require {
			if _, ok := t.Permissions[act]; !ok {
				// A condition on an action nobody defined never runs, and reads
				// as a restriction that is in force.
				return fmt.Errorf("%s: `require` names %q, which is not a "+
					"permission on %s -- the condition would never be applied",
					name, act, name)
			}
		}
		// A relation cycle would make expansion loop. Detected here rather than
		// bounded at evaluation time, because a bound turns a broken model into
		// a slow one rather than a refused one.
		if cyc := t.cycle(); cyc != "" {
			return fmt.Errorf("%s: the relations form a cycle (%s)", name, cyc)
		}
	}
	return nil
}

// cycle returns a description of a relation cycle, or "".
func (t Type) cycle() string {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	colour := map[string]int{}
	var path []string
	var walk func(string) string
	walk = func(rel string) string {
		colour[rel] = grey
		path = append(path, rel)
		for _, next := range t.Relations[rel] {
			switch colour[next] {
			case grey:
				return strings.Join(append(path, next), " -> ")
			case white:
				if c := walk(next); c != "" {
					return c
				}
			}
		}
		path = path[:len(path)-1]
		colour[rel] = black
		return ""
	}
	names := make([]string, 0, len(t.Relations))
	for rel := range t.Relations {
		names = append(names, rel)
	}
	sort.Strings(names) // deterministic, so the reported cycle does not vary
	for _, rel := range names {
		if colour[rel] == white {
			if c := walk(rel); c != "" {
				return c
			}
		}
	}
	return ""
}

// Expand returns every relation that implies rel, including rel itself.
//
// The set an evaluator must look for: to answer "may an editor write", the
// stored relation might be `owner`, and owner implies editor.
func (t Type) Expand(rel string) []string {
	seen := map[string]bool{rel: true}
	queue := []string{rel}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, from := range t.Relations[cur] {
			if !seen[from] {
				seen[from] = true
				queue = append(queue, from)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// RelationsFor returns every relation that could grant this action.
func (m *Model) RelationsFor(objectType, action string) ([]string, bool) {
	t, ok := m.Types[objectType]
	if !ok {
		return nil, false
	}
	grants, ok := t.Permissions[action]
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	var out []string
	for _, rel := range grants {
		for _, r := range t.Expand(rel) {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	sort.Strings(out)
	return out, true
}

// ConditionFor returns the extra requirement on an action, if any.
func (m *Model) ConditionFor(objectType, action string) (Condition, bool) {
	t, ok := m.Types[objectType]
	if !ok {
		return Condition{}, false
	}
	c, ok := t.Require[action]
	if !ok || c.isEmpty() {
		return Condition{}, false
	}
	return c, true
}

// RunTests checks the model's own examples.
func (m *Model) RunTests() error {
	for i, tc := range m.Tests {
		name := tc.Name
		if name == "" {
			name = fmt.Sprintf("test %d", i+1)
		}
		objType, _, ok := ParseRef(tc.Resource)
		if !ok {
			return fmt.Errorf("%s: resource %q is not type:id", name, tc.Resource)
		}
		wanted, defined := m.RelationsFor(objType, tc.Action)
		if !defined {
			return fmt.Errorf("%s: %s has no permission %q", name, objType, tc.Action)
		}

		held := map[string]bool{}
		for _, r := range tc.Relations {
			held[r] = true
		}
		granted := false
		for _, r := range wanted {
			if held[r] {
				granted = true
				break
			}
		}
		if granted {
			if c, has := m.ConditionFor(objType, tc.Action); has {
				granted = c.SatisfiedBy(Facts{
					MFA: tc.MFA, Groups: tc.Groups, DeviceManaged: tc.DeviceManaged,
					DeviceCompliant: tc.DeviceCompliant, Risk: tc.Risk,
				})
			}
		}
		if granted != tc.Allow {
			return fmt.Errorf("%s: expected allow=%v, the model says %v "+
				"(relations held: %v; %s.%s is granted to any of %v)",
				name, tc.Allow, granted, tc.Relations, objType, tc.Action, wanted)
		}
	}
	return nil
}

// Facts are what the SESSION proved -- not what the caller claimed.
//
// This is the whole argument for putting the PDP in the identity provider. A
// standalone one has to believe the application about the subject's groups and
// factors, because it has no other source. We read them from the session we
// issued.
type Facts struct {
	MFA             bool
	Groups          []string
	DeviceManaged   bool
	DeviceCompliant bool
	Risk            int
	// FromSession records whether these came from a session we can see. When
	// false, a condition that depends on them is refused rather than guessed at.
	FromSession bool
}

// SatisfiedBy reports whether the facts meet the condition.
func (c Condition) SatisfiedBy(f Facts) bool {
	if c.MFA && !f.MFA {
		return false
	}
	if c.DeviceManaged && !f.DeviceManaged {
		return false
	}
	if c.DeviceCompliant && !f.DeviceCompliant {
		return false
	}
	if c.MaxRisk > 0 && f.Risk > c.MaxRisk {
		return false
	}
	if len(c.AnyGroup) > 0 {
		found := false
		for _, want := range c.AnyGroup {
			for _, have := range f.Groups {
				if have == want {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Unmet names the first unsatisfied requirement, as a NOUN PHRASE.
//
// "a second factor", not "the session did not prove a second factor", so the
// caller can put it after "requires ..." or "could not show ..." and have both
// read as English. A message assembled by prefixing "not " onto a sentence
// produces "but not the session proved a second factor", which is the kind of
// thing that survives review because nobody reads the error path.
func (c Condition) Unmet(f Facts) string {
	switch {
	case c.MFA && !f.MFA:
		return "a second factor"
	case c.DeviceManaged && !f.DeviceManaged:
		return "a managed device"
	case c.DeviceCompliant && !f.DeviceCompliant:
		return "a compliant device"
	case c.MaxRisk > 0 && f.Risk > c.MaxRisk:
		return fmt.Sprintf("session risk at most %d (it is %d)", c.MaxRisk, f.Risk)
	case len(c.AnyGroup) > 0:
		return "membership of " + strings.Join(c.AnyGroup, " or ")
	}
	return ""
}

func plainName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9', r == '_', r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
