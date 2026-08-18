package authzen

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

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
	Policies map[string]Condition `yaml:"policies" json:"policies,omitempty"`
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

	// SubjectActive requires the account to be active in OUR directory. A
	// deactivated user whose relations were never cleaned up still holds them;
	// this is what stops the tuples outliving the account.
	SubjectActive bool `yaml:"subject_active" json:"subject_active,omitempty"`
	// EmailVerified requires a verified address.
	EmailVerified bool `yaml:"email_verified" json:"email_verified,omitempty"`

	// Time restricts the action to a window, by OUR clock. Not the caller's:
	// a time restriction an application can lie about is a comment.
	Time *TimeWindow `yaml:"time" json:"time,omitempty"`

	// Asserted holds requirements the CALLER supplies. Separated on purpose --
	// see the type comment.
	Asserted *Asserted `yaml:"asserted" json:"asserted,omitempty"`

	// Policies names entries from the model's `policies` block, combined by
	// Strategy. Everything else on this Condition still applies, and applies
	// AND-wise alongside the combined result -- an inline requirement is not
	// quietly outvoted by a consensus of named ones.
	Policies []string `yaml:"policies" json:"policies,omitempty"`
	// Strategy is how the named policies combine: unanimous (the default),
	// affirmative, or consensus.
	Strategy string `yaml:"strategy" json:"strategy,omitempty"`
}

const (
	// StrategyUnanimous requires every named policy. The default, because it is
	// the only one where adding a policy cannot make a request MORE permitted --
	// under affirmative and consensus, adding one can flip a denial to a grant.
	StrategyUnanimous = "unanimous"
	// StrategyAffirmative requires at least one.
	StrategyAffirmative = "affirmative"
	StrategyConsensus = "consensus"
)

// TimeWindow restricts an action to certain days and hours.
type TimeWindow struct {
	// Days as three-letter lowercase names. Empty means every day.
	Days []string `yaml:"days" json:"days,omitempty"`
	// From and To are "HH:MM", inclusive of From and exclusive of To.
	From string `yaml:"from" json:"from,omitempty"`
	To   string `yaml:"to" json:"to,omitempty"`
	// Zone is an IANA name. Required when From/To are set: "09:00" without a
	// zone means nine o'clock somewhere, which is not a security control.
	Zone string `yaml:"zone" json:"zone,omitempty"`
}

// Asserted are requirements met from what the caller sent.
//
// Worth exactly as much as your trust in the calling application. Useful when
// the caller is a gateway you run; not a control against the application itself.
type Asserted struct {
	// Resource matches on resource.properties from the request. Each key must
	// be present and its value must be one of the listed ones.
	Resource map[string][]string `yaml:"resource" json:"resource,omitempty"`
	Context map[string][]string `yaml:"context" json:"context,omitempty"`
	// Networks requires context.ip to fall in one of these CIDR blocks.
	Networks []string `yaml:"networks" json:"networks,omitempty"`
}

func (c Condition) isEmpty() bool {
	return !c.MFA && !c.DeviceManaged && !c.DeviceCompliant &&
		len(c.AnyGroup) == 0 && c.MaxRisk == 0 && !c.SubjectActive &&
		!c.EmailVerified && c.Time == nil && c.Asserted == nil &&
		len(c.Policies) == 0
}

// resolved is a Condition with its named policies attached.
//
// The named policies travel WITH the condition rather than being looked up
// during evaluation, so SatisfiedBy stays a pure function of a condition and
// some facts. A predicate that needs the whole model to answer is one that
// cannot be tested on its own, and every test in this package would have to
// build a model to ask a question about one rule.
type resolved struct {
	Condition
	named []Condition
}

// combine applies the decision strategy to the named policies.
func (r resolved) combine(f Facts) bool {
	if len(r.named) == 0 {
		return true
	}
	grants := 0
	for _, p := range r.named {
		if p.SatisfiedBy(f) {
			grants++
		}
	}
	switch r.Strategy {
	case StrategyAffirmative:
		return grants > 0
	case StrategyConsensus:
		return grants > len(r.named)-grants
	default:
		return grants == len(r.named)
	}
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
	Active          *bool    `yaml:"active" json:"active,omitempty"`
	EmailVerified   bool     `yaml:"email_verified" json:"email_verified,omitempty"`
	// At pins the clock, as RFC 3339. A time-window rule whose tests only pass
	// between nine and five is a test nobody can run in CI.
	At string `yaml:"at" json:"at,omitempty"`
	// ResourceProps and IP are what a caller would have asserted.
	ResourceProps map[string]any `yaml:"resource_properties" json:"resource_properties,omitempty"`
	IP            string         `yaml:"ip" json:"ip,omitempty"`

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
	// Named policies first: every rule below may reference them, and a rule
	// naming a policy that does not exist must be a parse failure rather than a
	// silently-skipped requirement. A typo in a policy name is otherwise a
	// permission quietly granted -- the rule still parses, the clause simply
	// never fires.
	for name, c := range m.Policies {
		if !plainName(name) {
			return fmt.Errorf("policy %q: names must be lowercase letters, digits, "+
				"_ or -", name)
		}
		if c.isEmpty() {
			return fmt.Errorf("policy %q requires nothing, so every rule naming it "+
				"is weaker than it looks", name)
		}
		if len(c.Policies) > 0 {
			return fmt.Errorf("policy %q names other policies; composition is one "+
				"level deep, so compose them at the rule instead", name)
		}
	}

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
		for act, c := range t.Require {
			if err := m.validateRule(name, act, c); err != nil {
				return err
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
		for act, cond := range t.Require {
			// Validated HERE rather than at evaluation time. A zone name that
			// does not exist, or a CIDR that does not parse, must stop the model
			// loading -- at evaluation time the only safe response is to refuse,
			// and a typo that silently denies everything is worse than one that
			// refuses to deploy.
			if err := cond.validate(name, act); err != nil {
				return err
			}
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

// validate checks a condition can actually be evaluated.
func (c Condition) validate(typeName, action string) error {
	where := typeName + "." + action
	if c.Time != nil {
		w := c.Time
		if (w.From != "" || w.To != "") && w.Zone == "" {
			return fmt.Errorf("%s: a time window needs a `zone` -- \"%s\" without "+
				"one means that hour somewhere, which is not a control", where, w.From+w.To)
		}
		if w.Zone != "" {
			if _, err := time.LoadLocation(w.Zone); err != nil {
				return fmt.Errorf("%s: %q is not an IANA time zone", where, w.Zone)
			}
		}
		for _, f := range []string{w.From, w.To} {
			if f != "" && !validHM(f) {
				return fmt.Errorf("%s: %q is not HH:MM", where, f)
			}
		}
		for _, d := range w.Days {
			if !validDay(d) {
				return fmt.Errorf("%s: %q is not a day (use mon, tue, wed, thu, "+
					"fri, sat, sun)", where, d)
			}
		}
		if len(w.Days) == 0 && w.From == "" && w.To == "" {
			return fmt.Errorf("%s: the time window restricts nothing", where)
		}
	}
	if c.Asserted != nil {
		for _, cidr := range c.Asserted.Networks {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("%s: %q is not a CIDR block", where, cidr)
			}
		}
		for key, vals := range c.Asserted.Resource {
			if len(vals) == 0 {
				return fmt.Errorf("%s: asserted.resource.%s allows no values, so "+
					"nothing can ever satisfy it", where, key)
			}
		}
		if len(c.Asserted.Resource) == 0 && len(c.Asserted.Networks) == 0 {
			return fmt.Errorf("%s: `asserted` requires nothing", where)
		}
	}
	return nil
}

func validHM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	return h < 24 && m < 60
}

func validDay(d string) bool {
	switch strings.ToLower(d) {
	case "mon", "tue", "wed", "thu", "fri", "sat", "sun":
		return true
	}
	return false
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
func (m *Model) ConditionFor(objectType, action string) (Rule, bool) {
	t, ok := m.Types[objectType]
	if !ok {
		return Rule{}, false
	}
	c, ok := t.Require[action]
	if !ok || c.isEmpty() {
		return Rule{}, false
	}
	r := Rule{resolved: resolved{Condition: c}}
	for _, name := range c.Policies {
		// Validation guarantees the name exists; a missing one here would be a
		// model that never parsed.
		r.named = append(r.named, m.Policies[name])
	}
	return r, true
}

// Rule is a condition together with the named policies it composes.
type Rule struct{ resolved }

// SatisfiedBy reports whether the facts meet the rule.
//
// The inline requirements and the combined named policies are ANDed. An inline
// requirement is not outvoted by a consensus of named ones: if a rule says
// `mfa: true` alongside three policies under `affirmative`, the second factor is
// still required. Anything else would make adding a policy able to REMOVE a
// requirement written beside it.
func (r Rule) SatisfiedBy(f Facts) bool {
	return r.Condition.SatisfiedBy(f) && r.combine(f)
}

// Unmet explains the first unsatisfied requirement.
func (r Rule) Unmet(f Facts) string {
	if why := r.Condition.Unmet(f); why != "" {
		return why
	}
	if r.combine(f) {
		return ""
	}
	// Name the policies that failed, not just the strategy: "consensus not
	// reached" tells an operator nothing about which rule to look at.
	var failed []string
	for i, p := range r.named {
		if !p.SatisfiedBy(f) {
			name := "policy"
			if i < len(r.Policies) {
				name = r.Policies[i]
			}
			failed = append(failed, name)
		}
	}
	strategy := r.Strategy
	if strategy == "" {
		strategy = StrategyUnanimous
	}
	return "the " + strategy + " policies to be satisfied (" +
		strings.Join(failed, ", ") + " " + wereOrWas(len(failed)) + " not)"
}

func wereOrWas(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// validateRule checks one action's requirement.
func (m *Model) validateRule(typeName, action string, c Condition) error {
	for _, ref := range c.Policies {
		if _, ok := m.Policies[ref]; !ok {
			return fmt.Errorf("%s.%s names the policy %q, which is not defined; a "+
				"rule referring to a policy that does not exist would evaluate as "+
				"though the requirement were not there", typeName, action, ref)
		}
	}
	switch c.Strategy {
	case "", StrategyUnanimous, StrategyAffirmative, StrategyConsensus:
	default:
		return fmt.Errorf("%s.%s has strategy %q; it must be one of %s, %s or %s",
			typeName, action, c.Strategy,
			StrategyUnanimous, StrategyAffirmative, StrategyConsensus)
	}
	if c.Strategy != "" && len(c.Policies) == 0 {
		return fmt.Errorf("%s.%s sets a decision strategy but names no policies, "+
			"so the strategy decides nothing", typeName, action)
	}
	return nil
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
				f := Facts{
					MFA: tc.MFA, Groups: tc.Groups, DeviceManaged: tc.DeviceManaged,
					DeviceCompliant: tc.DeviceCompliant, Risk: tc.Risk,
					EmailVerified: tc.EmailVerified,
					ResourceProps: tc.ResourceProps, IP: tc.IP,
				}
				// A test that does not say defaults to active, because that is
				// the ordinary case and making every case spell it out would
				// bury the one that matters.
				f.Active = tc.Active == nil || *tc.Active
				if tc.At != "" {
					at, err := time.Parse(time.RFC3339, tc.At)
					if err != nil {
						return fmt.Errorf("%s: `at` is not RFC 3339: %w", name, err)
					}
					f.Now = at
				} else if c.Time != nil {
					return fmt.Errorf("%s: %s.%s has a time window, so the test "+
						"must pin the clock with `at:` -- otherwise it passes or "+
						"fails depending on when CI runs",
						name, objType, tc.Action)
				}
				granted = c.SatisfiedBy(f)
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
	// Active and EmailVerified come from our directory.
	Active        bool
	EmailVerified bool
	// Now is the evaluation time. A field rather than a call to time.Now so a
	// model's own tests can pin it -- a time window whose tests only pass
	// between nine and five is a test nobody can run.
	Now time.Time
	// Context is the request's `context` object as the caller sent it.
	Context map[string]any
	// ResourceProps and IP are what the CALLER sent. Named so that reading the
	// evaluator makes obvious which side of the trust boundary each value is on.
	ResourceProps map[string]any
	IP            string
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
	if c.SubjectActive && !f.Active {
		return false
	}
	if c.EmailVerified && !f.EmailVerified {
		return false
	}
	if c.Time != nil && !c.Time.contains(f.Now) {
		return false
	}
	if c.Asserted != nil {
		for key, allowed := range c.Asserted.Resource {
			v, present := f.ResourceProps[key]
			if !present {
				// An absent property does NOT satisfy the requirement. Treating
				// "the caller did not mention it" as "it is fine" means a caller
				// bypasses the rule by omitting the field.
				return false
			}
			if !matchesAny(v, allowed) {
				return false
			}
		}
		for key, allowed := range c.Asserted.Context {
			v, present := f.Context[key]
			if !present {
				// Absent does not satisfy, for the same reason as above: a caller
				// that omits the field would otherwise bypass the rule by saying
				// less rather than by qualifying.
				return false
			}
			if !matchesAny(v, allowed) {
				return false
			}
		}
		if len(c.Asserted.Networks) > 0 && !inAnyNetwork(f.IP, c.Asserted.Networks) {
			return false
		}
	}
	return true
}

// contains reports whether t falls inside the window.
func (w *TimeWindow) contains(t time.Time) bool {
	if t.IsZero() {
		// No evaluation time supplied. Refused rather than assumed: a time
		// window satisfied by not knowing the time is not a window.
		return false
	}
	if w.Zone != "" {
		loc, err := time.LoadLocation(w.Zone)
		if err != nil {
			// Validated at parse time, so this is unreachable in practice.
			// Refusing is still the right answer if it ever is reached.
			return false
		}
		t = t.In(loc)
	}
	if len(w.Days) > 0 {
		today := strings.ToLower(t.Format("Mon"))
		ok := false
		for _, d := range w.Days {
			if strings.ToLower(d) == today {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if w.From == "" && w.To == "" {
		return true
	}
	mins := t.Hour()*60 + t.Minute()
	from, to := 0, 24*60
	if w.From != "" {
		from = parseHM(w.From)
	}
	if w.To != "" {
		to = parseHM(w.To)
	}
	if from <= to {
		return mins >= from && mins < to
	}
	// A window that wraps midnight -- 22:00 to 06:00 is one window, not none.
	return mins >= from || mins < to
}

func parseHM(s string) int {
	h, m := 0, 0
	if len(s) >= 5 && s[2] == ':' {
		h = int(s[0]-'0')*10 + int(s[1]-'0')
		m = int(s[3]-'0')*10 + int(s[4]-'0')
	}
	return h*60 + m
}

// matchesAny compares a JSON value against the allowed strings.
func matchesAny(v any, allowed []string) bool {
	var got string
	switch t := v.(type) {
	case string:
		got = t
	case bool:
		got = "false"
		if t {
			got = "true"
		}
	case float64:
		got = strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		// A list property matches when ANY of its entries is allowed.
		for _, e := range t {
			if matchesAny(e, allowed) {
				return true
			}
		}
		return false
	default:
		return false
	}
	for _, a := range allowed {
		if a == got {
			return true
		}
	}
	return false
}

func inAnyNetwork(ip string, cidrs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
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
	case len(c.AnyGroup) > 0 && !hasAny(f.Groups, c.AnyGroup):
		return "membership of " + strings.Join(c.AnyGroup, " or ")
	case c.SubjectActive && !f.Active:
		return "an active account"
	case c.EmailVerified && !f.EmailVerified:
		return "a verified email address"
	case c.Time != nil && !c.Time.contains(f.Now):
		return "the action to be taken inside its permitted hours"
	case c.Asserted != nil:
		for key, allowed := range c.Asserted.Resource {
			v, present := f.ResourceProps[key]
			if !present {
				return "the caller to state the resource's " + key
			}
			if !matchesAny(v, allowed) {
				return "the resource's " + key + " to be " +
					strings.Join(allowed, " or ")
			}
		}
		for key, allowed := range c.Asserted.Context {
			v, present := f.Context[key]
			if !present {
				return "the caller to state " + key + " in the request context"
			}
			if !matchesAny(v, allowed) {
				return key + " to be " + strings.Join(allowed, " or ")
			}
		}
		if len(c.Asserted.Networks) > 0 && !inAnyNetwork(f.IP, c.Asserted.Networks) {
			return "the request to come from a permitted network"
		}
	}
	return ""
}

func hasAny(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
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
