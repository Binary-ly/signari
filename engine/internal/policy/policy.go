// Package policy evaluates access rules written as a file.
//
// # Why a file rather than a builder
//
// The usual shape for this is a graph editor: drag stages onto a canvas, wire
// them together, save. It demonstrates well and it has three properties that
// hurt in production -- you cannot diff it, you cannot review it in a pull
// request, and you cannot test it before it is live.
//
// A file fixes all three for free. The interesting part is the fourth:
//
// # A policy that fails its own tests will not load
//
// Every policy file carries its own test cases, and they are run when the file
// is loaded -- not only by `signari policy test`, but by the engine, at startup
// and on every reload. A file whose stated intent disagrees with its behaviour
// is refused.
//
// That inverts the usual failure. Ordinarily an access rule is written, deployed,
// and discovered to be wrong when somebody is locked out or -- far worse -- when
// somebody who should have been locked out was not. Here the author writes down
// what they meant, and the file does not deploy unless the rules agree with it.
package policy

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is a parsed policy document.
type File struct {
	Version int `yaml:"version"`
	// Default is what happens to a request NO rule matched: "allow" (the
	// default) or "deny".
	//
	// It is a file-level setting rather than a catch-all rule, and that is a
	// correction. The first design expected default-deny to be written as a
	// trailing rule with no `when` -- but every matching rule applies here, so
	// such a rule also matched requests the earlier rules had just approved, and
	// denied them. Default-deny was inexpressible, and the file's own tests are
	// what caught it.
	//
	// Keeping it at the file level preserves the invariant that a RULE can only
	// ever restrict, never grant. Where the boundary sits is one word at the top
	// of the file, which is also where a reviewer looks first.
	Default  string     `yaml:"default"`
	Policies []Rule     `yaml:"policies"`
	Tests    []TestCase `yaml:"tests"`
}

// Rule is one access rule.
type Rule struct {
	Name string `yaml:"name"`
	// When selects the requests this rule applies to. An empty When matches
	// everything, which is how a catch-all is written.
	When Match `yaml:"when"`
	// Require lists conditions that must ALL hold. A rule adds restrictions; it
	// never grants access that was not otherwise available.
	Require Conditions `yaml:"require"`
	// Deny refuses outright, whatever else holds.
	Deny bool `yaml:"deny"`
	// Message is shown to the person who was refused. Written for them, not for
	// a log: somebody who cannot sign in needs to know what to do next.
	Message string `yaml:"message"`
}

// Match selects requests.
type Match struct {
	Client  string   `yaml:"client"`
	Clients []string `yaml:"clients"`
	Scope   string   `yaml:"scope"`
}

// Conditions are what a rule demands.
type Conditions struct {
	// Groups: the user must be in ALL of these.
	Groups []string `yaml:"groups"`
	// AnyGroup: the user must be in at least one.
	AnyGroup []string `yaml:"any_group"`
	// MFA requires a multi-factor authentication context.
	MFA bool `yaml:"mfa"`
	// FromNetworks limits the request to these CIDR ranges.
	FromNetworks []string `yaml:"from_networks"`
	// NoImpossibleTravel refuses when the previous sign-in was somewhere this
	// person could not have travelled from in the time available.
	//
	// It is satisfied when the check did NOT run -- no position, too close
	// together, no history. A condition that failed whenever it could not be
	// evaluated would lock out every first-time user and every deployment
	// without a GeoIP database, which is how a risk signal becomes an outage.
	NoImpossibleTravel bool `yaml:"no_impossible_travel"`
}

// TestCase is an assertion the file makes about itself.
type TestCase struct {
	Name   string  `yaml:"name"`
	Given  Request `yaml:"given"`
	Expect string  `yaml:"expect"` // "allow" or "deny"
}

// Request is what a policy decision is made about.
type Request struct {
	Client string   `yaml:"client"`
	Scope  string   `yaml:"scope"`
	Groups []string `yaml:"groups"`
	MFA    bool     `yaml:"mfa"`
	IP     string   `yaml:"ip"`
	// ImpossibleTravel is set by the caller from a risk check that RAN. A test
	// case can set it directly, which is how the condition is covered by the
	// file's own tests without a GeoIP database.
	ImpossibleTravel bool `yaml:"impossible_travel"`
}

// Decision is the result.
type Decision struct {
	Allowed bool
	// Rule names the rule that refused, so an operator can find it in the file.
	Rule    string
	Message string
}

// Parse reads a policy file and RUNS ITS TESTS.
//
// The tests are not optional and not a separate step: a file that fails them
// does not parse. Anything else makes them documentation, and documentation
// drifts.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// Unknown fields are an ERROR, not a warning. A misspelled `any_group` would
	// otherwise be silently ignored, and the rule would quietly demand nothing --
	// a policy that appears to restrict and does not.
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the policy file did not parse: %w", err)
	}

	switch f.Default {
	case "", "allow":
		f.Default = "allow"
	case "deny":
	default:
		return nil, fmt.Errorf("default is %q; it must be \"allow\" or \"deny\"", f.Default)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("policy version %d is not supported (expected 1)", f.Version)
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
	for i, r := range f.Policies {
		if r.Name == "" {
			return fmt.Errorf("policy %d has no name; a rule that refuses somebody must "+
				"be findable in this file by the name in the error", i+1)
		}
		if seen[r.Name] {
			return fmt.Errorf("two policies are named %q", r.Name)
		}
		seen[r.Name] = true

		if r.Deny && !r.Require.isEmpty() {
			return fmt.Errorf("policy %q both denies and requires; a rule that denies "+
				"outright cannot also state conditions, and which was meant is unclear",
				r.Name)
		}
		for _, cidr := range r.Require.FromNetworks {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("policy %q: %q is not a network in CIDR form", r.Name, cidr)
			}
		}
	}
	if len(f.Tests) == 0 {
		// Refused, not warned about. A policy with no tests is a policy whose
		// author has not written down what they meant, and this whole design is
		// built on comparing the two.
		return fmt.Errorf("this policy file has no tests. Add cases under `tests:` " +
			"stating what should be allowed and denied -- they are run every time the " +
			"file is loaded, so a rule that stops doing what you meant cannot deploy")
	}
	return nil
}

func (c Conditions) isEmpty() bool {
	return len(c.Groups) == 0 && len(c.AnyGroup) == 0 && !c.MFA &&
		len(c.FromNetworks) == 0 && !c.NoImpossibleTravel
}

// RunTests evaluates every case in the file.
func (f *File) RunTests() error {
	var failures []string
	for _, tc := range f.Tests {
		if tc.Expect != "allow" && tc.Expect != "deny" {
			return fmt.Errorf("test %q expects %q; it must be \"allow\" or \"deny\"",
				tc.Name, tc.Expect)
		}
		d := f.Evaluate(tc.Given)
		want := tc.Expect == "allow"
		if d.Allowed != want {
			got := "deny"
			if d.Allowed {
				got = "allow"
			}
			detail := ""
			if d.Rule != "" {
				detail = fmt.Sprintf(" (by rule %q)", d.Rule)
			}
			failures = append(failures,
				fmt.Sprintf("  %s: expected %s, got %s%s", tc.Name, tc.Expect, got, detail))
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return fmt.Errorf("this policy does not do what its tests say:\n%s",
			strings.Join(failures, "\n"))
	}
	return nil
}

// Evaluate decides one request.
//
// # Rules restrict; they never grant
//
// A request with no matching rule is ALLOWED unless the file says
// `default: deny`. Allow is the default default: adding a policy file to a
// running deployment must not lock everybody out of everything.
//
// Where that boundary sits is one word at the top of the file, so a reviewer
// sees it immediately -- rather than it being an invisible property of the
// engine, or an emergent consequence of rule ordering.
//
// The first rule that refuses wins, and its name and message are returned so the
// person refused can be told which rule and why.
func (f *File) Evaluate(req Request) Decision {
	matched := false
	for _, r := range f.Policies {
		if !r.When.matches(req) {
			continue
		}
		matched = true
		if r.Deny {
			return Decision{Allowed: false, Rule: r.Name, Message: message(r)}
		}
		if !r.Require.satisfiedBy(req) {
			return Decision{Allowed: false, Rule: r.Name, Message: message(r)}
		}
	}
	if !matched && f.Default == "deny" {
		return Decision{
			Allowed: false,
			Rule:    "(default)",
			Message: "This application is not available.",
		}
	}
	return Decision{Allowed: true}
}

func message(r Rule) string {
	if r.Message != "" {
		return r.Message
	}
	return "Access to this application is restricted by policy."
}

func (m Match) matches(req Request) bool {
	if m.Client != "" && m.Client != req.Client {
		return false
	}
	if len(m.Clients) > 0 {
		found := false
		for _, c := range m.Clients {
			if c == req.Client {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if m.Scope != "" && !hasScope(req.Scope, m.Scope) {
		return false
	}
	return true
}

func (c Conditions) satisfiedBy(req Request) bool {
	for _, g := range c.Groups {
		if !contains(req.Groups, g) {
			return false
		}
	}
	if len(c.AnyGroup) > 0 {
		any := false
		for _, g := range c.AnyGroup {
			if contains(req.Groups, g) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	if c.MFA && !req.MFA {
		return false
	}
	if c.NoImpossibleTravel && req.ImpossibleTravel {
		return false
	}
	if len(c.FromNetworks) > 0 {
		// An absent or unparseable address fails the check. Treating "we do not
		// know where this came from" as "inside the office network" is how a
		// network restriction becomes decorative behind a proxy that strips the
		// address.
		ip := net.ParseIP(req.IP)
		if ip == nil {
			return false
		}
		inside := false
		for _, cidr := range c.FromNetworks {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil && n.Contains(ip) {
				inside = true
				break
			}
		}
		if !inside {
			return false
		}
	}
	return true
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// Summary describes a loaded policy, for the startup log.
func (f *File) Summary() string {
	return fmt.Sprintf("%d rule(s), %d test(s), all passing", len(f.Policies), len(f.Tests))
}

// UsesImpossibleTravel reports whether any rule asks about travel.
//
// Checked before doing the work: resolving a position and querying history on
// every authorization would be effort spent for nothing in the deployments --
// most of them -- whose policy never mentions it.
func (f *File) UsesImpossibleTravel() bool {
	for _, r := range f.Policies {
		if r.Require.NoImpossibleTravel {
			return true
		}
	}
	return false
}
