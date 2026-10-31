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
	"maps"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"signari.dev/engine/internal/authzen"
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
	// ApplicationRoles: the user must hold at least one of these roles in the
	// application being signed in to, a relation on application:<client>.
	ApplicationRoles []string `yaml:"application_roles"`
	// UserAttributes: the user must hold each of these, as the directory has
	// it: one of the values listed, or any value when none are. Only attributes
	// declared and not personal; storing a policy that names another is refused.
	UserAttributes map[string][]string `yaml:"user_attributes"`
	// MFA requires a multi-factor authentication context.
	MFA bool `yaml:"mfa"`
	// FromNetworks limits the request to these CIDR ranges.
	FromNetworks []string `yaml:"from_networks"`
	// FromCountries limits the request to these ISO 3166 codes, as the GeoIP
	// database places its address. Unplaced, it is not met, as FromNetworks is
	// not: "we do not know" must not read as "inside".
	FromCountries []string `yaml:"from_countries"`
	// NotFromCountries refuses these. An address nothing can place passes: this
	// is evidence against a request, and there is none.
	NotFromCountries []string `yaml:"not_from_countries"`
	// MaxRecentFailures refuses an address that has failed more sign-ins than
	// this lately, across every account: a reputation this deployment earned
	// for it, read from the budget the sign-in form already keeps.
	MaxRecentFailures int `yaml:"max_recent_failures"`
	// Time limits the request to a window, by this server's clock. It is checked
	// at a refresh too: access for office hours stops at the end of them.
	Time *authzen.TimeWindow `yaml:"time"`
	// NoImpossibleTravel refuses when the previous sign-in was somewhere this
	// person could not have travelled from in the time available.
	//
	// It is satisfied when the check did NOT run -- no position, too close
	// together, no history. A condition that failed whenever it could not be
	// evaluated would lock out every first-time user and every deployment
	// without a GeoIP database, which is how a risk signal becomes an outage.
	NoImpossibleTravel bool `yaml:"no_impossible_travel"`

	DeviceManaged bool `yaml:"device_managed"`

	// DeviceCompliant is stricter: managed AND reported healthy by whatever
	// attests to it. Separate from DeviceManaged because "we issued this laptop"
	// and "this laptop is patched and encrypted" are different claims, and
	// collapsing them lets a stolen managed device satisfy a rule meant to check
	// its state.
	DeviceCompliant bool `yaml:"device_compliant"`

	// PhishingResistant requires a factor that survives a convincing fake
	// sign-in page: a passkey or a security key, bound to this origin by the
	// browser.
	//
	// `mfa: true` is NOT this. A one-time code is multi-factor and is typed by
	// the person into whatever page asked for it, including the attacker's --
	// which is how every real-time phishing kit works. SMS is weaker still: SIM
	// swap needs no phishing page at all, only a convincing phone call to a
	// mobile operator.
	//
	// This condition exists because SMS exists. Offering a weak factor and then
	// having no way to say "not for this application" would mean the weakness
	// spreads to everything the strongest policy protects.
	PhishingResistant bool `yaml:"phishing_resistant"`

	// FactorsAnyOf names acceptable RFC 8176 amr values directly, for the cases
	// the two booleans above do not cover -- "an authenticator app or a security
	// key, but not a text message" is a real requirement and is not
	// phishing-resistant.
	FactorsAnyOf []string `yaml:"factors_any_of"`
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
	// Attributes are the user's attributes that are not personal, read when a
	// rule asks (File.AttributeNames).
	Attributes map[string]string `yaml:"attributes"`
	// ApplicationRoles are their roles in Client, read when a rule asks.
	ApplicationRoles []string `yaml:"application_roles"`
	MFA              bool     `yaml:"mfa"`
	// AMR is what the session ACTUALLY proved, in RFC 8176 terms. A test case
	// sets it directly, which is how factor conditions are covered by the
	// file's own tests without a phone.
	AMR []string `yaml:"amr"`
	IP  string   `yaml:"ip"`
	// Country is where the GeoIP database places IP, empty when it cannot, and
	// RecentFailures how many sign-ins that address has failed lately. Each is
	// set by the caller only when a rule asks, and by a test case directly.
	Country        string `yaml:"country"`
	RecentFailures int    `yaml:"recent_failures"`
	// At is the moment of the decision as RFC 3339, for a test case: a window
	// whose tests only pass between nine and five is a test nobody can run. A
	// real request leaves it empty and is decided by this server's clock.
	At string `yaml:"at"`
	// ImpossibleTravel is set by the caller from a risk check that RAN. A test
	// case can set it directly, which is how the condition is covered by the
	// file's own tests without a GeoIP database.
	ImpossibleTravel bool `yaml:"impossible_travel"`

	// DeviceManaged and DeviceCompliant are set by the caller from evidence that
	// was actually checked. A test case sets them directly, which is how these
	// conditions are covered by the file's own tests without an MDM.
	DeviceManaged   bool `yaml:"device_managed"`
	DeviceCompliant bool `yaml:"device_compliant"`

	// Refresh is a refresh-token grant: the application's server asking again
	// for a person who is not there. Who they are is checked again -- groups,
	// deny rules, the factors their session recorded -- because those can change
	// after the grant was issued, and a person removed from a group must stop
	// receiving tokens for what the group admitted them to. Where they are is
	// not: the network, device and travel conditions describe the browser at
	// sign-in, were checked then, and the request at hand comes from the
	// application's server, whose address and lack of a device certificate say
	// nothing about the person.
	Refresh bool `yaml:"refresh"`

	// Unobserved is a decision nothing here watched the person arrive for: a
	// jwt-bearer, pre-authorized code, token exchange, UMA or transaction-token
	// grant, made by a server or a wallet with no sign-in to this client in
	// front of it, and forward auth, whose request is the proxy's. Who they are
	// is checked as for a refresh. Where they are cannot be, and unlike a
	// refresh no sign-in to this client checked it earlier, so the network,
	// device and travel conditions are NOT met. Counting them as met made a
	// rule admitting a client only from the office decorative for every grant
	// that does not pass through a browser.
	Unobserved bool `yaml:"unobserved"`
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
		for _, code := range append(slices.Clone(r.Require.FromCountries), r.Require.NotFromCountries...) {
			if len(code) != 2 || strings.ToUpper(code) != code {
				return fmt.Errorf("policy %q: %q is not an ISO 3166 country code, two capital letters: "+
					"it would match nothing, and nobody would see why", r.Name, code)
			}
		}
		if r.Require.MaxRecentFailures < 0 {
			return fmt.Errorf("policy %q: max_recent_failures of %d", r.Name, r.Require.MaxRecentFailures)
		}
		if r.Require.Time != nil {
			if err := r.Require.Time.Validate("policy " + r.Name); err != nil {
				return err
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
	return len(c.Groups) == 0 && len(c.AnyGroup) == 0 && len(c.UserAttributes) == 0 &&
		len(c.ApplicationRoles) == 0 && !c.MFA &&
		!c.PhishingResistant && len(c.FactorsAnyOf) == 0 &&
		len(c.FromNetworks) == 0 && !c.NoImpossibleTravel &&
		!c.DeviceManaged && !c.DeviceCompliant &&
		len(c.FromCountries) == 0 && len(c.NotFromCountries) == 0 && c.MaxRecentFailures == 0 && c.Time == nil
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
	if len(c.ApplicationRoles) > 0 && !slices.ContainsFunc(c.ApplicationRoles, func(role string) bool {
		return contains(req.ApplicationRoles, role)
	}) {
		return false
	}
	for name, allowed := range c.UserAttributes {
		v, held := req.Attributes[name]
		if !held || (len(allowed) > 0 && !contains(allowed, v)) {
			return false
		}
	}
	if c.PhishingResistant && !hasPhishingResistantFactor(req.AMR) {
		return false
	}
	if len(c.FactorsAnyOf) > 0 && !hasAnyFactor(req.AMR, c.FactorsAnyOf) {
		return false
	}
	if c.MFA && !req.MFA {
		return false
	}
	if c.Time != nil {
		now := time.Now()
		if req.At != "" {
			var err error
			if now, err = time.Parse(time.RFC3339, req.At); err != nil {
				return false
			}
		}
		if !c.Time.Contains(now) {
			return false
		}
	}
	if req.Refresh {
		// The where-from conditions below were checked at sign-in; see Request.
		return true
	}
	if req.Unobserved {
		// Nothing checked them, now or at a sign-in; see Request. Travel too:
		// it is met when the check could not run because a person who IS here
		// may have no history, and a request with nobody here is not that.
		return !c.asksWhereFrom()
	}
	if c.DeviceManaged && !req.DeviceManaged {
		return false
	}
	// Compliance implies management: an unmanaged device cannot be reported
	// compliant by anything we would believe, so the stricter condition checks
	// both rather than trusting a compliance signal on its own.
	if c.DeviceCompliant && (!req.DeviceCompliant || !req.DeviceManaged) {
		return false
	}
	if c.NoImpossibleTravel && req.ImpossibleTravel {
		return false
	}
	if len(c.FromCountries) > 0 && !contains(c.FromCountries, req.Country) {
		return false
	}
	if contains(c.NotFromCountries, req.Country) {
		return false
	}
	if c.MaxRecentFailures > 0 && req.RecentFailures > c.MaxRecentFailures {
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

// asksWhereFrom reports whether c has a condition about where the person is or
// what they are holding, which only a request from the person can answer.
func (c Conditions) asksWhereFrom() bool {
	return c.DeviceManaged || c.DeviceCompliant || c.NoImpossibleTravel || len(c.FromNetworks) > 0 ||
		len(c.FromCountries) > 0 || len(c.NotFromCountries) > 0 || c.MaxRecentFailures > 0
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

// UsesCountries reports whether any rule asks where an address is, for the same
// reason, and for `signari doctor`: with no GeoIP database nothing can be placed,
// so from_countries refuses everybody.
func (f *File) UsesCountries() bool {
	for _, r := range f.Policies {
		if len(r.Require.FromCountries) > 0 || len(r.Require.NotFromCountries) > 0 {
			return true
		}
	}
	return false
}

// UsesApplicationRoles reports whether any rule asks about a role.
func (f *File) UsesApplicationRoles() bool {
	for _, r := range f.Policies {
		if len(r.Require.ApplicationRoles) > 0 {
			return true
		}
	}
	return false
}

// UsesRecentFailures reports whether any rule asks about an address's record.
func (f *File) UsesRecentFailures() bool {
	for _, r := range f.Policies {
		if r.Require.MaxRecentFailures > 0 {
			return true
		}
	}
	return false
}

// AttributeNames lists the attributes the rules read, sorted, so nothing is read
// for a policy that asks about none, and whoever stores the policy can check
// them against the organisation's declarations.
func (f *File) AttributeNames() []string {
	seen := map[string]bool{}
	for _, r := range f.Policies {
		for name := range r.Require.UserAttributes {
			seen[name] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// UsesDevicePosture reports whether any rule asks about the device.
//
// Same reason as UsesImpossibleTravel: establishing posture verifies a
// certificate chain or reads proxy headers, and doing that on every
// authorization for a deployment whose policy never mentions a device is work
// done for nothing.
func (f *File) UsesDevicePosture() bool {
	for _, r := range f.Policies {
		if r.Require.DeviceManaged || r.Require.DeviceCompliant {
			return true
		}
	}
	return false
}

// hasPhishingResistantFactor reports whether the session proved one.
//
// Only a hardware-backed credential counts: RFC 8176's "hwk", which this engine
// asserts for WebAuthn. Everything else in the list is a secret the person can
// be persuaded to read out.
//
// Note what is absent: "mfa". A provider asserting the generic value has told
// us that several factors were used and nothing about what they were, and
// treating an unspecified claim as the strongest one is how this condition
// would quietly stop meaning anything.
func hasPhishingResistantFactor(amr []string) bool {
	for _, m := range amr {
		if m == "hwk" {
			return true
		}
	}
	return false
}

// hasAnyFactor reports whether the session used at least one of the named
// factors.
func hasAnyFactor(amr, want []string) bool {
	for _, w := range want {
		for _, m := range amr {
			if m == w {
				return true
			}
		}
	}
	return false
}
