// Package proxyrules says what forward authentication does with one path of a
// protected application, where the host alone does not say enough: a health check
// that must answer anybody, a console that no outside address should reach, an
// admin section held to more than the rest (8.26).
//
// # The rule is only as good as the path it is compared with
//
// A rule is checked here and the path is served somewhere else, by an application
// that decides for itself what a path means. Where the two differ, a rule is a way
// past the check: `/static/../admin` matches `/static/**` here and is `/admin` there.
// So a path is compared only in a form with one meaning, and one that has no such
// form is not compared at all: Canonical says so, and a host with rules refuses it.
package proxyrules

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// The effects a rule can have.
const (
	// EffectPublic needs no sign-in, and tells the application of nobody.
	EffectPublic = "public"
	// EffectDeny is refused to everybody, signed in or not.
	EffectDeny = "deny"
	// EffectAuth is what a host does with any path no rule names. Written out to take
	// a path back from a wider rule after it, or to hold it to a policy of its own.
	EffectAuth = "auth"
)

const (
	// MaxRules is the most a host may hold: they are compared on every request.
	MaxRules = 64
	maxPath  = 512
	// maxSegments bounds the comparison. A path longer than this has no rule to match.
	maxSegments = 64
)

// Rule is one line of a host's rules. The first that matches decides.
type Rule struct {
	Effect string `json:"effect" yaml:"effect"`
	// Path is matched whole. * stands for anything within one segment, and ** alone
	// in a segment for any number of them, none included.
	Path string `json:"path" yaml:"path"`
	// Methods are the ones it applies to, none for all.
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	// Name gives a path an access policy of its own, keyed proxy:<host>#<name>, on
	// top of the host's. Only on auth: nobody is signed in on the others to hold to it.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

var knownMethods = []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}

// Check refuses rules that could not mean what they say.
func Check(rules []Rule) error {
	if len(rules) > MaxRules {
		return fmt.Errorf("a host holds at most %d rules, not %d", MaxRules, len(rules))
	}
	for i, r := range rules {
		if r.Effect != EffectPublic && r.Effect != EffectDeny && r.Effect != EffectAuth {
			return fmt.Errorf("rule %d: the effect is %s, %s or %s, not %q", i+1, EffectPublic, EffectDeny, EffectAuth, r.Effect)
		}
		if r.Name != "" && r.Effect != EffectAuth {
			return fmt.Errorf("rule %d: only an auth rule can have a policy: nobody is signed in on a %s path to hold to it", i+1, r.Effect)
		}
		if strings.ContainsAny(r.Name, "# \t") {
			return fmt.Errorf("rule %d: %q cannot name a policy", i+1, r.Name)
		}
		if len(r.Path) > maxPath || !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("rule %d: a path starts with / and runs to %d characters: %q", i+1, maxPath, r.Path)
		}
		if strings.ContainsAny(r.Path, "?#[]{}\\;%") {
			return fmt.Errorf("rule %d: %q has a character a path is not compared on; * and ** are the only patterns", i+1, r.Path)
		}
		for _, segment := range strings.Split(r.Path[1:], "/") {
			if segment == "." || segment == ".." {
				return fmt.Errorf("rule %d: %q has a dot segment, which no path that reaches a rule has", i+1, r.Path)
			}
			if strings.Contains(segment, "**") && segment != "**" {
				return fmt.Errorf("rule %d: ** stands alone in a segment: %q", i+1, r.Path)
			}
		}
		for _, m := range r.Methods {
			if !slices.Contains(knownMethods, m) {
				return fmt.Errorf("rule %d: %q is not a method", i+1, m)
			}
		}
	}
	return nil
}

// ParseLines reads rules as `signari proxy rules` takes them, one a line:
//
//	public GET,HEAD /static/**
//	deny * /internal/**
//	auth:console * /console/**
//
// A blank line and a line starting with # are skipped.
func ParseLines(text string) ([]Rule, error) {
	rules := []Rule{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: a rule is an effect, its methods or *, and a path: %q", i+1, line)
		}
		r := Rule{Path: fields[2]}
		r.Effect, r.Name, _ = strings.Cut(fields[0], ":")
		if fields[1] != "*" {
			r.Methods = strings.Split(fields[1], ",")
		}
		rules = append(rules, r)
	}
	if err := Check(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// ErrUncheckable is a path with no one meaning.
var ErrUncheckable = errors.New("this path cannot be held to the application's rules")

// Canonical is a request's path in the one form it is compared in: the query gone,
// decoded once. Anything an application could read as a different path is refused:
// a dot segment, an empty one, a backslash, a parameter, an encoded slash, and
// anything still encoded once decoded.
func Canonical(uri string) (string, error) {
	path, _, _ := strings.Cut(uri, "?")
	path, _, _ = strings.Cut(path, "#")
	if !strings.HasPrefix(path, "/") || len(path) > maxPath*3 {
		return "", ErrUncheckable
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", ErrUncheckable
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || strings.ContainsAny(decoded, "\\;%") {
		return "", ErrUncheckable
	}
	for _, c := range decoded {
		if c < 0x20 || c == 0x7f {
			return "", ErrUncheckable
		}
	}
	segments := strings.Split(decoded[1:], "/")
	if len(segments) > maxSegments {
		return "", ErrUncheckable
	}
	for i, s := range segments {
		// One empty segment at the end is a trailing slash, which means what it says.
		if s == "." || s == ".." || (s == "" && i != len(segments)-1) {
			return "", ErrUncheckable
		}
	}
	return decoded, nil
}

// Match is the first rule a request meets, nil for none. path is Canonical's.
//
// method is empty when the proxy did not say, and the request the proxy is asking about
// could then be any. So a rule naming methods is applied only where that errs towards
// refusing: a deny is taken to cover it, and one that would let it through is not.
func Match(rules []Rule, method, path string) *Rule {
	for i := range rules {
		r := &rules[i]
		if !matchPath(r.Path, path) {
			continue
		}
		if len(r.Methods) == 0 || slices.Contains(r.Methods, method) || (method == "" && r.Effect == EffectDeny) {
			return r
		}
	}
	return nil
}

// matchPath compares a pattern with a path, segment by segment, by which pairs of
// places can be reached, so two ** cost what one does.
func matchPath(pattern, path string) bool {
	want, have := strings.Split(pattern[1:], "/"), strings.Split(path[1:], "/")
	reach := make([]bool, len(have)+1)
	reach[0] = true
	for _, p := range want {
		next := make([]bool, len(have)+1)
		for i, ok := range reach {
			if !ok {
				continue
			}
			if p == "**" {
				for j := i; j <= len(have); j++ {
					next[j] = true
				}
			} else if i < len(have) && matchSegment(p, have[i]) {
				next[i+1] = true
			}
		}
		reach = next
	}
	return reach[len(have)]
}

// matchSegment compares one segment, * standing for any run of characters.
func matchSegment(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		at := strings.Index(s, part)
		if at < 0 {
			return false
		}
		s = s[at+len(part):]
	}
	return strings.HasSuffix(s, last)
}
