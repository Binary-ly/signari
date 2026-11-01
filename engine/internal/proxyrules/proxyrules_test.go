package proxyrules

import (
	"errors"
	"strings"
	"testing"
)

func TestAPathIsComparedInOneForm(t *testing.T) {
	for uri, want := range map[string]string{
		"/":                  "/",
		"/static/app.js":     "/static/app.js",
		"/static/app.js?a=1": "/static/app.js",
		"/static/app.js#top": "/static/app.js",
		"/a%20b":             "/a b",
		"/%61dmin":           "/admin",
		"/café":              "/café",
		"/admin/":            "/admin/",
	} {
		if got, err := Canonical(uri); err != nil || got != want {
			t.Errorf("%q read as %q, %v", uri, got, err)
		}
	}
}

// Every one of these is a path an application may read as something the rule was not
// written for, and the shape of the published ways round a path rule.
func TestAPathWithoutOneMeaningIsNotCompared(t *testing.T) {
	for _, uri := range []string{
		"",
		"static",
		"/static/../admin",
		"/static/./admin",
		"/static/..",
		"/static/%2e%2e/admin",
		"/static/%2E%2e/admin",
		"//admin",
		"/static//admin",
		"/static%2fadmin",
		"/static%2Fadmin",
		"/static%5cadmin",
		"/static\\admin",
		"/static;/admin",
		"/static/%3b/admin",
		"/static/%252e%252e/admin",
		"/static/%25",
		"/static/%zz",
		"/a\x00b",
		"/a%00b",
		"/a%0ab",
		"/" + strings.Repeat("a/", 100),
	} {
		if got, err := Canonical(uri); !errors.Is(err, ErrUncheckable) {
			t.Errorf("%q was read as %q", uri, got)
		}
	}
}

func TestARulePatternReadsAsWritten(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          bool
	}{
		{"/health", "/health", true},
		{"/health", "/health/", false},
		{"/health", "/healthz", false},
		{"/static/*", "/static/app.js", true},
		{"/static/*", "/static/", true},
		{"/static/*", "/static/js/app.js", false},
		{"/static/*.js", "/static/app.js", true},
		{"/static/*.js", "/static/app.css", false},
		{"/static/a*b*c", "/static/axbyc", true},
		{"/static/a*b*c", "/static/axbx", false},
		{"/static/a*a", "/static/a", false},
		{"/static/**", "/static", true},
		{"/static/**", "/static/", true},
		{"/static/**", "/static/js/app.js", true},
		{"/static/**", "/staticfiles/app.js", false},
		{"/**/secret", "/secret", true},
		{"/**/secret", "/a/b/secret", true},
		{"/**/secret", "/a/b/secret/x", false},
		{"/a/**/b/**/c", "/a/x/b/y/z/c", true},
		{"/a/**/b/**/c", "/a/x/c", false},
		{"/**", "/", true},
		{"/**", "/anything/at/all", true},
	} {
		if got := matchPath(c.pattern, c.path); got != c.want {
			t.Errorf("%q against %q: %v", c.pattern, c.path, got)
		}
	}
}

// Many ** against a long path costs what one does, or a rule would be a way to make
// every request here expensive.
func TestManyPatternsDoNotCostMore(t *testing.T) {
	pattern := "/" + strings.Repeat("**/", 30) + "x"
	path := "/" + strings.Repeat("a/", 60) + "y"
	if matchPath(pattern, path) {
		t.Error("it matched")
	}
}

func TestTheFirstRuleThatMatchesDecides(t *testing.T) {
	rules := []Rule{
		{Effect: EffectAuth, Path: "/static/private/**"},
		{Effect: EffectPublic, Path: "/static/**", Methods: []string{"GET", "HEAD"}},
		{Effect: EffectDeny, Path: "/static/**"},
	}
	for _, c := range []struct {
		method, path, want string
	}{
		{"GET", "/static/app.js", EffectPublic},
		{"HEAD", "/static/app.js", EffectPublic},
		{"POST", "/static/app.js", EffectDeny},
		{"GET", "/static/private/key", EffectAuth},
		{"GET", "/elsewhere", ""},
	} {
		got := ""
		if r := Match(rules, c.method, c.path); r != nil {
			got = r.Effect
		}
		if got != c.want {
			t.Errorf("%s %s: %q", c.method, c.path, got)
		}
	}
}

// With no method from the proxy the request could be any. A rule letting some through
// does not apply, and one refusing some does.
func TestARequestOfNoKnownMethodIsHeldToTheStricterReading(t *testing.T) {
	rules := []Rule{
		{Effect: EffectPublic, Path: "/open", Methods: []string{"GET"}},
		{Effect: EffectAuth, Path: "/kept", Methods: []string{"GET"}},
		{Effect: EffectDeny, Path: "/shut", Methods: []string{"DELETE"}},
		{Effect: EffectPublic, Path: "/any"},
	}
	if r := Match(rules, "", "/open"); r != nil {
		t.Errorf("/open answered %+v", r)
	}
	if r := Match(rules, "", "/kept"); r != nil {
		t.Errorf("/kept answered %+v", r)
	}
	if r := Match(rules, "", "/shut"); r == nil || r.Effect != EffectDeny {
		t.Errorf("/shut answered %+v", r)
	}
	if r := Match(rules, "", "/any"); r == nil || r.Effect != EffectPublic {
		t.Errorf("a rule naming no method answered %+v", r)
	}
}

func TestRulesAreReadFromLines(t *testing.T) {
	rules, err := ParseLines(`
# what the proxy may let through
public GET,HEAD /static/**

deny * /internal/**
auth:console * /console/**
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("%d rules", len(rules))
	}
	if r := rules[0]; r.Effect != EffectPublic || r.Path != "/static/**" || len(r.Methods) != 2 {
		t.Errorf("the first is %+v", r)
	}
	if r := rules[1]; r.Effect != EffectDeny || len(r.Methods) != 0 {
		t.Errorf("the second is %+v", r)
	}
	if r := rules[2]; r.Effect != EffectAuth || r.Name != "console" {
		t.Errorf("the third is %+v", r)
	}
	if rules, err := ParseLines("\n# nothing\n"); err != nil || rules == nil || len(rules) != 0 {
		t.Errorf("no rules read as %v, %v", rules, err)
	}
	if _, err := ParseLines("public /static/**"); err == nil {
		t.Error("two fields were read")
	}
}

func TestARuleThatCouldNotMeanWhatItSaysIsRefused(t *testing.T) {
	for name, r := range map[string]Rule{
		"an unknown effect":        {Effect: "allow", Path: "/x"},
		"no path":                  {Effect: EffectDeny},
		"not from the root":        {Effect: EffectDeny, Path: "static/**"},
		"a dot segment":            {Effect: EffectPublic, Path: "/a/../b"},
		"a query":                  {Effect: EffectPublic, Path: "/a?b=c"},
		"encoded":                  {Effect: EffectPublic, Path: "/a%20b"},
		"a class":                  {Effect: EffectPublic, Path: "/[ab]"},
		"a ** inside a segment":    {Effect: EffectPublic, Path: "/a**b"},
		"an unknown method":        {Effect: EffectPublic, Path: "/a", Methods: []string{"get"}},
		"a policy nobody meets":    {Effect: EffectPublic, Path: "/a", Name: "n"},
		"a policy of a refusal":    {Effect: EffectDeny, Path: "/a", Name: "n"},
		"a name that breaks a key": {Effect: EffectAuth, Path: "/a", Name: "a#b"},
	} {
		if err := Check([]Rule{r}); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	if err := Check(make([]Rule, MaxRules+1)); err == nil {
		t.Error("too many were taken")
	}
	if err := Check([]Rule{{Effect: EffectAuth, Path: "/a/*.js", Name: "n", Methods: []string{"GET"}}}); err != nil {
		t.Errorf("a good rule: %v", err)
	}
}
