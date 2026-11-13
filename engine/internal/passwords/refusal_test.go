package passwords

import (
	"context"
	"errors"
	"os"
	"regexp"
	"testing"
)

// Every pattern Estimate can name has a message key, read from the source rather than
// listed by hand: a pattern added without one would reach a page as English inside an
// Arabic sentence.
func TestEveryStrengthPatternHasAMessage(t *testing.T) {
	src, err := os.ReadFile("strength.go")
	if err != nil {
		t.Fatal(err)
	}
	named := regexp.MustCompile(`consider\([^\n]*, "([^"]+)"\)|\{longest\w+, \d+, \d+, "([^"]+)"\}`)
	found := 0
	for _, m := range named.FindAllStringSubmatch(string(src), -1) {
		name := m[1] + m[2]
		found++
		if _, ok := PatternKeys[name]; !ok {
			t.Errorf("Estimate can name the pattern %q, and PatternKeys has no message for it", name)
		}
	}
	if found < 7 {
		t.Fatalf("only %d patterns were read from strength.go; the expression no longer matches it", found)
	}
}

// Each refusal carries its key and the values its message names, and says the same
// English it always did, which the Admin API and the command line still show.
func TestARefusalCarriesItsMessage(t *testing.T) {
	ctx := context.Background()
	p := Policy{MinLength: 12, MinScore: 3}
	for _, c := range []struct {
		candidate, identity, key, english string
		data                              map[string]any
	}{
		{candidate: "short", key: "password.refused.short", data: map[string]any{"Min": 12},
			english: "passwords must be at least 12 characters"},
		{candidate: "            ", key: "password.refused.blank", english: "only whitespace"},
		{candidate: "aaaaaaaaaaaaaaa", key: "password.refused.repeated", english: "one character repeated"},
		{candidate: "zz-adalovelace-zz", identity: "adalovelace@example.test", key: "password.refused.identity",
			english: "contains your username"},
		{candidate: "qwertyuiopasdf", key: "password.refused.weak",
			data: map[string]any{"Pattern": "password.pattern.keyboard"}, english: "guessed quickly"},
	} {
		_, err := p.Check(ctx, c.candidate, c.identity, nil, nil)
		var refused *Refusal
		if !errors.As(err, &refused) {
			t.Errorf("%q: got %v, not a refusal", c.candidate, err)
			continue
		}
		if refused.Key != c.key {
			t.Errorf("%q: key %q, want %q", c.candidate, refused.Key, c.key)
		}
		for k, v := range c.data {
			if refused.Data[k] != v {
				t.Errorf("%q: %s = %v, want %v", c.candidate, k, refused.Data[k], v)
			}
		}
		if !regexp.MustCompile(regexp.QuoteMeta(c.english)).MatchString(err.Error()) {
			t.Errorf("%q: the English became %q", c.candidate, err.Error())
		}
	}
}
