package prompts

import (
	"strings"
	"testing"
)

func termsPrompt() *Prompt {
	return &Prompt{
		Slug: "terms", Title: "Terms of service", Once: true,
		Fields: []Field{
			{Type: Notice, Label: "Please read the terms before continuing."},
			{Name: "accept", Type: Checkbox, Label: "I accept the terms", Required: true},
		},
	}
}

// TestAnUntickedBoxIsNotAgreement is the reason this package exists.
//
// Browsers do not send unchecked checkboxes. A validator that asks "is the
// field present and non-empty" therefore cannot tell "I did not agree" from
// "this field was not in the form" — and the obvious fix for the second silently
// accepts the first.
//
// Terms acceptance that can be skipped by not ticking the box is a compliance
// failure that looks exactly like a working feature.
func TestAnUntickedBoxIsNotAgreement(t *testing.T) {
	p := termsPrompt()

	// Absent entirely, which is what a browser sends for an unticked box.
	if _, err := p.ValidateAnswers(Answers{}); err == nil {
		t.Fatal("an unticked required checkbox was accepted as agreement")
	}
	// Present but false, which is what a scripted submission might send.
	for _, v := range []string{"", "0", "false", "False"} {
		if _, err := p.ValidateAnswers(Answers{"accept": v}); err == nil {
			t.Errorf("accept=%q was accepted as agreement", v)
		}
	}
	// Actually ticked.
	out, err := p.ValidateAnswers(Answers{"accept": "on"})
	if err != nil {
		t.Fatalf("a ticked box was refused: %v", err)
	}
	if out["accept"] != "true" {
		t.Errorf("a ticked box recorded as %q, want \"true\"", out["accept"])
	}
}

func TestRequiredFieldsAreNamedInTheError(t *testing.T) {
	p := &Prompt{Slug: "p", Title: "T", Fields: []Field{
		{Name: "dept", Type: Text, Label: "Department", Required: true},
		{Name: "phone", Type: Text, Label: "Phone", Required: true},
	}}
	_, err := p.ValidateAnswers(Answers{"dept": "  "})
	if err == nil {
		t.Fatal("whitespace was accepted for a required field")
	}
	// Both, so somebody does not fix one and resubmit to find the other.
	for _, want := range []string{"Department", "Phone"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q: %v", want, err)
		}
	}
}

// A select value outside the options did not come from the rendered form.
func TestSelectValuesMustBeOffered(t *testing.T) {
	p := &Prompt{Slug: "p", Title: "T", Fields: []Field{
		{Name: "site", Type: Select, Label: "Site", Required: true,
			Options: []string{"london", "berlin"}},
	}}
	if _, err := p.ValidateAnswers(Answers{"site": "elsewhere"}); err == nil {
		t.Fatal("a value outside the offered options was accepted")
	}
	if _, err := p.ValidateAnswers(Answers{"site": "berlin"}); err != nil {
		t.Errorf("an offered option was refused: %v", err)
	}
}

func TestOptionalFieldsMayBeBlank(t *testing.T) {
	p := &Prompt{Slug: "p", Title: "T", Fields: []Field{
		{Name: "nickname", Type: Text, Label: "Nickname"},
		{Name: "news", Type: Checkbox, Label: "Send me news"},
	}}
	out, err := p.ValidateAnswers(Answers{})
	if err != nil {
		t.Fatalf("optional fields should not be required: %v", err)
	}
	// An unticked optional box is recorded as false rather than omitted: "they
	// declined" and "they were never asked" are different facts.
	if out["news"] != "false" {
		t.Errorf("an unticked optional box recorded as %q, want \"false\"", out["news"])
	}
}

func TestDefinitionsAreValidated(t *testing.T) {
	cases := []struct {
		name, want string
		p          Prompt
	}{
		{"no title", "title", Prompt{Slug: "a", Fields: []Field{{Name: "x", Type: Text, Label: "X"}}}},
		{"no fields", "no fields", Prompt{Slug: "a", Title: "T"}},
		{"duplicate names", "two fields called", Prompt{Slug: "a", Title: "T", Fields: []Field{
			{Name: "x", Type: Text, Label: "X"}, {Name: "x", Type: Text, Label: "Y"}}}},
		{"select with no options", "no options", Prompt{Slug: "a", Title: "T", Fields: []Field{
			{Name: "x", Type: Select, Label: "X"}}}},
		{"unknown type", "use checkbox", Prompt{Slug: "a", Title: "T", Fields: []Field{
			{Name: "x", Type: "slider", Label: "X"}}}},
		// A prompt that collects nothing can never be answered, so it would be
		// shown on every sign-in forever.
		{"notices only", "collects nothing", Prompt{Slug: "a", Title: "T", Fields: []Field{
			{Type: Notice, Label: "Hello"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q: %v", tc.want, err)
			}
		})
	}
}

func TestAValidDefinitionPasses(t *testing.T) {
	if err := termsPrompt().Validate(); err != nil {
		t.Fatalf("a reasonable terms prompt was refused: %v", err)
	}
}
