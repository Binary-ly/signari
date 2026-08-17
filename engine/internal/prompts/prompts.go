// Package prompts asks a question during sign-in.
//
// Terms acceptance, a field the directory did not supply, a notice somebody
// must see. This is the part of a flow builder people actually use, and it is a
// YAML block rather than a graph: it diffs in a pull request, and it cannot be
// edited by accident in a console at two in the morning.
package prompts

import (
	"fmt"
	"strings"
)

// FieldType is what a field collects.
type FieldType string

const (
	// Checkbox is the terms-acceptance case. A required checkbox must be TICKED,
	// not merely present -- see Validate.
	Checkbox FieldType = "checkbox"
	Text     FieldType = "text"
	Email    FieldType = "email"
	Select   FieldType = "select"
	// Notice displays text and collects nothing. It exists so a prompt can say
	// something without pretending to ask.
	Notice FieldType = "notice"
)

// Field is one question.
type Field struct {
	Name     string    `json:"name" yaml:"name"`
	Type     FieldType `json:"type" yaml:"type"`
	Label    string    `json:"label" yaml:"label"`
	Help     string    `json:"help,omitempty" yaml:"help,omitempty"`
	Required bool      `json:"required,omitempty" yaml:"required,omitempty"`
	Options  []string  `json:"options,omitempty" yaml:"options,omitempty"`
}

// Prompt is a question asked between authentication and the session.
type Prompt struct {
	ID    string
	Slug  string
	Title string
	Body  string
	Once  bool

	Fields []Field
}

// Validate checks a prompt's definition.
func (p *Prompt) Validate() error {
	if p.Slug == "" {
		return fmt.Errorf("a prompt needs a slug")
	}
	if p.Title == "" {
		return fmt.Errorf("prompt %q needs a title: it is the heading somebody "+
			"reads before deciding whether to agree to something", p.Slug)
	}
	if len(p.Fields) == 0 {
		return fmt.Errorf("prompt %q has no fields", p.Slug)
	}
	seen := map[string]bool{}
	collects := false
	for i, f := range p.Fields {
		if f.Type == Notice {
			if f.Label == "" {
				return fmt.Errorf("prompt %q field %d: a notice needs a label, which "+
					"is the text it displays", p.Slug, i)
			}
			continue
		}
		collects = true
		switch {
		case f.Name == "":
			return fmt.Errorf("prompt %q field %d needs a name", p.Slug, i)
		case seen[f.Name]:
			return fmt.Errorf("prompt %q has two fields called %q", p.Slug, f.Name)
		case f.Label == "":
			return fmt.Errorf("prompt %q field %q needs a label", p.Slug, f.Name)
		}
		seen[f.Name] = true

		switch f.Type {
		case Checkbox, Text, Email:
		case Select:
			if len(f.Options) == 0 {
				return fmt.Errorf("prompt %q field %q is a select with no options",
					p.Slug, f.Name)
			}
		default:
			return fmt.Errorf("prompt %q field %q has type %q; use checkbox, text, "+
				"email, select or notice", p.Slug, f.Name, f.Type)
		}
	}
	if !collects {
		return fmt.Errorf("prompt %q contains only notices. A prompt that collects "+
			"nothing cannot be answered, so it would be shown on every sign-in "+
			"forever", p.Slug)
	}
	return nil
}

// Answers is what somebody submitted.
type Answers map[string]string

// Validate checks a submission against the prompt.
//
// # A required checkbox must be ticked
//
// This is the whole reason this function is not three lines. An unticked
// checkbox is ABSENT from a form submission — browsers do not send unchecked
// boxes — so a validator that only checks "is the field present and non-empty"
// treats "I did not agree" identically to "this field was not in the form", and
// the natural fix for the second breaks the first.
//
// Terms acceptance that can be skipped by not ticking the box is the failure
// this exists to prevent.
func (p *Prompt) ValidateAnswers(a Answers) (Answers, error) {
	out := Answers{}
	var missing []string

	for _, f := range p.Fields {
		if f.Type == Notice {
			continue
		}
		v, present := a[f.Name]
		v = strings.TrimSpace(v)

		if f.Type == Checkbox {
			ticked := present && v != "" && v != "0" && !strings.EqualFold(v, "false")
			if f.Required && !ticked {
				missing = append(missing, f.Label)
				continue
			}
			out[f.Name] = map[bool]string{true: "true", false: "false"}[ticked]
			continue
		}

		if v == "" {
			if f.Required {
				missing = append(missing, f.Label)
			}
			continue
		}
		if f.Type == Email && !strings.Contains(v, "@") {
			missing = append(missing, f.Label+" (not an email address)")
			continue
		}
		if f.Type == Select {
			ok := false
			for _, o := range f.Options {
				if o == v {
					ok = true
					break
				}
			}
			if !ok {
				// Not merely invalid: a value outside the options is a submission
				// that did not come from the rendered form.
				missing = append(missing, f.Label+" (not one of the options)")
				continue
			}
		}
		if len(v) > 500 {
			return nil, fmt.Errorf("%s is too long", f.Label)
		}
		out[f.Name] = v
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("please complete: %s", strings.Join(missing, ", "))
	}
	return out, nil
}
