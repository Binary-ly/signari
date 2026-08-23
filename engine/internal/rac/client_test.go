package rac_test

import (
	"strings"
	"testing"

	"signari.dev/engine/internal/pages"
	"signari.dev/engine/internal/rac"
)

// The viewer's markup and the script that drives it are in different packages
// now, so the contract between them needs holding somewhere.
//
// It used to be one file, and the comment there said why: "a rename in one is a
// blank screen from the other". Moving the markup into the page set is what made
// the viewer themeable, and `signari theme check` cannot know that #screen is
// load-bearing -- to the validator it is a div with no hidden input in it. This
// test is the part of that guarantee the validator cannot express.
//
// The failure being defended against is silent. Every one of these is missing
// from a page that renders, validates and looks completely normal; what happens
// is a black rectangle, which is the one symptom this viewer was written to
// avoid ever showing without an explanation.
func TestTheViewerMarkupHoldsItsContractWithTheScript(t *testing.T) {
	set, problems, err := pages.Load("")
	if err != nil {
		t.Fatalf("loading pages: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("unexpected refusals: %v", problems)
	}

	var sb strings.Builder
	if err := set.Execute(&sb, "racview", map[string]any{
		"Slug": "lab-1", "Name": "Windows lab", "Protocol": "RDP",
	}); err != nil {
		t.Fatalf("rendering the viewer: %v", err)
	}
	page := sb.String()

	for _, want := range rac.ViewContract {
		if !strings.Contains(page, want) {
			t.Errorf("the viewer's markup is missing %s, which rac.ClientJS reads. "+
				"The page still renders and still validates; what a person gets is a "+
				"blank screen", want)
		}
	}

	// The slug specifically, because losing the value is a different mistake
	// from losing the attribute and has the same symptom: a viewer that
	// connects to nothing.
	if !strings.Contains(page, `data-slug="lab-1"`) {
		t.Error("the viewer rendered without its slug, so the WebSocket has no " +
			"machine to open against")
	}

	// The script itself has to be asked for, or none of the above matters.
	if !strings.Contains(page, `src="/rac.js"`) {
		t.Error("the viewer does not load /rac.js, so nothing drives the display")
	}
}
