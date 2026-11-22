package main

import (
	"slices"
	"testing"
)

// -algorithms takes the names an operator knows, or the COSE numbers the
// schema holds, in the order given, and refuses anything a policy may not
// offer rather than dropping it. Empty is the default, which the writer fills.
func TestTheAlgorithmsFlagReadsNamesAndNumbers(t *testing.T) {
	got, err := webauthnAlgorithms("EdDSA, es256,-257,ps256")
	if err != nil || !slices.Equal(got, []int{-8, -7, -257, -37}) {
		t.Errorf("EdDSA, es256,-257,ps256 read as %v (%v)", got, err)
	}
	if names := algorithmNames(got); names != "EdDSA,ES256,RS256,PS256" {
		t.Errorf("printed as %q", names)
	}
	if got, err := webauthnAlgorithms(""); err != nil || len(got) != 0 {
		t.Errorf("an empty -algorithms read as %v (%v), want the default", got, err)
	}
	for _, bad := range []string{"HS256", "RS1", "-65535", "ES256,none"} {
		if got, err := webauthnAlgorithms(bad); err == nil {
			t.Errorf("%q was accepted as %v", bad, got)
		}
	}
}
