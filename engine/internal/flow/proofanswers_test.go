package flow

import (
	"slices"
	"testing"
)

// The sign-in page asks a flow on every render whether it admits somebody who
// arrived by an emailed code and by a passkey. A parsed flow answers what it
// would have worked out, and once asked answers again without working it out:
// working it out plans every state of the flow's conditions, and allocates doing
// so, where reading a kept answer allocates nothing (E.33).
func TestAParsedFlowWorksOutEachProofOnce(t *testing.T) {
	builtin, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*File{"the built-in flows": builtin}
	for _, stages := range []string{"[passkey, session]", "[password, mfa, session]", "[password, deny]",
		"[email_otp, session]", "[federated, prompt, session]"} {
		f, err := Parse([]byte(oneFlow(Authentication, stages)))
		if err != nil {
			t.Fatal(err)
		}
		files[stages] = f
	}
	for name, f := range files {
		for i := range f.Flows {
			fl := &f.Flows[i]
			for _, s := range proofStages {
				want := fl.admitsProof(s)
				for ask := 1; ask <= 2; ask++ {
					if got := fl.AdmitsProof(s); got != want {
						t.Errorf("%s, flow %q, asked %d times whether it admits %s: %v, want %v",
							name, fl.Name, ask, s, got, want)
					}
				}
				if n := testing.AllocsPerRun(20, func() { fl.AdmitsProof(s) }); n != 0 {
					t.Errorf("%s, flow %q, asked again whether it admits %s, allocated %v times: "+
						"it worked the answer out again", name, fl.Name, s, n)
				}
			}
		}
	}
}

// Every sign-in proof has a place for its answer; one without would be worked out
// on every render, correct and as slow as before.
func TestEverySignInProofHasAPlaceForItsAnswer(t *testing.T) {
	for s := range signInProofs {
		if !slices.Contains(proofStages[:], s) {
			t.Errorf("%s is a sign-in proof with no place in proofStages", s)
		}
	}
	if len(proofStages) != len(signInProofs) {
		t.Errorf("proofStages has %d stages and signInProofs %d", len(proofStages), len(signInProofs))
	}
}
