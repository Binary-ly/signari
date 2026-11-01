package flow

import (
	"slices"
	"testing"
)

const factorFile = `version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - {stage: external_factor, factor: push}
      - session
    tests:
      - name: asked
        given: {}
        expect: [password, external_factor, session]
`

func TestAFlowNamesTheServiceAStageAsks(t *testing.T) {
	f := mustParse(t, factorFile)
	fl, _ := f.For(Authentication)
	if got := fl.Factors(); !slices.Equal(got, []string{"push"}) {
		t.Errorf("Factors() = %v", got)
	}
	c := fl.Cursor()
	for {
		stage, ok := c.Next(nil)
		if !ok {
			t.Fatal("the walk never reached the stage")
		}
		if stage == StageExternalFactor {
			if c.Factor() != "push" {
				t.Errorf("the cursor names %q", c.Factor())
			}
			return
		}
	}
}

func TestACursorNamesTheBranchItTook(t *testing.T) {
	f := mustParse(t, `version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - one_of:
          - {stage: external_factor, factor: strong, when: risk_elevated}
          - {stage: external_factor, factor: plain}
      - session
    tests:
      - name: quiet
        given: {}
        expect: [password, external_factor, session]
      - name: loud
        given: {risk_elevated: true}
        expect: [password, external_factor, session]
`)
	fl, _ := f.For(Authentication)
	if got := fl.Factors(); !slices.Equal(got, []string{"strong", "plain"}) {
		t.Errorf("Factors() = %v", got)
	}
	for held, want := range map[bool]string{true: "strong", false: "plain"} {
		c := fl.Cursor()
		for {
			stage, ok := c.Next(evalOf{"risk_elevated": held})
			if !ok {
				t.Fatalf("risk %v: the walk never reached the stage", held)
			}
			if stage == StageExternalFactor {
				break
			}
		}
		if c.Factor() != want {
			t.Errorf("risk %v asks %q, and %q was chosen", held, c.Factor(), want)
		}
	}
}

type evalOf map[string]bool

func (e evalOf) Holds(name string) bool { return e[name] }

func TestAnExternalFactorMustBeAskedOfSomebodyProved(t *testing.T) {
	for name, tc := range map[string]struct {
		stages string
		want   string
	}{
		"naming no service": {"      - password\n      - external_factor\n      - session", "`factor`"},
		"on another stage":  {"      - {stage: password, factor: push}\n      - session", "`factor` is for"},
		"on another branch": {"      - one_of:\n          - {stage: password, factor: push, when: proved_by_password}\n" +
			"          - {stage: passkey}\n      - session", "`factor` is for"},
		"before anything is proved": {"      - {stage: external_factor, factor: push}\n      - password\n      - session",
			"nothing before it has proved"},
		"instead of a proof": {"      - identify\n      - {stage: external_factor, factor: push}\n      - session",
			"nothing before it has proved"},
	} {
		t.Run(name, func(t *testing.T) {
			parseErr(t, "version: 1\nflows:\n  - name: sign-in\n    on: authentication\n    stages:\n"+tc.stages+
				"\n    tests:\n      - name: any\n        given: {}\n        expect: [session]\n", tc.want)
		})
	}
}

func TestOnlyASignInRunsAnExternalFactor(t *testing.T) {
	parseErr(t, `version: 1
flows:
  - name: reset
    on: recovery
    stages:
      - email_otp
      - {stage: external_factor, factor: push}
      - password_change
      - done
    tests:
      - name: any
        given: {}
        expect: [email_otp, external_factor, password_change, done]
`, "does not run")
}

func TestAnExternalFactorDoesNotCountAsAProof(t *testing.T) {
	if provingStages[StageExternalFactor] {
		t.Error("an external factor counts as what proves a subject, and the walk reaches it only after one")
	}
}
