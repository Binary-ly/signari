package flow

import (
	"slices"
	"strings"
	"testing"
)

const pinFile = `
version: 1
flows:
  - name: pinned
    on: authentication
    stages:
%s
      - session
    tests:
      - name: walks
        given: {proved_by_federated: true}
        expect: [federated, session]
`

func parsePinned(t *testing.T, stages string) (*Flow, error) {
	t.Helper()
	f, err := Parse([]byte(strings.Replace(pinFile, "%s", stages, 1)))
	if err != nil {
		return nil, err
	}
	fl, _ := f.For(Authentication)
	return fl, nil
}

// A pin says which provider satisfies a federated stage (8.22). It restricts a flow only
// when every way through a provider names one, and it says the sign-in page has nothing
// to offer only when there is no other way in.
func TestAFlowPinsItsProviders(t *testing.T) {
	for name, tc := range map[string]struct {
		stages string
		pins   []string
		only   string
	}{
		"unpinned": {stages: "      - federated", pins: nil, only: ""},
		"one provider": {stages: "      - {stage: federated, provider: corp}",
			pins: []string{"corp"}, only: "corp"},
		"two providers": {stages: "      - one_of:\n          - {stage: federated, provider: corp, when: proved_by_federated}\n" +
			"          - {stage: federated, provider: other}", pins: []string{"corp", "other"}},
		"one branch names none": {stages: "      - one_of:\n          - {stage: federated, provider: corp, when: proved_by_federated}\n" +
			"          - {stage: federated}", pins: nil},
		"a password besides": {stages: "      - one_of:\n          - {stage: federated, provider: corp, when: proved_by_federated}\n" +
			"          - {stage: password}", pins: []string{"corp"}},
	} {
		t.Run(name, func(t *testing.T) {
			fl, err := parsePinned(t, tc.stages)
			if err != nil {
				t.Fatal(err)
			}
			if got := fl.PinnedProviders(); !slices.Equal(got, tc.pins) {
				t.Errorf("pinned %v", got)
			}
			if got := fl.OnlyProvider(); got != tc.only {
				t.Errorf("the only provider is %q", got)
			}
			for _, pin := range tc.pins {
				if !fl.AdmitsProvider(pin) {
					t.Errorf("%s is pinned and not admitted", pin)
				}
			}
			if want := tc.pins == nil; fl.AdmitsProvider("anyone") != want {
				t.Errorf("a provider nobody named: admitted %t", !want)
			}
		})
	}
}

func TestOnlyAFederatedStageTakesAPin(t *testing.T) {
	for _, stages := range []string{
		"      - {stage: password, provider: corp}",
		"      - one_of:\n          - {stage: password, provider: corp, when: proved_by_password}\n          - {stage: federated}",
	} {
		_, err := parsePinned(t, stages)
		if err == nil || !strings.Contains(err.Error(), "is for a federated stage") {
			t.Errorf("%s answered %v", stages, err)
		}
	}
}
