package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every capability an operator can configure must be reachable from a real path.
//
// # Why this test exists, and what it caught
//
// This codebase already refuses one shape of this bug in one place:
// `provider.Hook.Called()` declares which hooks a decision point actually
// consults, because a hook an operator can register that nothing calls is
// "a thing an operator can configure, which parses, validates, has tests, and
// governs nothing". `flow.Designation.Driven` exists for the same reason.
//
// Both are narrow. Neither noticed when six capabilities were built, tested,
// documented and wired to nothing:
//
//   - directory group sync — a planner with no sync command calling it
//   - SCIM group provisioning — a client with no reconciliation calling it
//   - LDAP bind-through — a verifier no authentication path used
//   - scope descriptions — never reached the consent screen
//   - undeclared-scope validation — never reached client registration
//   - claim mappers for the ID token and access token — two of three
//     destinations defined and never used, so a mapper configured for an ID
//     token silently produced nothing
//
// Every one had passing tests, because a test calls the function directly. That
// is precisely the gap: a unit test proves the mechanism works when called and
// says nothing about whether anything calls it.
//
// So this generalises the rule. Each entry names a function that must have a
// caller outside its own package's tests, and the reason it matters — because a
// list of names with no reasons is one somebody deletes an entry from.

type capability struct {
	// fn is the function that must be called.
	fn string
	// why explains what silently stops working if nothing calls it.
	why string
}

var mustBeReachable = []capability{
	{"MappedClaims", "an operator maps an attribute to a claim, the admin API " +
		"accepts it, the audit trail records it, and no token carries it"},
	{"SAMLAttributes", "a service provider's declared attribute release produces " +
		"assertions carrying none of it"},
	{"ApplyIDPAttributeMapping", "an upstream provider's claims never reach the " +
		"local attributes an operator mapped them to"},
	{"ConsultTokenProvider", "a registered token provider is never asked, so its " +
		"veto is not enforced"},
	{"AdvertisedScopes", "a declared scope never appears in discovery, so an " +
		"integrator cannot find it"},
	{"DescribeScopes", "the consent screen cannot say what a scope means, which " +
		"is the whole reason scopes are declarable"},
	{"UndeclaredScopes", "a typo in a client's registered scope is never caught, " +
		"and the mapper waiting on it silently never fires"},
	{"PermitsAuthenticator", "an organisation's approved-authenticator list is " +
		"not applied at registration"},
	{"BuildGroupPlan", "a configured directory group mapping never changes any " +
		"membership"},
	{"LoadGroupMappings", "the same, from the other end"},
	{"VerifyLDAP", "a migration configured to verify against the old directory " +
		"cannot authenticate anybody"},
	{"AddMembers", "group membership is provisioned to no target"},
	{"RemoveMembers", "somebody removed from a group keeps their access at every " +
		"provisioned target"},
	{"DeleteGroup", "a group provisioned to a target can never be removed from it, " +
		"so deprovisioning is one-way"},
}

// This test is NOT sufficient, and knowing why is the point.
//
// It checks that a function has a caller. It passed, green, while ten
// capabilities were unusable — because each one's loader genuinely was called,
// on the request path, on every request, against a table no operator could put a
// row in. A function being called is not the same as a capability being
// reachable, and the difference is exactly one table nobody can write to.
//
// `TestEveryTableTheEngineReadsCanBeWritten` and
// `TestEveryColumnAddedForBehaviourCanBeWritten` in writepath_test.go close that
// second gap. Both are needed: a write path with no reader is dead
// configuration, and a reader with no write path is a feature that cannot be
// switched on. Neither test sees the other's failure.

// callSite matches a call that is not the declaration.
func callSite(fn string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^\w.])(?:[\w]+\.)?` + regexp.QuoteMeta(fn) + `\s*\(`)
}

func TestEveryConfigurableCapabilityIsReachable(t *testing.T) {
	root := repoRoot(t)
	engine := filepath.Join(root, "engine")

	// Every non-test Go file, and where each capability is called from.
	callers := map[string][]string{}
	err := filepath.Walk(engine, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		body := string(src)
		rel, _ := filepath.Rel(root, path)

		for _, c := range mustBeReachable {
			// The declaration itself is not a call site.
			stripped := regexp.MustCompile(`func (?:\([^)]*\) )?`+regexp.QuoteMeta(c.fn)+`\(`).
				ReplaceAllString(body, "")
			if callSite(c.fn).MatchString(stripped) {
				callers[c.fn] = append(callers[c.fn], rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range mustBeReachable {
		if len(callers[c.fn]) == 0 {
			t.Errorf("%s has no caller outside its own tests.\n\n"+
				"What silently stops working: %s.\n\n"+
				"A unit test proves the mechanism works WHEN CALLED and says "+
				"nothing about whether anything calls it. That is how six "+
				"capabilities came to be built, tested, documented and reachable "+
				"by nobody.", c.fn, c.why)
		}
	}
}
