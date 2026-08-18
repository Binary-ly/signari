package httpapi

import (
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
)

// Discovery and the token endpoint must agree about which grants exist.
//
// This repository's stated rule is that nothing enters a metadata document
// before it works, and until now that rule was held by a comment. A comment does
// not survive the next person adding a grant to one list and not the other, and
// both directions of the disagreement are real failures:
//
//   - Advertised but not dispatched is the lie the rule exists to prevent. A
//     client reads discovery, builds a request, and gets `unsupported_grant_type`
//     from the endpoint that just told it otherwise.
//   - Dispatched but not advertised is a working grant nobody can find, which is
//     the shape the OID4VCI grant had while it was being built.
//
// The advertised list is the one in the metadata document; the dispatched list
// is whatever oauth.ValidateGrantType lets through, since that is the gate every
// token request passes.
func TestEveryAdvertisedGrantIsDispatched(t *testing.T) {
	md := buildHonestyMetadata(t)

	for _, gt := range md.GrantTypesSupported {
		if err := oauth.ValidateGrantType(gt); err != nil {
			t.Errorf("discovery advertises %q and the token endpoint refuses it: %s",
				gt, err.Description)
		}
	}
}

// The converse. Every grant the token endpoint accepts must be discoverable.
func TestEveryDispatchedGrantIsAdvertised(t *testing.T) {
	// Written out rather than derived, because deriving it from the same switch
	// the other test reads would make both tests one test.
	dispatched := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		oauth.GrantTypeDeviceCode,
		oauth.GrantTypeTokenExchange,
		oauth.GrantTypePreAuthorizedCode,
	}
	md := buildHonestyMetadata(t)

	advertised := map[string]bool{}
	for _, gt := range md.GrantTypesSupported {
		advertised[gt] = true
	}
	for _, gt := range dispatched {
		if !advertised[gt] {
			t.Errorf("the token endpoint accepts %q and discovery does not mention "+
				"it, so no client can discover a grant that works", gt)
		}
	}

	// And the switch itself has not grown a case this list forgot.
	for _, gt := range []string{"password", "implicit", "made_up_grant"} {
		if err := oauth.ValidateGrantType(gt); err == nil {
			t.Errorf("%q is accepted by the token endpoint and appears in neither "+
				"list; this test is no longer complete", gt)
		}
	}
}

func buildHonestyMetadata(t *testing.T) *oidc.Metadata {
	t.Helper()
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	md, err := oidc.Build(oidc.Config{Issuer: "https://honesty.test", Keys: set})
	if err != nil {
		t.Fatal(err)
	}
	return md
}
