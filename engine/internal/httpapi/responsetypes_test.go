package httpapi

import (
	"testing"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
)

// Every response type discovery advertises is one the authorization endpoint
// serves, for a client permitted it. The hybrid type was served and not
// advertised (2.39); the opposite drift, advertising one that is refused, is
// what this catches from here on.
func TestEveryAdvertisedResponseTypeIsServed(t *testing.T) {
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	md, err := oidc.Build(oidc.Config{Issuer: "https://idp.example.test", Keys: set})
	if err != nil {
		t.Fatal(err)
	}
	c := &clients.Client{
		ClientID: "app", Enabled: true, Type: "public", RequirePKCE: true, AllowHybrid: true,
		GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid"},
		ResponseTypes: []string{"code", "code id_token"},
		RedirectURIs:  []string{"https://app.example.test/cb"},
	}
	for _, rt := range md.ResponseTypesSupported {
		req := oauth.AuthzRequest{
			ClientID: "app", RedirectURI: "https://app.example.test/cb", ResponseType: rt,
			Scope: "openid", State: "s", Nonce: "n",
			CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
		}
		if aerr := oauth.ValidateAuthz(req, c, nil); aerr != nil {
			t.Errorf("discovery advertises response_type %q and the authorization endpoint refuses it: %v",
				rt, aerr)
		}
	}
}
