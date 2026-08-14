package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Discovered is the subset of an OIDC discovery document we act on.
type Discovered struct {
	Issuer       string `json:"issuer"`
	AuthorizeURL string `json:"authorization_endpoint"`
	TokenURL     string `json:"token_endpoint"`
	UserinfoURL  string `json:"userinfo_endpoint"`
	JWKSURL      string `json:"jwks_uri"`
}

// Discover fetches a provider's OIDC metadata.
//
// Run at REGISTRATION rather than at each login. Two reasons, and the second is
// the important one:
//
//   - A fetch on every sign-in is a hard dependency on the provider's metadata
//     endpoint being up, in the request path, for something that changes yearly.
//   - A typo in the issuer fails HERE, in front of the operator who typed it,
//     with a message about the issuer -- instead of at the first user's first
//     sign-in, as an error about a missing endpoint.
func Discover(ctx context.Context, hc *http.Client, issuer string) (*Discovered, error) {
	if !strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://") {
		return nil, fmt.Errorf("the issuer must be an absolute URL, got %q", issuer)
	}
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d; is that the right issuer?", u, resp.StatusCode)
	}

	var d Discovered
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("the discovery document did not parse: %w", err)
	}

	// The issuer in the document must match the one asked for. A document
	// claiming a different issuer either belongs to somebody else or is being
	// served from a host that is not the issuer -- and every later check that
	// compares an id_token's `iss` would then be comparing against the wrong
	// value, silently.
	if strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return nil, fmt.Errorf("the discovery document at %s declares issuer %q, not %q",
			u, d.Issuer, issuer)
	}
	if d.AuthorizeURL == "" || d.TokenURL == "" {
		return nil, fmt.Errorf("the discovery document names no authorization or token endpoint")
	}
	if d.JWKSURL == "" {
		// Without a JWKS there is no way to verify an id_token signature, and an
		// unverified id_token is a claim anybody can make.
		return nil, fmt.Errorf("the discovery document names no jwks_uri, so id_token " +
			"signatures could not be verified")
	}
	return &d, nil
}
