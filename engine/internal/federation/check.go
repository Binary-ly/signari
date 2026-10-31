package federation

import (
	"context"
	"fmt"
	"net/http"
)

// CheckResult is what probing a provider found: every step that passed, and the one
// that did not.
type CheckResult struct {
	OK bool
	// Step is where it stopped: discovery, endpoints or keys. Detail says why, or
	// says what could not be asked of a provider with nothing to ask.
	Step, Detail string
	// Keys is how many signing keys the provider publishes.
	Keys int
}

// Check asks a provider what a sign-in would rely on, so that a mistyped issuer or a
// key endpoint that has moved is found by the operator rather than by somebody's first
// sign-in (8.21). It reads only public documents and uses no credential, so it says
// nothing of whether the client id or secret are right: only a sign-in shows that.
func (c Config) Check(ctx context.Context, hc *http.Client) CheckResult {
	issuer, jwksURL := c.issuer(), c.jwksURL()
	if issuer == "" && jwksURL == "" {
		return CheckResult{OK: true, Detail: "this provider publishes no discovery document or keys, so there is " +
			"nothing to ask of it without signing in"}
	}
	if issuer != "" {
		d, err := Discover(ctx, hc, issuer)
		if err != nil {
			return CheckResult{Step: "discovery", Detail: err.Error()}
		}
		// Only what an operator wrote can disagree: a preset is what the provider
		// is known to publish, and a sign-in has been working from it.
		for _, e := range []struct{ name, set, published string }{
			{"authorization", c.AuthorizeOverride, d.AuthorizeURL},
			{"token", c.TokenOverride, d.TokenURL},
			{"keys", c.JWKSOverride, d.JWKSURL},
		} {
			if e.set != "" && e.set != e.published {
				return CheckResult{Step: "endpoints", Detail: fmt.Sprintf("the %s endpoint is set to %s and the "+
					"provider publishes %s", e.name, e.set, e.published)}
			}
		}
		if jwksURL == "" {
			jwksURL = d.JWKSURL
		}
	}
	keys, err := fetchJWKSFrom(ctx, hc, jwksURL)
	if err != nil {
		return CheckResult{Step: "keys", Detail: err.Error()}
	}
	if len(keys.Keys) == 0 {
		return CheckResult{Step: "keys", Detail: "the provider publishes no signing keys, so no token from it could be verified"}
	}
	return CheckResult{OK: true, Keys: len(keys.Keys)}
}
