package federation

import (
	"fmt"
	"sort"
	"strings"
)

// Provider presets.
//
// These exist because each of the big three lies to you in a different way
// about email verification, and a generic OIDC client that treats them alike
// will believe at least one of them when it should not.
//
// Every entry below is set from the provider's own documentation, checked
// rather than recalled.

// Kind identifies a preset.
type Kind string

const (
	KindOIDC      Kind = "oidc"
	KindGoogle    Kind = "google"
	KindGitHub    Kind = "github"
	KindMicrosoft Kind = "microsoft"
	KindApple     Kind = "apple"
	KindGitLab    Kind = "gitlab"
	KindDiscord   Kind = "discord"
	KindTwitch    Kind = "twitch"
	KindLinkedIn  Kind = "linkedin"
	// KindSAML is an upstream SAML identity provider. It shares the linking and
	// account-matching rules with the OAuth kinds and nothing else: there is no
	// preset, because a SAML upstream's endpoints and certificate come from its
	// metadata rather than from a list this package could know.
	KindSAML Kind = "saml"
)

// Preset is the endpoint configuration and email-verification policy for a kind.
type Preset struct {
	AuthorizeURL string
	TokenURL     string
	UserinfoURL  string
	JWKSURL      string
	Issuer       string
	Scopes       []string

	// OIDC reports whether the provider returns an id_token we can verify.
	// GitHub does not -- it is plain OAuth 2.0 with a user API bolted on.
	OIDC bool

	// TrustsEmailVerification records whether the EmailVerified value THIS
	// PACKAGE PRODUCES for the provider can be believed.
	//
	// The distinction matters and it caused a bug. The obvious reading is "does
	// the provider's raw response tell the truth", and by that reading GitHub is
	// false -- its /user endpoint returns unconfirmed addresses. But we do not
	// use that endpoint's flag: we query /user/emails and only report verified
	// when GitHub says the address is confirmed. So the value we produce IS
	// trustworthy, and marking the provider untrusted made sign-up impossible
	// for a provider we had gone to the trouble of verifying properly.
	//
	// It is therefore a statement about our own handling, one line below the
	// code that does the handling.
	TrustsEmailVerification bool

	// EmailNeedsSeparateCheck records that the trustworthiness above is EARNED by
	// extra work -- a second request or an additional claim -- rather than by the
	// response being reliable on its own. Documentation for the reader; changing
	// the handling means revisiting the flag above.
	EmailNeedsSeparateCheck bool

	// EmailsURL is a second endpoint some providers need for verification.
	// GitHub's verified flag lives here rather than on the user object.
	EmailsURL string

	// SecretIsJWT records that the client secret is not a string the provider
	// hands over but a JWT this side signs and must re-mint before it expires.
	//
	// Apple is the only one, and it is the single most common way an Apple
	// integration breaks: the secret is valid for at most six months, so every
	// deployment that pasted one in fails twice a year with an invalid_client
	// nobody expected.
	SecretIsJWT bool

	// Note explains the policy to whoever reads the configuration. It is
	// surfaced by the CLI, because an operator choosing a provider should not
	// have to read this file to learn that GitHub needs a second request.
	Note string
}

// presets, keyed by kind.
var presets = map[Kind]Preset{
	KindGoogle: {
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserinfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		JWKSURL:      "https://www.googleapis.com/oauth2/v3/certs",
		Issuer:       "https://accounts.google.com",
		Scopes:       []string{"openid", "email", "profile"},
		OIDC:         true,
		// Google is the one that behaves. `email_verified` in the id_token means
		// Google verified it, and a Workspace account's domain is verified by
		// the tenant. Believed as returned.
		TrustsEmailVerification: true,
		Note:                    "email_verified in the id_token is authoritative.",
	},

	KindGitHub: {
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserinfoURL:  "https://api.github.com/user",
		EmailsURL:    "https://api.github.com/user/emails",
		Scopes:       []string{"read:user", "user:email"},
		// NOT OpenID Connect. There is no id_token, so identity comes from the
		// user API and nothing is signed -- which is fine, because the token was
		// obtained over TLS directly from GitHub, but it does mean none of the
		// OIDC verification machinery applies.
		OIDC: false,
		// /user returns a `email` field that is whatever the user set as public,
		// INCLUDING addresses they never confirmed, and it can be null. The
		// verified flag lives on a different endpoint entirely.
		// True because of what githubIdentity does, not because /user is honest.
		TrustsEmailVerification: true,
		EmailNeedsSeparateCheck: true,
		Note: "GET /user returns an unconfirmed address, so /user/emails is queried " +
			"instead and only a confirmed address counts as verified.",
	},

	// Every endpoint below was read from the provider's own
	// /.well-known/openid-configuration rather than from documentation or
	// memory. A preset whose endpoints are wrong is worse than no preset: it
	// looks configured and fails at the point a user is trying to sign in.

	KindApple: {
		AuthorizeURL: "https://appleid.apple.com/auth/authorize",
		TokenURL:     "https://appleid.apple.com/auth/token",
		JWKSURL:      "https://appleid.apple.com/auth/keys",
		Issuer:       "https://appleid.apple.com",
		Scopes:       []string{"openid", "email", "name"},
		OIDC:         true,
		// There is NO userinfo endpoint. Apple's discovery document does not
		// publish one, and identity comes from the id_token alone -- so a client
		// that expects to enrich the profile with a second request gets nothing.
		UserinfoURL: "",
		// Apple verifies every address it returns, including the private relay
		// ones. `email_verified` may arrive as the STRING "true" rather than a
		// boolean, which is handled where the claim is read.
		TrustsEmailVerification: true,
		// The client secret is a signed JWT that expires. See SecretIsJWT.
		SecretIsJWT: true,
		Note: "Apple has no userinfo endpoint -- identity comes from the id_token. " +
			"The client secret is a signed JWT valid for at most six months; " +
			"`signari idp apple-secret` mints and rotates it. Names are returned " +
			"only on the FIRST authorization, in the form post, never again.",
	},

	KindGitLab: {
		AuthorizeURL: "https://gitlab.com/oauth/authorize",
		TokenURL:     "https://gitlab.com/oauth/token",
		UserinfoURL:  "https://gitlab.com/oauth/userinfo",
		JWKSURL:      "https://gitlab.com/oauth/discovery/keys",
		Issuer:       "https://gitlab.com",
		Scopes:       []string{"openid", "email", "profile"},
		OIDC:         true,
		// GitLab returns email_verified and only issues confirmed addresses to
		// the userinfo endpoint.
		TrustsEmailVerification: true,
		Note: "For a self-managed GitLab, use the generic `oidc` kind with your " +
			"own issuer -- these endpoints are gitlab.com's.",
	},

	KindDiscord: {
		AuthorizeURL: "https://discord.com/api/oauth2/authorize",
		TokenURL:     "https://discord.com/api/oauth2/token",
		UserinfoURL:  "https://discord.com/api/oauth2/userinfo",
		JWKSURL:      "https://discord.com/api/oauth2/keys",
		Issuer:       "https://discord.com",
		Scopes:       []string{"openid", "email", "identify"},
		OIDC:         true,
		// Discord reports whether an address was confirmed, and an unconfirmed
		// account cannot use most of the platform -- but the flag is the only
		// thing standing between a claimed address and a verified one.
		TrustsEmailVerification: true,
		Note: "Discord accounts are consumer accounts with no domain ownership " +
			"behind them. Fine for a community; think twice before allowing " +
			"sign-up into anything an employee would use.",
	},

	KindTwitch: {
		AuthorizeURL: "https://id.twitch.tv/oauth2/authorize",
		TokenURL:     "https://id.twitch.tv/oauth2/token",
		UserinfoURL:  "https://id.twitch.tv/oauth2/userinfo",
		JWKSURL:      "https://id.twitch.tv/oauth2/keys",
		Issuer:       "https://id.twitch.tv/oauth2",
		// Twitch requires the email claim to be requested explicitly through a
		// claims parameter; the plain `email` scope is not enough.
		Scopes:                  []string{"openid", "user:read:email"},
		OIDC:                    true,
		TrustsEmailVerification: true,
		EmailNeedsSeparateCheck: true,
		Note: "Twitch needs the user:read:email scope AND a claims parameter " +
			"before it returns an address at all.",
	},

	KindLinkedIn: {
		AuthorizeURL: "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
		UserinfoURL:  "https://api.linkedin.com/v2/userinfo",
		JWKSURL:      "https://www.linkedin.com/oauth/openid/jwks",
		Issuer:       "https://www.linkedin.com/oauth",
		Scopes:       []string{"openid", "email", "profile"},
		OIDC:         true,
		// LinkedIn's issuer is https://www.linkedin.com/oauth while its userinfo
		// lives on api.linkedin.com -- a split that breaks clients which assume
		// one origin serves both.
		TrustsEmailVerification: true,
		Note: "The issuer and the userinfo endpoint are on different hosts, which " +
			"is unusual and correct.",
	},

	KindMicrosoft: {
		AuthorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserinfoURL:  "https://graph.microsoft.com/oidc/userinfo",
		JWKSURL:      "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		Scopes:       []string{"openid", "email", "profile"},
		OIDC:         true,
		// Microsoft's own documentation is explicit about this. Of the `email`
		// claim: "This value isn't guaranteed to be correct, and is mutable over
		// time - never use it for authorization or to save data for a user." And
		// under a Warning: "Never use email or upn claim values to store or
		// determine whether the user in an access token should have access to
		// data."
		//
		// The signal that DOES mean something is the optional `xms_edov` claim --
		// "Boolean value indicating whether the user's email domain owner has
		// been verified" -- which the application registration must opt into.
		//
		// So the plain claim is never believed, and xms_edov is honoured when
		// present. An operator who wants Microsoft sign-up must add the optional
		// claim to their app registration, which is a two-minute change and the
		// difference between a verified address and an asserted one.
		// True for the same reason: we never read Microsoft's email_verified, only
		// xms_edov. An address is reported verified here ONLY when Microsoft has
		// said the domain owner was verified.
		TrustsEmailVerification: true,
		EmailNeedsSeparateCheck: true,
		Note: "Microsoft documents the email claim as not guaranteed correct, so it " +
			"is ignored. Add the optional claim xms_edov to your app registration -- " +
			"without it no Microsoft address can be treated as verified, and sign-up " +
			"will refuse.",
	},

	KindOIDC: {
		Scopes: []string{"openid", "email", "profile"},
		OIDC:   true,
		TrustsEmailVerification: false,
		EmailNeedsSeparateCheck: false,
		Note: "Verification is not trusted by default for an unknown provider. " +
			"Enable it only if you know how that provider verifies addresses.",
	},
}

// PresetFor returns the configuration for a kind.
func PresetFor(k Kind) (Preset, error) {
	p, ok := presets[k]
	if !ok {
		return Preset{}, fmt.Errorf("unknown provider kind %q; use one of %s",
			k, strings.Join(kindNames(), ", "))
	}
	return p, nil
}

// Kinds lists the supported kinds, for help text.
//
// Derived from the presets map rather than written out again. The hardcoded
// version went stale the first time a provider was added -- the new kind worked
// and the error message listing valid kinds did not mention it, which is the
// worst possible combination for whoever is guessing.
func Kinds() []Kind {
	out := make([]Kind, 0, len(presets)+1)
	for k := range presets {
		out = append(out, k)
	}
	// The generic kind may or may not have an entry in the map depending on
	// whether it needs endpoints of its own; add it only if it does not.
	if _, ok := presets[KindOIDC]; !ok {
		out = append(out, KindOIDC)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func kindNames() []string {
	ks := Kinds()
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, string(k))
	}
	return out
}
