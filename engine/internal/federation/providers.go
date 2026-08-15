package federation

import "fmt"

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
		return Preset{}, fmt.Errorf("unknown provider kind %q; use one of oidc, google, "+
			"github, microsoft", k)
	}
	return p, nil
}

// Kinds lists the supported kinds, for help text.
func Kinds() []Kind {
	return []Kind{KindOIDC, KindGoogle, KindGitHub, KindMicrosoft}
}
