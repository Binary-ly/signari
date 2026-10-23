package config

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Upstream identity providers in a configuration file (6.19): where people
// sign in from. A generic OIDC provider's endpoints are given, not discovered,
// so the plan says exactly what sign-in will use and reaches nothing to say
// it; `signari idp add` discovers them, and an export writes what it found.
// The client secret is named by reference, and never exported.

// IdentityProvider is one upstream.
type IdentityProvider struct {
	Slug string `yaml:"slug"`
	// Kind is a named provider (google, github, microsoft and the rest of
	// the presets), oidc, saml or assertion, fixed once made.
	Kind string `yaml:"kind"`
	Name string `yaml:"name,omitempty"`
	// ClientID and ClientSecret are what the provider issued; a SAML upstream
	// and an assertion issuer have neither.
	ClientID     string     `yaml:"client_id,omitempty"`
	ClientSecret *SecretRef `yaml:"client_secret,omitempty"`
	// Issuer is a generic OIDC provider's and an assertion issuer's, and an
	// override for a named one.
	Issuer string `yaml:"issuer,omitempty"`
	// A generic OIDC provider's endpoints; JWKSURL is an assertion issuer's too.
	AuthorizeURL string        `yaml:"authorize_url,omitempty"`
	TokenURL     string        `yaml:"token_url,omitempty"`
	UserinfoURL  string        `yaml:"userinfo_url,omitempty"`
	JWKSURL      string        `yaml:"jwks_url,omitempty"`
	SAML         *SAMLUpstream `yaml:"saml,omitempty"`
	// Each left as it is when absent; a new provider takes the defaults
	// `signari idp add` gives it.
	AllowSignup            *bool         `yaml:"allow_signup,omitempty"`
	AllowLinking           *bool         `yaml:"allow_linking,omitempty"`
	Enabled                *bool         `yaml:"enabled,omitempty"`
	AllowAssertions        *bool         `yaml:"allow_assertions,omitempty"`
	TrustEmailVerification *bool         `yaml:"trust_email_verification,omitempty"`
	RequireVerifiedEmail   *bool         `yaml:"require_verified_email,omitempty"`
	MFAAMR                 *[]string     `yaml:"mfa_amr,omitempty"`
	MFAACR                 *[]string     `yaml:"mfa_acr,omitempty"`
	AttributeMap           *[]IdPMapping `yaml:"attribute_map,omitempty"`
}

// SAMLUpstream is a SAML identity provider's side of the federation. Its
// certificate is public, and so in the file.
type SAMLUpstream struct {
	EntityID         string `yaml:"entity_id"`
	SSOURL           string `yaml:"sso_url"`
	Certificate      string `yaml:"certificate"`
	NameIDFormat     string `yaml:"name_id_format,omitempty"`
	AllowUnsolicited bool   `yaml:"allow_unsolicited,omitempty"`
	ForceAuthn       bool   `yaml:"force_authn,omitempty"`
	SkewSeconds      int    `yaml:"skew_seconds,omitempty"`
}

func (s *SAMLUpstream) settings() *store.SAMLUpstreamSettings {
	if s == nil {
		return nil
	}
	return &store.SAMLUpstreamSettings{EntityID: s.EntityID, SSOURL: s.SSOURL, CertPEM: s.Certificate,
		NameIDFormat: s.NameIDFormat, ForceAuthn: s.ForceAuthn, AllowUnsolicited: s.AllowUnsolicited,
		SkewSeconds: s.SkewSeconds}
}

// IdPMapping routes a claim the provider sends into a declared attribute.
type IdPMapping struct {
	Claim     string `yaml:"claim"`
	Attribute string `yaml:"attribute"`
	Overwrite bool   `yaml:"overwrite,omitempty"`
	MaxLength int    `yaml:"max_length,omitempty"`
}

func (m IdPMapping) key() string { return m.Claim + " to " + m.Attribute }

func (w IdentityProvider) at() string { return "identity_providers[" + w.Slug + "]" }

func (w IdentityProvider) named() bool {
	return w.Kind != "oidc" && w.Kind != "saml" && w.Kind != "assertion"
}

// spec is the provider as store.AddIdentityProvider takes it, its secret
// resolved and a new one's defaults filled.
func (w IdentityProvider) spec() store.IdentityProviderSpec {
	on := func(b *bool, def bool) bool {
		if b == nil {
			return def
		}
		return *b
	}
	s := store.IdentityProviderSpec{Slug: w.Slug, Name: w.Name, Kind: w.Kind, ClientID: w.ClientID, Issuer: w.Issuer,
		AuthorizeURL: w.AuthorizeURL, TokenURL: w.TokenURL, UserinfoURL: w.UserinfoURL, JWKSURL: w.JWKSURL,
		AllowSignup: on(w.AllowSignup, w.Kind != "assertion"), AllowLinking: on(w.AllowLinking, w.Kind != "assertion"),
		// A SAML assertion has no field to say an address is unverified,
		// which is why `idp add` believes a SAML upstream's by default.
		TrustEmailVerification: on(w.TrustEmailVerification, w.Kind == "saml")}
	if w.ClientSecret != nil {
		s.ClientSecret = w.ClientSecret.value
	}
	if w.SAML != nil {
		s.EntityID, s.SSOURL, s.CertPEM, s.NameIDFormat = w.SAML.EntityID, w.SAML.SSOURL, w.SAML.Certificate,
			w.SAML.NameIDFormat
		s.AllowUnsolicited, s.ForceAuthn, s.SkewSeconds = w.SAML.AllowUnsolicited, w.SAML.ForceAuthn, w.SAML.SkewSeconds
	}
	return s
}

// change is what ChangeIdentityProvider writes, from what the file gives.
func (w IdentityProvider) change() store.IdentityProviderChange {
	return store.IdentityProviderChange{Enabled: w.Enabled, AllowAssertions: w.AllowAssertions,
		TrustEmailVerification: w.TrustEmailVerification, RequireVerifiedEmail: w.RequireVerifiedEmail,
		MFAAMR: w.MFAAMR, MFAACR: w.MFAACR}
}

type idpSection struct{}

func (idpSection) kind() string { return "identity_provider" }

// first is false: a mapping fills an attribute the file declares, which the
// attribute section, being first, has made by then.
func (idpSection) first() bool { return false }

func (idpSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "identity_providers")
	for i, w := range f.IdentityProviders {
		if !once(i, w.Slug) {
			continue
		}
		endpoints := []string{w.AuthorizeURL, w.TokenURL, w.UserinfoURL}
		switch {
		case w.Kind == "saml":
			if w.SAML == nil {
				add("%s: a SAML upstream needs saml: its entity_id, sso_url and certificate", w.at())
			}
			if w.ClientSecret != nil || w.Issuer != "" || w.JWKSURL != "" || slices.ContainsFunc(endpoints, notEmpty) {
				add("%s: a SAML upstream has no client, issuer or endpoints, only saml", w.at())
			}
		case w.SAML != nil:
			add("%s: saml is a SAML upstream's", w.at())
		case w.Kind == "assertion":
			if w.ClientSecret != nil || slices.ContainsFunc(endpoints, notEmpty) {
				add("%s: an assertion issuer signs nobody in, so it has no client secret or sign-in endpoints",
					w.at())
			}
		case w.Kind == "oidc":
			for name, u := range map[string]string{"authorize_url": w.AuthorizeURL, "token_url": w.TokenURL,
				"jwks_url": w.JWKSURL} {
				if !strings.HasPrefix(u, "https://") {
					add("%s: give the https %s: a generic provider's endpoints are written, not discovered, "+
						"so the plan says what sign-in uses (`signari idp add` discovers them, and an export "+
						"writes what it found)", w.at(), name)
				}
			}
			if w.UserinfoURL != "" && !strings.HasPrefix(w.UserinfoURL, "https://") {
				add("%s: userinfo_url must be https", w.at())
			}
		default:
			if w.JWKSURL != "" || slices.ContainsFunc(endpoints, notEmpty) {
				add("%s: a %s provider's endpoints are its preset's", w.at(), w.Kind)
			}
		}
		// The engine dials these from the request path, so an address the
		// dialer would refuse then is refused now.
		for _, u := range []string{w.TokenURL, w.UserinfoURL, w.JWKSURL} {
			if u != "" {
				if err := safedial.CheckURL(u); err != nil {
					add("%s: %v", w.at(), err)
				}
			}
		}
		if (w.Kind == "github" || w.Kind == "saml") && ((w.MFAAMR != nil && len(*w.MFAAMR) > 0) ||
			(w.MFAACR != nil && len(*w.MFAACR) > 0)) {
			add("%s: a %s provider sends no ID token for an amr or acr to be read from", w.at(), w.Kind)
		}
		if w.Kind == "assertion" && (w.TrustEmailVerification != nil || w.RequireVerifiedEmail != nil) {
			add("%s: an assertion issuer signs nobody in, so no address of its is recorded or required", w.at())
		} else if w.TrustEmailVerification != nil && w.named() {
			add("%s: a %s provider's email_verified is believed or not as that provider is known to behave; "+
				"only a generic OIDC provider's or a SAML upstream's is set here", w.at(), w.Kind)
		}
		if w.AttributeMap != nil {
			pairs := map[string]bool{}
			for _, m := range *w.AttributeMap {
				switch {
				case m.Claim == "" || m.Attribute == "":
					add("%s: an attribute_map entry needs its claim and attribute", w.at())
				case pairs[m.key()]:
					add("%s: attribute_map maps %s twice", w.at(), m.key())
				case m.MaxLength < 0:
					add("%s: attribute_map %s has a negative max_length", w.at(), m.key())
				}
				pairs[m.key()] = true
			}
		}
		// The rest of what registration checks, the secret aside: a kind no
		// preset has, a SAML certificate that will not parse or has expired.
		s := w.spec()
		if err := s.Validate(); err != nil {
			add("%s: %v", w.at(), err)
		}
		if w.ClientSecret != nil {
			w.ClientSecret.check(w.at()+".client_secret", add)
		}
	}
}

func notEmpty(s string) bool { return s != "" }

// keptProvider is the plan's detail for a provider a pruned file leaves out.
const keptProvider = "disabled rather than deleted: its links are how the people who sign in through it reach " +
	"their accounts"

// heldProvider is a provider as the deployment holds it, both halves.
type heldProvider struct {
	store.IdentityProviderRow
	store.IdentityProviderSettings
}

func heldProviders(ctx context.Context, tx pgx.Tx, orgID string) (map[string]heldProvider, error) {
	rows, err := store.IdentityProviders(ctx, tx, orgID)
	if err != nil {
		return nil, err
	}
	settings, err := store.IdentityProviderSettingsOf(ctx, tx, orgID)
	if err != nil {
		return nil, err
	}
	out := map[string]heldProvider{}
	for _, r := range rows {
		out[r.Slug] = heldProvider{r, settings[r.Slug]}
	}
	return out, nil
}

func (idpSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	held, err := heldProviders(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, w := range f.IdentityProviders {
		if w.ClientSecret != nil {
			if _, err := w.ClientSecret.secret(w.at() + ".client_secret"); err != nil {
				return err
			}
		}
		h, ok := held[w.Slug]
		if !ok {
			// The slug is the sign-in URL /login/with/<slug>, which names no
			// organisation, so another's is refused by name rather than
			// planned as a create the database would refuse.
			if owner, _, err := store.IdentityProviderOrg(ctx, tx, w.Slug); err == nil && owner != orgID {
				return refuse("%s: another organisation's provider has that slug, which is the sign-in URL "+
					"/login/with/%s and so unique across the deployment", w.at(), w.Slug)
			}
			continue
		}
		if h.Kind != w.Kind {
			return refuse("%s: it is a %s provider, and a provider's kind is fixed once made; register the %s "+
				"one under another slug", w.at(), h.Kind, w.Kind)
		}
		if h.HasSecret && w.ClientSecret == nil &&
			(h.ClientID != w.ClientID || h.Issuer != w.Issuer || h.TokenURL != w.TokenURL) {
			return refuse("%s: %v", w.at(), store.ErrIdPSecretForAnotherClient)
		}
	}

	var failed error
	planKeyed(p, "identity_provider", keyBy(f.IdentityProviders, func(w IdentityProvider) string { return w.Slug }),
		held, false, func(h heldProvider, w IdentityProvider) string {
			var c changed
			c.note(w.Name != "" && h.Name != w.Name, "name")
			c.note(h.ClientID != w.ClientID, "client_id")
			c.note(h.Issuer != w.Issuer, "issuer")
			c.note(h.AuthorizeURL != w.AuthorizeURL || h.TokenURL != w.TokenURL || h.UserinfoURL != w.UserinfoURL ||
				h.JWKSURL != w.JWKSURL, "endpoints")
			if want := w.SAML.settings(); want != nil && h.SAML != nil {
				if want.NameIDFormat == "" {
					want.NameIDFormat = "persistent"
				}
				c.note(*want != *h.SAML, "saml")
			}
			c.note(w.AllowSignup != nil && h.AllowSignup != *w.AllowSignup, "allow_signup")
			c.note(w.AllowLinking != nil && h.AllowLinking != *w.AllowLinking, "allow_linking")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			c.note(w.AllowAssertions != nil && h.AllowAssertions != *w.AllowAssertions, "allow_assertions")
			c.note(w.TrustEmailVerification != nil && h.TrustEmailVerification != *w.TrustEmailVerification,
				"trust_email_verification")
			c.note(w.RequireVerifiedEmail != nil && h.RequireVerifiedEmail != *w.RequireVerifiedEmail,
				"require_verified_email")
			c.note(w.MFAAMR != nil && !sameSet(h.MFAAMR, *w.MFAAMR), "mfa_amr")
			c.note(w.MFAACR != nil && !sameSet(h.MFAACR, *w.MFAACR), "mfa_acr")
			if w.AttributeMap != nil {
				have := map[string]IdPMapping{}
				for _, m := range h.AttributeMap {
					have[m.Claim+" to "+m.Attribute] = IdPMapping{Claim: m.Claim, Attribute: m.Attribute,
						Overwrite: m.Overwrite, MaxLength: m.MaxLength}
				}
				want := map[string]IdPMapping{}
				for _, m := range *w.AttributeMap {
					if m.MaxLength == 0 {
						m.MaxLength = 256
					}
					want[m.key()] = m
				}
				c.note(len(have) != len(want) || !mapsEqual(have, want), "attribute_map")
			}
			if w.ClientSecret != nil && failed == nil {
				if failed = p.needsRoot("identity_provider", w.Slug, "comparing the client secret the file names"); failed == nil {
					var secret string
					secret, failed = store.IdentityProviderSecret(ctx, tx, p.opts.Root, orgID, w.Slug)
					c.note(secret != w.ClientSecret.value, "client_secret")
				}
			}
			return c.String()
		}, "")
	if failed != nil {
		return failed
	}
	inFile := keyBy(f.IdentityProviders, func(w IdentityProvider) string { return w.Slug })
	if prune {
		for slug, h := range held {
			if _, ok := inFile[slug]; !ok && h.Enabled {
				p.Add(Change{Action: "update", Kind: "identity_provider", Name: slug, Detail: keptProvider})
			}
		}
	}
	for i, c := range p.Changes {
		if c.Kind != "identity_provider" || c.Action != "create" {
			continue
		}
		w := inFile[c.Name]
		switch {
		case w.ClientSecret != nil:
			p.Changes[i].Detail = "client secret from " + w.ClientSecret.String()
			if err := p.needsRoot("identity_provider", c.Name, "sealing its client secret"); err != nil {
				return err
			}
		case w.Kind != "saml" && w.Kind != "assertion":
			p.Changes[i].Detail = "no client secret"
		}
	}
	return nil
}

func mapsEqual(a, b map[string]IdPMapping) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (idpSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	held, err := heldProviders(ctx, tx, orgID)
	if err != nil {
		return err
	}
	inFile := map[string]bool{}
	for _, w := range f.IdentityProviders {
		inFile[w.Slug] = true
		c, ok := p.planned("identity_provider", w.Slug)
		if !ok {
			continue
		}
		if c.Action == "create" {
			spec := w.spec()
			if err := spec.Validate(); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
			if _, err := store.AddIdentityProvider(ctx, tx, p.opts.Root, orgID, spec); err != nil {
				return err
			}
		} else {
			u := store.IdentityProviderUpdate{ClientID: &w.ClientID, Issuer: &w.Issuer, AuthorizeURL: &w.AuthorizeURL,
				TokenURL: &w.TokenURL, UserinfoURL: &w.UserinfoURL, JWKSURL: &w.JWKSURL, AllowSignup: w.AllowSignup,
				AllowLinking: w.AllowLinking, SAML: w.SAML.settings()}
			if w.Name != "" {
				u.Name = &w.Name
			}
			if w.ClientSecret != nil {
				u.ClientSecret = &w.ClientSecret.value
			}
			if err := store.UpdateIdentityProvider(ctx, tx, p.opts.Root, orgID, w.Slug, u); err != nil {
				return err
			}
		}
		if change := w.change(); !change.Empty() {
			if c.Action == "create" {
				// Registration wrote the belief in email_verified already.
				change.TrustEmailVerification = nil
			}
			if err := store.ChangeIdentityProvider(ctx, tx, orgID, w.Slug, change); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
		}
		if w.AttributeMap == nil {
			continue
		}
		want := map[string]bool{}
		for _, m := range *w.AttributeMap {
			want[m.key()] = true
			if err := store.SetIdPAttributeMap(ctx, tx, orgID, w.Slug, m.Claim, m.Attribute, m.Overwrite,
				m.MaxLength); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
		}
		for _, m := range held[w.Slug].AttributeMap {
			if !want[m.Claim+" to "+m.Attribute] {
				if err := store.RemoveIdPAttributeMap(ctx, tx, orgID, w.Slug, m.Claim, m.Attribute); err != nil {
					return err
				}
			}
		}
	}
	off := false
	for slug := range held {
		if c, ok := p.planned("identity_provider", slug); ok && !inFile[slug] && c.Detail == keptProvider {
			if err := store.ChangeIdentityProvider(ctx, tx, orgID, slug, store.IdentityProviderChange{
				Enabled: &off}); err != nil {
				return err
			}
		}
	}
	return nil
}

// remove is never planned: a pruned provider is switched off, not deleted.
func (idpSection) remove(context.Context, pgx.Tx, string, string) error {
	return fmt.Errorf("an identity provider is disabled by a pruned file, never deleted")
}

// export writes what sign-in uses, a generic provider's discovered endpoints
// included, and never the client secret.
func (idpSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	held, err := heldProviders(ctx, tx, orgID)
	if err != nil {
		return err
	}
	slugs := make([]string, 0, len(held))
	for s := range held {
		slugs = append(slugs, s)
	}
	slices.Sort(slugs)
	for _, slug := range slugs {
		h := held[slug]
		w := IdentityProvider{Slug: slug, Kind: h.Kind, Name: h.Name, ClientID: h.ClientID, Issuer: h.Issuer,
			AuthorizeURL: h.AuthorizeURL, TokenURL: h.TokenURL, UserinfoURL: h.UserinfoURL, JWKSURL: h.JWKSURL}
		enabled, assertions := h.Enabled, h.AllowAssertions
		w.Enabled, w.AllowAssertions = &enabled, &assertions
		if h.Kind != "assertion" {
			signup, linking, require := h.AllowSignup, h.AllowLinking, h.RequireVerifiedEmail
			w.AllowSignup, w.AllowLinking, w.RequireVerifiedEmail = &signup, &linking, &require
		}
		if h.Kind == "oidc" || h.Kind == "saml" {
			trust := h.TrustEmailVerification
			w.TrustEmailVerification = &trust
		}
		if len(h.MFAAMR) > 0 {
			amr := sortedCopy(h.MFAAMR)
			w.MFAAMR = &amr
		}
		if len(h.MFAACR) > 0 {
			acr := sortedCopy(h.MFAACR)
			w.MFAACR = &acr
		}
		if s := h.SAML; s != nil {
			w.SAML = &SAMLUpstream{EntityID: s.EntityID, SSOURL: s.SSOURL, Certificate: s.CertPEM,
				NameIDFormat: s.NameIDFormat, AllowUnsolicited: s.AllowUnsolicited, ForceAuthn: s.ForceAuthn,
				SkewSeconds: s.SkewSeconds}
		}
		if len(h.AttributeMap) > 0 {
			var maps []IdPMapping
			for _, m := range h.AttributeMap {
				maps = append(maps, IdPMapping{Claim: m.Claim, Attribute: m.Attribute, Overwrite: m.Overwrite,
					MaxLength: m.MaxLength})
			}
			w.AttributeMap = &maps
		}
		f.IdentityProviders = append(f.IdentityProviders, w)
	}
	return nil
}
