// Package config applies a declarative file to a deployment.
//
// # Why not blueprints
//
// The comparable feature elsewhere in this field applies YAML at startup. You
// find out what it did afterwards, by looking at what changed.
//
// This plans first. `signari plan` prints exactly what would be created,
// updated and deleted, and `signari apply` does it. The difference matters most
// on the day somebody edits a file they did not write, which is every day after
// the first.
//
// # Additive by default, destructive only when asked
//
// A file that omits a client does NOT delete it. Declarative-means-delete is
// correct for infrastructure that can be rebuilt and wrong for an identity
// provider, where a missing line takes down an application and its sessions.
//
// `-prune` turns absence into deletion, and prints every deletion before making
// any of them.
//
// # Everything is validated before anything is changed
//
// A file with a bad redirect URI in the tenth client does not create nine and
// then stop. Half-applied configuration is worse than none: it looks like it
// worked and the failure is somewhere in the middle.
package config

import (
	"fmt"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/radius"
	"signari.dev/engine/internal/store"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// File is a whole configuration.
type File struct {
	Version int    `yaml:"version"`
	Org     string `yaml:"org"`

	Groups        []Group        `yaml:"groups"`
	Clients       []Client       `yaml:"clients"`
	SAMLProviders []SAMLProvider `yaml:"saml_providers"`
	RADIUSClients []RADIUSClient `yaml:"radius_clients"`
	ProxyHosts    []ProxyHost    `yaml:"proxy_hosts"`

	// The kinds in sections.go (6.19).
	Scopes     []Scope     `yaml:"scopes,omitempty"`
	Attributes []Attribute `yaml:"attributes,omitempty"`
	Resources  []Resource  `yaml:"resources,omitempty"`
	Signup     *Signup     `yaml:"signup,omitempty"`

	ClaimMappers []ClaimMapper `yaml:"claim_mappers,omitempty"`
	// AccessPolicy and SignInFlow are documents, kept as the text they were
	// written in; absent leaves the one in force.
	AccessPolicy *string  `yaml:"access_policy,omitempty"`
	SignInFlow   *string  `yaml:"sign_in_flow,omitempty"`
	Prompts      []Prompt `yaml:"prompts,omitempty"`
}

// ProxyHost is an application protected by forward authentication.
type ProxyHost struct {
	Host    string `yaml:"host"`
	Enabled *bool  `yaml:"enabled"`
}

// Group is a group of people.
type Group struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description"`
}

// shownAs is the group's display name, its name when the file gives none, as
// `signari group create` names one (0.34).
func (g Group) shownAs() string {
	if g.DisplayName == "" {
		return g.Name
	}
	return g.DisplayName
}

// Client is an OAuth/OIDC application.
type Client struct {
	ClientID     string   `yaml:"client_id"`
	Name         string   `yaml:"name"`
	RedirectURIs []string `yaml:"redirect_uris"`
	Scopes       []string `yaml:"scopes"`
	Public       bool     `yaml:"public"`
	LaunchURL    string   `yaml:"launch_url"`
	LogoURL      string   `yaml:"logo_url"`
	PortalHidden bool     `yaml:"portal_hidden"`
	Enabled      *bool    `yaml:"enabled"`
	// TokenExchange grants RFC 8693 token exchange. Absent leaves the client's
	// current permission alone, as an omitted `enabled` does.
	TokenExchange *TokenExchange `yaml:"token_exchange"`
	// The sign-out registration. Each left alone when absent; an empty list or
	// string clears it.
	PostLogoutRedirectURIs      *[]string `yaml:"post_logout_redirect_uris"`
	FrontchannelLogoutURI       *string   `yaml:"frontchannel_logout_uri"`
	FrontchannelSessionRequired *bool     `yaml:"frontchannel_logout_session_required"`
	// Token lifetimes, as Go durations ("10m", "720h"). Each left alone when
	// absent, as `client set-lifetimes` leaves the one it is not given.
	AccessTokenTTL  *time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL *time.Duration `yaml:"refresh_token_ttl"`
	// IDTokenAlg signs the client's ID and access tokens; absent leaves it.
	IDTokenAlg *string `yaml:"id_token_signed_response_alg"`
	// RequirePAR and FirstParty are the switches; each absent leaves it.
	RequirePAR *bool `yaml:"require_pushed_authorization_requests"`
	FirstParty *bool `yaml:"first_party"`
	// IssuerAlias pins the client to a legacy issuer the instance claims;
	// empty clears it, absent leaves it.
	IssuerAlias *string `yaml:"issuer_alias"`
	// MinimumACR is the weakest authentication the client accepts, "1" to
	// "4" (oauth.Meets); absent leaves it.
	MinimumACR *string `yaml:"minimum_acr"`
}

// settings is the client's part for store.SetClientSettings.
func (c Client) settings() store.ClientSettings {
	return store.ClientSettings{AccessTokenTTL: c.AccessTokenTTL, RefreshTokenTTL: c.RefreshTokenTTL,
		IDTokenAlg: c.IDTokenAlg, RequirePAR: c.RequirePAR, FirstParty: c.FirstParty,
		IssuerAlias: c.IssuerAlias, MinimumACR: c.MinimumACR}
}

// TokenExchange is whether a client may exchange tokens, and for which
// audiences besides itself.
type TokenExchange struct {
	Enabled   bool     `yaml:"enabled"`
	Audiences []string `yaml:"audiences"`
}

// SAMLProvider is a SAML service provider.
type SAMLProvider struct {
	EntityID string   `yaml:"entity_id"`
	Name     string   `yaml:"name"`
	ACSURLs  []string `yaml:"acs_urls"`
	NameID   string   `yaml:"name_id_format"`
	Enabled  *bool    `yaml:"enabled"`
}

// RADIUSClient is a network device permitted to ask.
type RADIUSClient struct {
	Name    string `yaml:"name"`
	Network string `yaml:"network"`
	Enabled *bool  `yaml:"enabled"`
	// Secret is never read from the file.
	//
	// A RADIUS shared secret in a repository is a shared secret in everybody's
	// clone, their editor's backup, and the CI logs of whoever forked it.
	// Secrets are set with `signari radius add-client` and left alone here; a
	// file that names one is refused rather than quietly ignored.
	Secret string `yaml:"secret"`
}

// Parse reads a configuration file.
func Parse(raw []byte) (*File, error) {
	var f File
	// KnownFields: a misspelled key is a line that does nothing, and silence is
	// the worst possible response to "I configured that and it had no effect".
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the configuration did not parse: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("version must be 1 (got %d)", f.Version)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Validate checks everything before anything is applied.
func (f *File) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	seenGroup := map[string]bool{}
	for i, g := range f.Groups {
		switch {
		case g.Name == "":
			add("groups[%d]: name is required", i)
		case seenGroup[g.Name]:
			add("groups[%d]: %q appears twice", i, g.Name)
		}
		seenGroup[g.Name] = true
	}

	seenClient := map[string]bool{}
	for i, c := range f.Clients {
		if c.ClientID == "" {
			add("clients[%d]: client_id is required", i)
			continue
		}
		if seenClient[c.ClientID] {
			add("clients[%d]: %q appears twice", i, c.ClientID)
		}
		seenClient[c.ClientID] = true

		if len(c.RedirectURIs) == 0 {
			add("clients[%s]: at least one redirect_uri is required", c.ClientID)
		}
		for _, u := range c.RedirectURIs {
			if err := clients.ValidateRedirectURI(u); err != nil {
				add("clients[%s]: %s", c.ClientID, err.Error())
			}
		}
		// Redirect URIs go to clients.ValidateRedirectURI; launch URLs to the
		// rule the client PATCH applies too.
		if c.LaunchURL != "" && !clients.SecureLaunchURL(c.LaunchURL) {
			add("clients[%s]: launch_url must be https", c.ClientID)
		}
		if c.LogoURL != "" && !strings.HasPrefix(c.LogoURL, "https://") {
			add("clients[%s]: logo_url must be https", c.ClientID)
		}
		if c.PortalHidden && c.LaunchURL != "" {
			add("clients[%s]: portal_hidden and launch_url contradict each other",
				c.ClientID)
		}
		if c.PostLogoutRedirectURIs != nil {
			for _, u := range *c.PostLogoutRedirectURIs {
				if err := clients.ValidateRedirectURI(u); err != nil {
					add("clients[%s]: post_logout_redirect_uri: %s", c.ClientID, err.Error())
				}
			}
		}
		if u := c.FrontchannelLogoutURI; u != nil && *u != "" &&
			(!strings.HasPrefix(*u, "https://") || strings.Contains(*u, "#")) {
			add("clients[%s]: frontchannel_logout_uri must be https with no fragment", c.ClientID)
		}
		if x := c.TokenExchange; x != nil {
			if x.Enabled && c.Public {
				add("clients[%s]: token_exchange needs a confidential client; a public "+
					"client cannot prove it is the one the permission was granted to", c.ClientID)
			}
			if !x.Enabled && len(x.Audiences) > 0 {
				add("clients[%s]: token_exchange lists audiences but is not enabled, "+
					"so they would grant nothing", c.ClientID)
			}
			if _, err := store.CleanExchangeAudiences(x.Audiences); err != nil {
				add("clients[%s]: token_exchange: %s", c.ClientID, err.Error())
			}
		}
		if err := store.CheckClientSettings(c.settings()); err != nil {
			add("clients[%s]: %s", c.ClientID, err.Error())
		}
	}

	seenSP := map[string]bool{}
	for i, p := range f.SAMLProviders {
		if p.EntityID == "" {
			add("saml_providers[%d]: entity_id is required", i)
			continue
		}
		if seenSP[p.EntityID] {
			add("saml_providers[%d]: %q appears twice", i, p.EntityID)
		}
		seenSP[p.EntityID] = true
		if len(p.ACSURLs) == 0 {
			add("saml_providers[%s]: at least one acs_url is required", p.EntityID)
		}
		for _, u := range p.ACSURLs {
			if !strings.HasPrefix(u, "https://") {
				add("saml_providers[%s]: acs_url %q must be https: it carries a "+
					"signed assertion for a real user", p.EntityID, u)
			}
			if strings.Contains(u, "*") {
				add("saml_providers[%s]: acs_url %q contains a wildcard", p.EntityID, u)
			}
		}
		switch p.NameID {
		case "", "persistent", "emailAddress", "transient":
		default:
			add("saml_providers[%s]: name_id_format %q is not one of persistent, "+
				"emailAddress, transient", p.EntityID, p.NameID)
		}
	}

	seenRadius := map[string]bool{}
	for i, r := range f.RADIUSClients {
		if r.Name == "" {
			add("radius_clients[%d]: name is required", i)
			continue
		}
		if seenRadius[r.Name] {
			add("radius_clients[%d]: %q appears twice", i, r.Name)
		}
		seenRadius[r.Name] = true
		if r.Network == "" {
			add("radius_clients[%s]: network is required", r.Name)
		} else if _, err := radius.ClientNetwork(r.Network); err != nil {
			// The rule `radius add-client` applies, an IPv4-mapped spelling of
			// every address included.
			add("radius_clients[%s]: network %v", r.Name, err)
		}
		if r.Secret != "" {
			add("radius_clients[%s]: remove `secret`. A RADIUS shared secret in a "+
				"repository is in every clone of it, every editor backup and the CI "+
				"logs of anyone who forked it. Set it with `signari radius "+
				"add-client` instead", r.Name)
		}
	}

	seenHosts := map[string]bool{}
	for i, h := range f.ProxyHosts {
		host, err := store.NormaliseProxyHost(h.Host)
		if err != nil {
			add("proxy_hosts[%d]: %v", i, err)
			continue
		}
		if host != h.Host {
			// Written as stored, so the plan's diff and the file agree on what
			// the host is called.
			add("proxy_hosts[%d]: write %q as %q", i, h.Host, host)
		}
		if seenHosts[host] {
			add("proxy_hosts[%d]: %q appears twice", i, host)
		}
		seenHosts[host] = true
	}

	for _, s := range sections {
		s.validate(f, add)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("the configuration has %d problem(s):\n  %s\n\nNothing was "+
			"changed. A file that is half-applied looks like it worked and fails "+
			"somewhere in the middle", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// Change is one difference between the file and the deployment.
type Change struct {
	Action string // create, update, delete
	Kind   string // group, client, saml_provider, radius_client, proxy_host
	Name   string
	Detail string
	// Destructive marks a change that removes something.
	Destructive bool
}

// Plan is everything that would change.
type Plan struct{ Changes []Change }

// Add records a change.
func (p *Plan) Add(c Change) { p.Changes = append(p.Changes, c) }

// Empty reports whether the deployment already matches.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Destructive returns the changes that remove something.
func (p *Plan) Destructive() []Change {
	var out []Change
	for _, c := range p.Changes {
		if c.Destructive {
			out = append(out, c)
		}
	}
	return out
}

// String renders the plan for an operator.
func (p *Plan) String() string {
	if p.Empty() {
		return "  no changes; the deployment already matches this file\n"
	}
	var b strings.Builder
	sym := map[string]string{"create": "+", "update": "~", "delete": "-"}
	for _, c := range p.Changes {
		fmt.Fprintf(&b, "  %s %-14s %s", sym[c.Action], c.Kind, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(&b, "   %s", c.Detail)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Counts summarises a plan.
func (p *Plan) Counts() (create, update, del int) {
	for _, c := range p.Changes {
		switch c.Action {
		case "create":
			create++
		case "update":
			update++
		case "delete":
			del++
		}
	}
	return
}
