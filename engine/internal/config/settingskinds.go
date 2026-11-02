package config

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/store"
)

// An organisation's settings that are one each (6.25): dynamic client
// registration, the WebAuthn policy and UMA's owner intervention. Each is a
// block the file names or leaves out, written through the writer its command
// and route share.

// Registration is RFC 7591 dynamic client registration.
type Registration struct {
	// Enabled is true when the block is given and says nothing; false turns
	// registration off, keeping its policy and initial access tokens.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Open lets a client register with no initial access token.
	Open bool `yaml:"open,omitempty"`
	// MaxClients is how many registration may make, 100 when absent.
	MaxClients int `yaml:"max_clients,omitempty"`
	// AllowedScopes are what a registered client may ask for; openid, profile
	// and email when absent.
	AllowedScopes []string `yaml:"allowed_scopes,omitempty"`
	// AllowConfidential lets registration hand out client secrets.
	AllowConfidential bool `yaml:"allow_confidential,omitempty"`
}

func (r Registration) on() bool { return r.Enabled == nil || *r.Enabled }

// policy is the registration policy as stored, its defaults filled.
func (r Registration) policy() store.RegistrationPolicy {
	p := store.RegistrationPolicy{Enabled: r.on(), Open: r.Open, MaxClients: r.MaxClients,
		AllowedScopes: r.AllowedScopes, AllowConfidential: r.AllowConfidential}
	if p.MaxClients <= 0 {
		p.MaxClients = store.DefaultRegistrationCeiling
	}
	if len(p.AllowedScopes) == 0 {
		p.AllowedScopes = store.DefaultRegistrationScopes
	}
	return p
}

type registrationSection struct{}

func (registrationSection) kind() string { return "registration" }

// first is false: the scopes it allows may be ones the file declares, which
// the scope section, being first, has by then.
func (registrationSection) first() bool { return false }

func (registrationSection) validate(f *File, add func(string, ...any)) {
	if r := f.Registration; r != nil && r.MaxClients < 0 {
		add("registration: max_clients is how many clients registration may make, not %d", r.MaxClients)
	}
}

const registrationOff = "turned off rather than deleted: its initial access tokens are kept for when it is " +
	"turned on again"

func (registrationSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.LoadRegistrationPolicy(ctx, tx, orgID)
	if err != nil {
		return err
	}
	switch want := f.Registration; {
	case want == nil && prune && have.Enabled:
		p.Add(Change{Action: "update", Kind: "registration", Name: "policy", Detail: registrationOff})
	case want == nil:
	case !want.on():
		if have.Enabled {
			p.Add(Change{Action: "update", Kind: "registration", Name: "policy", Detail: "enabled"})
		}
	default:
		w := want.policy()
		var c changed
		c.note(!have.Enabled, "enabled")
		c.note(have.Open != w.Open, "open")
		c.note(have.MaxClients != w.MaxClients, "max_clients")
		c.note(!sameSet(have.AllowedScopes, w.AllowedScopes), "allowed_scopes")
		c.note(have.AllowConfidential != w.AllowConfidential, "allow_confidential")
		if d := c.String(); d != "" {
			p.Add(Change{Action: "update", Kind: "registration", Name: "policy", Detail: d})
		}
	}
	return nil
}

func (registrationSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	if _, ok := p.planned("registration", "policy"); !ok {
		return nil
	}
	if f.Registration == nil || !f.Registration.on() {
		_, err := store.DisableRegistration(ctx, tx, orgID)
		return err
	}
	return store.SetRegistrationPolicy(ctx, tx, orgID, f.Registration.policy())
}

// remove is never planned: pruned, registration is turned off.
func (registrationSection) remove(context.Context, pgx.Tx, string, string) error { return nil }

func (registrationSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.LoadRegistrationPolicy(ctx, tx, orgID)
	if err != nil || !have.Enabled {
		return err
	}
	f.Registration = &Registration{Open: have.Open, MaxClients: have.MaxClients,
		AllowedScopes: sortedCopy(have.AllowedScopes), AllowConfidential: have.AllowConfidential}
	return nil
}

// WebAuthnPolicy is the organisation's authenticator rules, written whole: a
// field left out takes the default, as the command writes it.
type WebAuthnPolicy struct {
	// Attestation is none (the default), indirect, direct or enterprise.
	Attestation string `yaml:"attestation,omitempty"`
	// AllowedAAGUIDs admits only those authenticator models, and needs
	// attestation: with none, the model is the authenticator's own claim.
	AllowedAAGUIDs []string `yaml:"allowed_aaguids,omitempty"`
	// RefuseCloned refuses a sign-in whose signature counter did not
	// advance; on when absent.
	RefuseCloned     *bool    `yaml:"refuse_cloned,omitempty"`
	UserVerification string   `yaml:"user_verification,omitempty"`
	ResidentKey      string   `yaml:"resident_key,omitempty"`
	Attachment       string   `yaml:"attachment,omitempty"`
	Algorithms       []int    `yaml:"algorithms,omitempty"`
	TimeoutSeconds   int      `yaml:"timeout_seconds,omitempty"`
	Hints            []string `yaml:"hints,omitempty"`
}

// policy is the file's policy with the defaults filled, as the writer stores it.
func (w WebAuthnPolicy) policy() store.WebAuthnPolicy {
	d := store.DefaultWebAuthnPolicy()
	p := store.WebAuthnPolicy{Conveyance: w.Attestation, AllowedAAGUIDs: w.AllowedAAGUIDs,
		RefuseCloned: w.RefuseCloned == nil || *w.RefuseCloned, UserVerification: w.UserVerification,
		ResidentKey: w.ResidentKey, Attachment: w.Attachment, Algorithms: w.Algorithms,
		TimeoutSeconds: w.TimeoutSeconds, Hints: w.Hints}
	if p.Conveyance == "" {
		p.Conveyance = d.Conveyance
	}
	if p.UserVerification == "" {
		p.UserVerification = d.UserVerification
	}
	if p.ResidentKey == "" {
		p.ResidentKey = d.ResidentKey
	}
	if len(p.Algorithms) == 0 {
		p.Algorithms = d.Algorithms
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = d.TimeoutSeconds
	}
	if p.Hints == nil {
		p.Hints = []string{}
	}
	if p.AllowedAAGUIDs == nil {
		p.AllowedAAGUIDs = []string{}
	}
	return p
}

// samePolicy compares two policies as stored: the allow-list as a set, the
// algorithms in their order of preference.
func samePolicy(a, b store.WebAuthnPolicy) bool {
	return a.Conveyance == b.Conveyance && sameSet(a.AllowedAAGUIDs, b.AllowedAAGUIDs) &&
		a.RefuseCloned == b.RefuseCloned && a.UserVerification == b.UserVerification &&
		a.ResidentKey == b.ResidentKey && a.Attachment == b.Attachment && slices.Equal(a.Algorithms, b.Algorithms) &&
		a.TimeoutSeconds == b.TimeoutSeconds && sameSet(a.Hints, b.Hints)
}

type webauthnSection struct{}

func (webauthnSection) kind() string { return "webauthn_policy" }
func (webauthnSection) first() bool  { return false }

func (webauthnSection) validate(f *File, add func(string, ...any)) {
	if w := f.WebAuthnPolicy; w != nil {
		if _, err := store.CheckWebAuthnPolicy(w.policy()); err != nil {
			add("webauthn_policy: %v", err)
		}
	}
}

func (webauthnSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.LoadWebAuthnPolicy(ctx, tx, orgID)
	if err != nil {
		return err
	}
	switch want := f.WebAuthnPolicy; {
	case want == nil && prune && !samePolicy(have, store.DefaultWebAuthnPolicy()):
		p.Add(Change{Action: "delete", Kind: "webauthn_policy", Name: "policy", Destructive: true,
			Detail: "authenticator rules return to the defaults, any model admitted"})
	case want == nil:
	default:
		// Compared as it would be stored, its AAGUIDs canonical.
		checked, err := store.CheckWebAuthnPolicy(want.policy())
		if err != nil {
			return refuse("webauthn_policy: %v", err)
		}
		if !samePolicy(have, checked) {
			p.Add(Change{Action: "update", Kind: "webauthn_policy", Name: "policy", Detail: "the policy"})
		}
	}
	return nil
}

func (webauthnSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	if c, ok := p.planned("webauthn_policy", "policy"); !ok || c.Action == "delete" {
		return nil
	}
	_, err := store.SetWebAuthnPolicy(ctx, tx, orgID, f.WebAuthnPolicy.policy())
	return err
}

func (webauthnSection) remove(ctx context.Context, tx pgx.Tx, orgID, _ string) error {
	_, err := tx.Exec(ctx, `DELETE FROM core.webauthn_policy WHERE org_id = $1::uuid`, orgID)
	return err
}

// export writes the policy when it is not the default, every field given.
func (webauthnSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.LoadWebAuthnPolicy(ctx, tx, orgID)
	if err != nil || samePolicy(have, store.DefaultWebAuthnPolicy()) {
		return err
	}
	refuse := have.RefuseCloned
	f.WebAuthnPolicy = &WebAuthnPolicy{Attestation: have.Conveyance, AllowedAAGUIDs: sortedCopy(have.AllowedAAGUIDs),
		RefuseCloned: &refuse, UserVerification: have.UserVerification, ResidentKey: have.ResidentKey,
		Attachment: have.Attachment, Algorithms: have.Algorithms, TimeoutSeconds: have.TimeoutSeconds,
		Hints: sortedCopy(have.Hints)}
	return nil
}

// UMA is user-managed access's resource-owner intervention.
type UMA struct {
	// OwnerIntervention lets a resource owner approve a request the policy
	// refused, while the client polls; off, a refusal is final.
	OwnerIntervention bool `yaml:"owner_intervention"`
	// PollInterval is how often the client may ask, 30s when absent.
	PollInterval time.Duration `yaml:"poll_interval,omitempty"`
}

func (u UMA) settings() store.UMASettings {
	s := store.UMASettings{OwnerIntervention: u.OwnerIntervention, PollInterval: u.PollInterval}
	if s.PollInterval == 0 {
		s.PollInterval = 30 * time.Second
	}
	return s
}

type umaSection struct{}

func (umaSection) kind() string { return "uma" }
func (umaSection) first() bool  { return false }

func (umaSection) validate(f *File, add func(string, ...any)) {
	if u := f.UMA; u != nil {
		if s := u.settings(); s.PollInterval < 5*time.Second || s.PollInterval > time.Hour {
			add("uma: %v", store.ErrUMAPollInterval)
		}
	}
}

func (umaSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.LoadUMASettings(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := have.PollInterval != 0
	switch want := f.UMA; {
	case want == nil && prune && held:
		p.Add(Change{Action: "delete", Kind: "uma", Name: "settings", Destructive: have.OwnerIntervention,
			Detail: "a refused request is final again"})
	case want == nil:
	case !held:
		p.Add(Change{Action: "create", Kind: "uma", Name: "settings"})
	case have != want.settings():
		p.Add(Change{Action: "update", Kind: "uma", Name: "settings", Detail: "owner_intervention or poll_interval"})
	}
	return nil
}

func (umaSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	if c, ok := p.planned("uma", "settings"); !ok || c.Action == "delete" {
		return nil
	}
	return store.SetUMASettings(ctx, tx, orgID, f.UMA.settings())
}

func (umaSection) remove(ctx context.Context, tx pgx.Tx, orgID, _ string) error {
	_, err := tx.Exec(ctx, `DELETE FROM core.uma_settings WHERE org_id = $1::uuid`, orgID)
	return err
}

func (umaSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.LoadUMASettings(ctx, tx, orgID)
	if err != nil || have.PollInterval == 0 {
		return err
	}
	f.UMA = &UMA{OwnerIntervention: have.OwnerIntervention, PollInterval: have.PollInterval}
	return nil
}

// Brand is the organisation's appearance over its instance's: what it leaves
// out is the instance's, and the four colours are all set or none.
type Brand struct {
	ProductName      string `yaml:"product_name,omitempty"`
	LogoURL          string `yaml:"logo_url,omitempty"`
	SupportURL       string `yaml:"support_url,omitempty"`
	ColourPrimary    string `yaml:"colour_primary,omitempty"`
	ColourOnPrimary  string `yaml:"colour_on_primary,omitempty"`
	ColourBackground string `yaml:"colour_background,omitempty"`
	ColourText       string `yaml:"colour_text,omitempty"`
}

func (b Brand) brand() *brand.Brand {
	return &brand.Brand{ProductName: b.ProductName, LogoURL: b.LogoURL, SupportURL: b.SupportURL,
		Primary: b.ColourPrimary, OnPrimary: b.ColourOnPrimary, Background: b.ColourBackground, Text: b.ColourText}
}

type brandSection struct{}

func (brandSection) kind() string { return "brand" }
func (brandSection) first() bool  { return false }

func (brandSection) validate(f *File, add func(string, ...any)) {
	if b := f.Brand; b != nil {
		if err := b.brand().Validate(); err != nil {
			add("brand: %v", err)
		}
	}
}

func (brandSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.OrgBrandOf(ctx, tx, orgID)
	if err != nil {
		return err
	}
	switch want := f.Brand; {
	case want == nil && prune && have != nil:
		p.Add(Change{Action: "delete", Kind: "brand", Name: "brand", Detail: "its pages wear the instance's appearance again"})
	case want == nil:
	case have == nil:
		p.Add(Change{Action: "create", Kind: "brand", Name: "brand"})
	case *have != *want.brand():
		p.Add(Change{Action: "update", Kind: "brand", Name: "brand"})
	}
	return nil
}

func (brandSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	if c, ok := p.planned("brand", "brand"); !ok || c.Action == "delete" {
		return nil
	}
	return store.SaveOrgBrand(ctx, tx, orgID, f.Brand.brand())
}

func (brandSection) remove(ctx context.Context, tx pgx.Tx, orgID, _ string) error {
	_, err := store.RemoveOrgBrand(ctx, tx, orgID)
	return err
}

func (brandSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.OrgBrandOf(ctx, tx, orgID)
	if err != nil || have == nil {
		return err
	}
	f.Brand = &Brand{ProductName: have.ProductName, LogoURL: have.LogoURL, SupportURL: have.SupportURL,
		ColourPrimary: have.Primary, ColourOnPrimary: have.OnPrimary,
		ColourBackground: have.Background, ColourText: have.Text}
	return nil
}

// Message is one catalogue message reworded for the organisation, in one
// language, as plain text.
type Message struct {
	Locale string `yaml:"locale"`
	Key    string `yaml:"key"`
	Text   string `yaml:"text"`
}

func (m Message) name() string { return m.Locale + "/" + m.Key }

type messageSection struct{}

func (messageSection) kind() string { return "message" }
func (messageSection) first() bool  { return false }

func (messageSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "messages")
	for i, m := range f.Messages {
		if !once(i, m.name()) {
			continue
		}
		if err := i18n.Shipped().CheckWords(m.Locale, m.Key, m.Text); err != nil {
			add("messages[%s]: %v", m.name(), err)
		}
	}
}

func (messageSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.OrgMessages(ctx, tx, orgID)
	if err != nil {
		return err
	}
	planKeyed(p, "message", keyBy(f.Messages, Message.name),
		keyBy(have, func(m store.OrgMessage) string { return m.Locale + "/" + m.Key }), prune,
		func(h store.OrgMessage, w Message) string {
			if h.Body != w.Text {
				return "text"
			}
			return ""
		}, "says what the catalogue says again")
	return nil
}

func (messageSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, m := range f.Messages {
		if c, ok := p.planned("message", m.name()); !ok || c.Action == "delete" {
			continue
		}
		if err := store.SetOrgMessage(ctx, tx, orgID,
			store.OrgMessage{Locale: m.Locale, Key: m.Key, Body: m.Text}); err != nil {
			return err
		}
	}
	return nil
}

func (messageSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	locale, key, _ := strings.Cut(name, "/")
	_, err := store.RemoveOrgMessage(ctx, tx, orgID, locale, key)
	return err
}

func (messageSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.OrgMessages(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, m := range have {
		f.Messages = append(f.Messages, Message{Locale: m.Locale, Key: m.Key, Text: m.Body})
	}
	return nil
}
