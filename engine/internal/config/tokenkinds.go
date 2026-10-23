package config

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// The last of an organisation's configuration (6.25): outposts and inbound
// SCIM sources, whose tokens the engine generates and keeps only hashed, so a
// file has them minted and shown once and can never choose one; Shared
// Signals streams and sources; and the authorization model.

// Outpost is a process run near the people it serves (an LDAP or RADIUS
// front, a proxy, a desktop agent, a policy point) that calls back with a
// token minted when it is registered.
type Outpost struct {
	Name string `yaml:"name"`
	// Kind is ldap, radius, proxy, desktop or pdp, fixed once made.
	Kind string `yaml:"kind"`
	// SearchGroup is whose members may search the whole directory through an
	// LDAP outpost; "" nobody. Left as it is when absent.
	SearchGroup *string `yaml:"search_group,omitempty"`
	Enabled     *bool   `yaml:"enabled,omitempty"`
}

type outpostSection struct{}

func (outpostSection) kind() string { return "outpost" }

// first is false: the search group may be one the file makes.
func (outpostSection) first() bool { return false }

func (outpostSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "outposts")
	for i, o := range f.Outposts {
		if !once(i, o.Name) {
			continue
		}
		if !slices.Contains(store.OutpostKinds, o.Kind) {
			add("outposts[%s]: kind is %s, not %q", o.Name, strings.Join(store.OutpostKinds, ", "), o.Kind)
		}
		if o.SearchGroup != nil && *o.SearchGroup != "" && o.Kind != "ldap" {
			add("outposts[%s]: a search group is an LDAP outpost's", o.Name)
		}
	}
}

const keptOutpost = "disabled rather than deleted: its token is refused from its next call"

func (outpostSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.Outposts(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(o store.Outpost) string { return o.Name })
	var groups []string
	for _, o := range f.Outposts {
		if h, ok := held[o.Name]; ok && h.Kind != o.Kind {
			return refuse("outposts[%s]: it is a %s outpost, and an outpost's kind is fixed once made", o.Name, h.Kind)
		}
		if o.SearchGroup != nil && *o.SearchGroup != "" {
			groups = append(groups, *o.SearchGroup)
		}
	}
	if missing, err := missingGroups(ctx, tx, orgID, f, prune, groups); err != nil {
		return err
	} else if len(missing) > 0 {
		return refuse("outposts: the organisation has no group %s; declare it in groups", strings.Join(missing, ", "))
	}
	planKeyed(p, "outpost", keyBy(f.Outposts, func(o Outpost) string { return o.Name }), held, false,
		func(h store.Outpost, w Outpost) string {
			var c changed
			c.note(w.SearchGroup != nil && h.SearchGroup != *w.SearchGroup, "search_group")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			return c.String()
		}, "")
	keepDisabled(p, "outpost", keyBy(f.Outposts, func(o Outpost) string { return o.Name }), held, prune,
		func(o store.Outpost) bool { return o.Enabled }, keptOutpost)
	minted(p, "outpost", "a token is minted and shown once")
	return nil
}

// keepDisabled plans switching off, rather than deleting, what a pruned file
// leaves out and is on.
func keepDisabled[W, H any](p *Plan, kind string, want map[string]W, have map[string]H, prune bool,
	on func(H) bool, detail string) {
	if !prune {
		return
	}
	for _, name := range sortedKeys(have) {
		if _, ok := want[name]; !ok && on(have[name]) {
			p.Add(Change{Action: "update", Kind: kind, Name: name, Detail: detail})
		}
	}
}

// minted says on each planned create of the kind that a token is minted.
func minted(p *Plan, kind, detail string) {
	for i, c := range p.Changes {
		if c.Kind == kind && c.Action == "create" {
			p.Changes[i].Detail = detail
		}
	}
}

func (outpostSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.Outposts(ctx, tx, orgID)
	if err != nil {
		return err
	}
	inFile := map[string]bool{}
	for _, o := range f.Outposts {
		inFile[o.Name] = true
		c, ok := p.planned("outpost", o.Name)
		if !ok {
			continue
		}
		if c.Action == "create" {
			group := ""
			if o.SearchGroup != nil {
				group = *o.SearchGroup
			}
			_, token, err := store.CreateOutpost(ctx, tx, orgID, o.Name, o.Kind, group)
			if err != nil {
				return refuse("outposts[%s]: %v", o.Name, err)
			}
			p.Minted = append(p.Minted, Minted{Kind: "outpost", Name: o.Name, Secret: token})
		} else if o.SearchGroup != nil {
			if err := store.SetOutpostSearchGroup(ctx, tx, orgID, o.Name, *o.SearchGroup); err != nil {
				return refuse("outposts[%s]: %v", o.Name, err)
			}
		}
		if o.Enabled != nil {
			if err := store.SetOutpostEnabled(ctx, tx, orgID, o.Name, *o.Enabled); err != nil {
				return err
			}
		}
	}
	for _, h := range have {
		if c, ok := p.planned("outpost", h.Name); ok && !inFile[h.Name] && c.Detail == keptOutpost {
			if err := store.SetOutpostEnabled(ctx, tx, orgID, h.Name, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (outpostSection) remove(context.Context, pgx.Tx, string, string) error {
	return errors.New("an outpost is disabled by a pruned file, never deleted")
}

// export leaves out the token, which is held only as a hash: applied
// elsewhere, each outpost is given a new one.
func (outpostSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.Outposts(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		group, enabled := h.SearchGroup, h.Enabled
		o := Outpost{Name: h.Name, Kind: h.Kind, Enabled: &enabled}
		if h.Kind == "ldap" {
			o.SearchGroup = &group
		}
		f.Outposts = append(f.Outposts, o)
	}
	return nil
}

// SCIMSource is an upstream that provisions people into the organisation over
// SCIM, with a bearer token minted when it is registered.
type SCIMSource struct {
	Slug string `yaml:"slug"`
	// Name and OnDelete (deactivate, the default, or delete) are fixed once
	// made.
	Name     string `yaml:"name,omitempty"`
	OnDelete string `yaml:"on_delete,omitempty"`
	Enabled  *bool  `yaml:"enabled,omitempty"`
}

func (s SCIMSource) onDelete() string {
	if s.OnDelete == "" {
		return "deactivate"
	}
	return s.OnDelete
}

type scimSourceSection struct{}

func (scimSourceSection) kind() string { return "scim_source" }
func (scimSourceSection) first() bool  { return false }

func (scimSourceSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "scim_sources")
	for i, s := range f.SCIMSources {
		if once(i, s.Slug) && s.onDelete() != "deactivate" && s.onDelete() != "delete" {
			add("scim_sources[%s]: %v", s.Slug, store.ErrSCIMSourceOnDelete)
		}
	}
}

const keptSCIMSource = "disabled rather than deleted: its links are who it provisioned"

func (scimSourceSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.SCIMSources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(s store.SCIMSourceRow) string { return s.Slug })
	for _, s := range f.SCIMSources {
		h, ok := held[s.Slug]
		if !ok {
			continue
		}
		if h.OnDelete != s.onDelete() || (s.Name != "" && h.Name != s.Name) {
			return refuse("scim_sources[%s]: its name and on_delete are fixed once registered (%s, %s); register "+
				"another under a new slug", s.Slug, h.Name, h.OnDelete)
		}
	}
	planKeyed(p, "scim_source", keyBy(f.SCIMSources, func(s SCIMSource) string { return s.Slug }), held, false,
		func(h store.SCIMSourceRow, w SCIMSource) string {
			if w.Enabled != nil && h.Enabled != *w.Enabled {
				return "enabled"
			}
			return ""
		}, "")
	keepDisabled(p, "scim_source", keyBy(f.SCIMSources, func(s SCIMSource) string { return s.Slug }), held, prune,
		func(s store.SCIMSourceRow) bool { return s.Enabled }, keptSCIMSource)
	minted(p, "scim_source", "a bearer token is minted and shown once")
	return nil
}

func (scimSourceSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.SCIMSources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	inFile := map[string]bool{}
	for _, s := range f.SCIMSources {
		inFile[s.Slug] = true
		c, ok := p.planned("scim_source", s.Slug)
		if !ok {
			continue
		}
		if c.Action == "create" {
			_, token, err := store.AddSCIMSource(ctx, tx, orgID, s.Slug, s.Name, s.onDelete())
			if err != nil {
				return refuse("scim_sources[%s]: %v", s.Slug, err)
			}
			p.Minted = append(p.Minted, Minted{Kind: "scim_source", Name: s.Slug, Secret: token})
		}
		if s.Enabled != nil {
			if err := store.SetSCIMSourceEnabledIn(ctx, tx, orgID, s.Slug, *s.Enabled); err != nil {
				return err
			}
		}
	}
	for _, h := range have {
		if c, ok := p.planned("scim_source", h.Slug); ok && !inFile[h.Slug] && c.Detail == keptSCIMSource {
			if err := store.SetSCIMSourceEnabledIn(ctx, tx, orgID, h.Slug, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (scimSourceSection) remove(context.Context, pgx.Tx, string, string) error {
	return errors.New("a SCIM source is disabled by a pruned file, never deleted")
}

func (scimSourceSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.SCIMSources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		enabled := h.Enabled
		f.SCIMSources = append(f.SCIMSources, SCIMSource{Slug: h.Slug, Name: h.Name, OnDelete: h.OnDelete,
			Enabled: &enabled})
	}
	return nil
}

// SSFStream is the Shared Signals stream a client receives security events
// on: pushed to its endpoint with the receiver's token, or polled.
type SSFStream struct {
	ClientID string `yaml:"client_id"`
	Endpoint string `yaml:"endpoint,omitempty"`
	// ReceiverToken is the receiver's bearer token for a push stream, by
	// reference; kept when left out, and needed again for a new endpoint.
	ReceiverToken *SecretRef `yaml:"receiver_token,omitempty"`
	// Events are what it is sent: session-revoked when absent.
	Events []string `yaml:"events,omitempty"`
	Poll   bool     `yaml:"poll,omitempty"`
}

func (s SSFStream) where() string { return "ssf_streams[" + s.ClientID + "].receiver_token" }

func (s SSFStream) spec() store.StreamSpec {
	spec := store.StreamSpec{ClientID: s.ClientID, Endpoint: s.Endpoint, Events: s.Events, Poll: s.Poll}
	if s.ReceiverToken != nil {
		spec.ReceiverToken = s.ReceiverToken.value
	}
	return spec
}

type ssfStreamSection struct{}

func (ssfStreamSection) kind() string { return "ssf_stream" }

// first is false: a stream is a client's, and the file may make the client.
func (ssfStreamSection) first() bool { return false }

func (ssfStreamSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "ssf_streams")
	for i, s := range f.SSFStreams {
		if !once(i, s.ClientID) {
			continue
		}
		spec := s.spec()
		if s.ReceiverToken != nil {
			spec.ReceiverToken = "stand-in"
			s.ReceiverToken.check(s.where(), add)
		}
		if err := spec.Validate(); err != nil {
			add("ssf_streams[%s]: %v", s.ClientID, err)
		}
	}
}

func (ssfStreamSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.Streams(ctx, tx, orgID, nil)
	if err != nil {
		return err
	}
	held := keyBy(have, func(s store.Stream) string { return s.ClientID })
	inFile := map[string]bool{}
	for _, c := range f.Clients {
		inFile[c.ClientID] = true
	}
	for _, s := range f.SSFStreams {
		if s.ReceiverToken != nil {
			if _, err := s.ReceiverToken.secret(s.where()); err != nil {
				return err
			}
		}
		h, ok := held[s.ClientID]
		if !ok && !inFile[s.ClientID] {
			var ours bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1 AND org_id = $2::uuid)`,
				s.ClientID, orgID).Scan(&ours); err != nil {
				return err
			}
			if !ours {
				return refuse("ssf_streams[%s]: %v", s.ClientID, store.ErrStreamClientElsewhere)
			}
		}
		if ok && !s.Poll && h.HasToken && s.ReceiverToken == nil && h.Endpoint != s.Endpoint {
			return refuse("ssf_streams[%s]: %v", s.ClientID, store.ErrStreamTokenForAnotherEndpoint)
		}
	}
	var failed error
	planKeyed(p, "ssf_stream", keyBy(f.SSFStreams, func(s SSFStream) string { return s.ClientID }), held, prune,
		func(h store.Stream, w SSFStream) string {
			events := w.Events
			if len(events) == 0 {
				events = []string{ssf.EventSessionRevoked}
			}
			method := "push"
			if w.Poll {
				method = "poll"
			}
			var c changed
			c.note(h.Method != method || h.Endpoint != w.Endpoint, "delivery")
			c.note(!sameSet(h.Events, events), "events")
			if w.ReceiverToken != nil && failed == nil {
				if failed = p.needsRoot("ssf_stream", w.ClientID, "comparing the token the file names"); failed == nil {
					var token string
					token, failed = store.StreamReceiverToken(ctx, tx, p.opts.Root, orgID, w.ClientID)
					c.note(token != w.ReceiverToken.value, "receiver_token")
				}
			}
			return c.String()
		}, "the receiver stops being told of sessions revoked and credentials changed")
	if failed != nil {
		return failed
	}
	for i, c := range p.Changes {
		if c.Kind != "ssf_stream" || c.Action != "create" {
			continue
		}
		if w := keyBy(f.SSFStreams, func(s SSFStream) string { return s.ClientID })[c.Name]; w.ReceiverToken != nil {
			p.Changes[i].Detail = "receiver token from " + w.ReceiverToken.String()
			if err := p.needsRoot("ssf_stream", c.Name, "sealing the receiver's token"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ssfStreamSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, s := range f.SSFStreams {
		c, ok := p.planned("ssf_stream", s.ClientID)
		if !ok || c.Action == "delete" {
			continue
		}
		var err error
		if c.Action == "create" {
			_, err = store.AddStream(ctx, tx, p.opts.Root, orgID, s.spec())
		} else {
			err = store.UpdateStream(ctx, tx, p.opts.Root, orgID, s.spec(), s.ReceiverToken != nil)
		}
		if err != nil {
			return refuse("ssf_streams[%s]: %v", s.ClientID, err)
		}
	}
	return nil
}

func (ssfStreamSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	return store.RemoveStream(ctx, tx, orgID, name)
}

// export leaves out the receiver's token.
func (ssfStreamSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.Streams(ctx, tx, orgID, nil)
	if err != nil {
		return err
	}
	for _, h := range have {
		f.SSFStreams = append(f.SSFStreams, SSFStream{ClientID: h.ClientID, Endpoint: h.Endpoint,
			Events: sortedCopy(h.Events), Poll: h.Method == "poll"})
	}
	return nil
}

// SSFSource is a Shared Signals transmitter whose events the organisation
// accepts: its issuer, where its keys are, and the audience its tokens are
// addressed to.
type SSFSource struct {
	Issuer   string `yaml:"issuer"`
	Name     string `yaml:"name"`
	JWKSURI  string `yaml:"jwks_uri"`
	Audience string `yaml:"audience"`
	// Events are what it may send, an allow-list.
	Events                 []string `yaml:"events"`
	CriticalSubjectMembers []string `yaml:"critical_subject_members,omitempty"`
	Enabled                *bool    `yaml:"enabled,omitempty"`
}

type ssfSourceSection struct{}

func (ssfSourceSection) kind() string { return "ssf_source" }
func (ssfSourceSection) first() bool  { return false }

func (ssfSourceSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "ssf_sources")
	for i, s := range f.SSFSources {
		if !once(i, s.Issuer) {
			continue
		}
		switch {
		case s.Name == "":
			add("ssf_sources[%s]: give a name", s.Issuer)
		case s.Audience == "":
			add("ssf_sources[%s]: give the audience: a token addressed to somebody else is not ours to act on, "+
				"however valid its signature", s.Issuer)
		case len(s.Events) == 0:
			add("ssf_sources[%s]: give the events: a source permitted to send nothing is not useful, and one "+
				"permitted to send everything is not what you meant", s.Issuer)
		}
		// Keys come from there, never from the token, through the dialer.
		if err := safedial.CheckURL(s.JWKSURI); err != nil {
			add("ssf_sources[%s]: the jwks_uri: %v", s.Issuer, err)
		}
	}
}

const keptSSFSource = "switched off rather than deleted: deleting it takes the record of what it sent"

func (ssfSourceSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.Sources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(s store.Source) string { return s.Issuer })
	planKeyed(p, "ssf_source", keyBy(f.SSFSources, func(s SSFSource) string { return s.Issuer }), held, false,
		func(h store.Source, w SSFSource) string {
			var c changed
			c.note(h.Name != w.Name || h.JWKSURI != w.JWKSURI || h.Audience != w.Audience, "source")
			c.note(!sameSet(h.Events, w.Events), "events")
			c.note(!sameSet(h.CriticalMembers, w.CriticalSubjectMembers), "critical_subject_members")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			return c.String()
		}, "")
	keepDisabled(p, "ssf_source", keyBy(f.SSFSources, func(s SSFSource) string { return s.Issuer }), held, prune,
		func(s store.Source) bool { return s.Enabled }, keptSSFSource)
	return nil
}

func (ssfSourceSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.Sources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(s store.Source) string { return s.Issuer })
	inFile := map[string]bool{}
	for _, s := range f.SSFSources {
		inFile[s.Issuer] = true
		if _, ok := p.planned("ssf_source", s.Issuer); !ok {
			continue
		}
		// The writer upserts and switches the source on, so one switched off
		// that the file says nothing about is switched off again.
		if err := store.AddSource(ctx, tx, orgID, s.Name, s.Issuer, s.JWKSURI, s.Audience, s.Events,
			s.CriticalSubjectMembers); err != nil {
			return refuse("ssf_sources[%s]: %v", s.Issuer, err)
		}
		h, existed := held[s.Issuer]
		if s.Enabled != nil && !*s.Enabled || s.Enabled == nil && existed && !h.Enabled {
			if err := store.SetSSFSourceEnabled(ctx, tx, orgID, s.Issuer, false); err != nil {
				return err
			}
		}
	}
	for _, h := range have {
		if c, ok := p.planned("ssf_source", h.Issuer); ok && !inFile[h.Issuer] && c.Detail == keptSSFSource {
			if err := store.SetSSFSourceEnabled(ctx, tx, orgID, h.Issuer, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ssfSourceSection) remove(context.Context, pgx.Tx, string, string) error {
	return errors.New("an SSF source is switched off by a pruned file, never deleted")
}

func (ssfSourceSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.Sources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		enabled := h.Enabled
		f.SSFSources = append(f.SSFSources, SSFSource{Issuer: h.Issuer, Name: h.Name, JWKSURI: h.JWKSURI,
			Audience: h.Audience, Events: sortedCopy(h.Events), CriticalSubjectMembers: sortedCopy(h.CriticalMembers),
			Enabled: &enabled})
	}
	return nil
}

// authorizationModelSection is the organisation's authorization model, one
// document kept as the text it was written in, as `signari authz model`
// applies it.
var authorizationModelSection = documentSection{
	name:  "authorization_model",
	field: func(f *File) **string { return &f.AuthorizationModel },
	parse: func(b []byte) error { _, err := authzen.ParseModel(b); return err },
	read: func(ctx context.Context, tx pgx.Tx, org string) (store.AppliedDocument, error) {
		source, err := store.ModelSource(ctx, tx, org)
		if err != nil || source == "" {
			return store.AppliedDocument{}, err
		}
		now := time.Now()
		return store.AppliedDocument{Document: source, AppliedAt: &now}, nil
	},
	write: func(ctx context.Context, tx pgx.Tx, org string, doc []byte) error {
		m, err := authzen.ParseModel(doc)
		if err != nil {
			return fmt.Errorf("the authorization model: %w", err)
		}
		return store.SaveModel(ctx, tx, org, string(doc), m, "")
	},
	table: "authorization_models",
	gone:  "no model is in force, so every relation check finds nothing to evaluate",
}
