package config

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// Remote-access connections in a configuration file (6.19): machines somebody
// may reach through the browser. What guacd signs in to the machine with is
// named by reference, compared when given, and never in an export.

// RACConnection is one machine.
type RACConnection struct {
	Slug string `yaml:"slug"`
	Name string `yaml:"name,omitempty"`
	// Protocol is rdp, vnc or ssh, fixed once made.
	Protocol string `yaml:"protocol"`
	Host     string `yaml:"host"`
	// Port is the protocol's own when absent.
	Port int `yaml:"port,omitempty"`
	// Login and Password are compared and replaced together, each by
	// reference; neither leaves what the connection holds.
	Login    *SecretRef `yaml:"login,omitempty"`
	Password *SecretRef `yaml:"password,omitempty"`
	// RequireGroup limits it to one group's members, "" to everybody in the
	// organisation; RecordingPath is where guacd records its sessions, ""
	// for nowhere. Each left as it is when absent.
	RequireGroup  *string `yaml:"require_group,omitempty"`
	RecordingPath *string `yaml:"recording_path,omitempty"`
	// Parameters are guacd's, never one the connection's own settings supply.
	Parameters *map[string]string `yaml:"parameters,omitempty"`
	Enabled    *bool              `yaml:"enabled,omitempty"`
}

func (w RACConnection) at() string { return "rac_connections[" + w.Slug + "]" }

// credentials are the login and password the file names, resolved; nil when
// it names neither.
func (w RACConnection) credentials() *store.RACCredentials {
	if w.Login == nil && w.Password == nil {
		return nil
	}
	var c store.RACCredentials
	if w.Login != nil {
		c.Login = w.Login.value
	}
	if w.Password != nil {
		c.Password = w.Password.value
	}
	return &c
}

func (w RACConnection) source() string {
	var from []string
	for _, r := range []*SecretRef{w.Login, w.Password} {
		if r != nil {
			from = append(from, r.String())
		}
	}
	return strings.Join(from, " and ")
}

type racSection struct{}

func (racSection) kind() string { return "rac_connection" }

// first is false: a connection may be limited to a group the file makes.
func (racSection) first() bool { return false }

func (racSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "rac_connections")
	for i, w := range f.RACConnections {
		if !once(i, w.Slug) {
			continue
		}
		switch {
		case w.Protocol != "rdp" && w.Protocol != "vnc" && w.Protocol != "ssh":
			add("%s: protocol is rdp, vnc or ssh, not %q", w.at(), w.Protocol)
		case strings.TrimSpace(w.Host) == "":
			add("%s: give the host to connect to", w.at())
		case w.Port < 0 || w.Port > 65535:
			add("%s: port %d is not one", w.at(), w.Port)
		}
		if w.Parameters != nil {
			for k := range *w.Parameters {
				if slices.Contains(store.RACReservedParameters, k) {
					add("%s: %s is not a parameter: the connection's own settings supply it", w.at(), k)
				}
			}
		}
		if w.Login != nil {
			w.Login.check(w.at()+".login", add)
		}
		if w.Password != nil {
			w.Password.check(w.at()+".password", add)
		}
	}
}

// keptConnection is the plan's detail for a connection a pruned file leaves
// out.
const keptConnection = "disabled rather than deleted: its sessions are the record of who reached that machine"

func (racSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.RACConnections(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(c store.RACListing) string { return c.Slug })
	var groups []string
	for _, w := range f.RACConnections {
		for _, r := range []struct {
			ref   *SecretRef
			where string
		}{{w.Login, w.at() + ".login"}, {w.Password, w.at() + ".password"}} {
			if r.ref != nil {
				if _, err := r.ref.secret(r.where); err != nil {
					return err
				}
			}
		}
		if w.RequireGroup != nil && *w.RequireGroup != "" {
			groups = append(groups, *w.RequireGroup)
		}
		h, ok := held[w.Slug]
		if !ok {
			continue
		}
		if h.Protocol != w.Protocol {
			return refuse("%s: it is an %s connection, and a connection's protocol is fixed once made; register "+
				"the %s one under another slug", w.at(), h.Protocol, w.Protocol)
		}
		moved := h.Host != w.Host || (w.Port != 0 && h.Port != w.Port)
		if moved && h.HasLogin && w.credentials() == nil {
			return refuse("%s: %v", w.at(), store.ErrRACCredentialsForAnotherMachine)
		}
	}
	if missing, err := missingGroups(ctx, tx, orgID, f, prune, groups); err != nil {
		return err
	} else if len(missing) > 0 {
		return refuse("rac_connections: the organisation has no group %s to limit a connection to; declare it "+
			"in groups", strings.Join(missing, ", "))
	}

	var failed error
	planKeyed(p, "rac_connection", keyBy(f.RACConnections, func(w RACConnection) string { return w.Slug }), held,
		false, func(h store.RACListing, w RACConnection) string {
			var c changed
			c.note(w.Name != "" && h.Name != w.Name, "name")
			c.note(h.Host != w.Host, "host")
			c.note(w.Port != 0 && h.Port != w.Port, "port")
			c.note(w.RequireGroup != nil && h.RequireGroup != *w.RequireGroup, "require_group")
			c.note(w.Parameters != nil && !maps.Equal(h.Parameters, *w.Parameters), "parameters")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			if w.RecordingPath != nil && failed == nil {
				var path string
				path, failed = store.RACRecordingPath(ctx, tx, orgID, w.Slug)
				c.note(path != *w.RecordingPath, "recording_path")
			}
			if want := w.credentials(); want != nil && failed == nil {
				if failed = p.needsRoot("rac_connection", w.Slug, "comparing the credentials the file names"); failed == nil {
					var have store.RACCredentials
					have, failed = store.HeldRACCredentials(ctx, tx, p.opts.Root, orgID, w.Slug)
					c.note(have != *want, "credentials")
				}
			}
			return c.String()
		}, "")
	if failed != nil {
		return failed
	}
	if prune {
		inFile := keyBy(f.RACConnections, func(w RACConnection) string { return w.Slug })
		for _, h := range have {
			if _, ok := inFile[h.Slug]; !ok && h.Enabled {
				p.Add(Change{Action: "update", Kind: "rac_connection", Name: h.Slug, Detail: keptConnection})
			}
		}
	}
	inFile := keyBy(f.RACConnections, func(w RACConnection) string { return w.Slug })
	for i, c := range p.Changes {
		if c.Kind != "rac_connection" || c.Action != "create" {
			continue
		}
		w := inFile[c.Name]
		if w.credentials() == nil {
			p.Changes[i].Detail = "holds no credentials"
			continue
		}
		p.Changes[i].Detail = "credentials from " + w.source()
		if err := p.needsRoot("rac_connection", c.Name, "sealing its credentials"); err != nil {
			return err
		}
	}
	return nil
}

func (racSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.RACConnections(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(c store.RACListing) string { return c.Slug })
	inFile := map[string]bool{}
	for _, w := range f.RACConnections {
		inFile[w.Slug] = true
		c, ok := p.planned("rac_connection", w.Slug)
		if !ok {
			continue
		}
		if c.Action == "create" {
			spec := store.RACSpec{Slug: w.Slug, Name: w.Name, Protocol: w.Protocol, Host: w.Host, Port: w.Port}
			if creds := w.credentials(); creds != nil {
				spec.Login, spec.Password = creds.Login, creds.Password
			}
			if w.RequireGroup != nil {
				spec.RequireGroup = *w.RequireGroup
			}
			if w.RecordingPath != nil {
				spec.RecordingPath = *w.RecordingPath
			}
			if _, err := store.AddRACConnection(ctx, tx, p.opts.Root, orgID, spec); err != nil {
				return err
			}
		} else {
			change := store.RACChange{Host: &w.Host, RequireGroup: w.RequireGroup, RecordingPath: w.RecordingPath,
				Credentials: w.credentials()}
			if w.Name != "" {
				change.Name = &w.Name
			}
			if w.Port != 0 {
				change.Port = &w.Port
			}
			if err := store.UpdateRACConnection(ctx, tx, p.opts.Root, orgID, w.Slug, change); err != nil {
				return err
			}
		}
		if w.Parameters != nil {
			if err := store.SetRACParameters(ctx, tx, orgID, w.Slug, *w.Parameters); err != nil {
				return err
			}
		}
		if w.Enabled != nil {
			if err := store.SetRACEnabled(ctx, tx, orgID, w.Slug, *w.Enabled); err != nil {
				return err
			}
		}
	}
	for slug := range held {
		if c, ok := p.planned("rac_connection", slug); ok && !inFile[slug] && c.Detail == keptConnection {
			if err := store.SetRACEnabled(ctx, tx, orgID, slug, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// remove is never planned: a pruned connection is switched off, not deleted.
func (racSection) remove(context.Context, pgx.Tx, string, string) error {
	return fmt.Errorf("a remote-access connection is disabled by a pruned file, never deleted")
}

// export leaves out the credentials; applied elsewhere, the file names them
// by reference or the connection holds none.
func (racSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.RACConnections(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		path, err := store.RACRecordingPath(ctx, tx, orgID, h.Slug)
		if err != nil {
			return err
		}
		group, params, enabled := h.RequireGroup, h.Parameters, h.Enabled
		f.RACConnections = append(f.RACConnections, RACConnection{Slug: h.Slug, Name: h.Name, Protocol: h.Protocol,
			Host: h.Host, Port: h.Port, RequireGroup: &group, RecordingPath: &path, Parameters: &params,
			Enabled: &enabled})
	}
	return nil
}
