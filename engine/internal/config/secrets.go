package config

import (
	"fmt"
	"regexp"
	"strings"

	"signari.dev/engine/internal/keys"
)

// Secrets in a configuration file (6.19).
//
// A file never holds one. A kind that needs one either has it minted by the
// engine when it is created, shown once by the apply as the command that
// registers it shows it, or names it by reference: an environment variable or
// a file, read by the command line on the machine the file is applied from.
//
// The Admin API refuses a reference. Read there, it would be read from the
// server's environment and disk and then sent, or used to sign what is sent,
// to a URL the caller chose: SIGNARI_ROOT_KEY to a SCIM target as its bearer
// token, for anybody holding organizations:write.

// SecretRef names a secret the file does not hold: exactly one of Env and
// File. A relative File is read from beside the configuration file.
type SecretRef struct {
	Env  string `yaml:"env,omitempty"`
	File string `yaml:"file,omitempty"`

	value    string
	resolved bool
}

// String says where the secret is read from, never what it is.
func (r SecretRef) String() string {
	if r.Env != "" {
		return "$" + r.Env
	}
	return r.File
}

// envName is what a reference may name: a variable, not an expression.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// check refuses a reference that names nothing, both things, or a setting the
// engine or its database connection reads. The engine's own configuration is
// never another system's secret, and a reviewer reading `{env:
// SIGNARI_ROOT_KEY}` beside a URL in a pull request is one approval from
// handing the key that seals everything to whoever runs that URL.
func (r *SecretRef) check(where string, add func(string, ...any)) {
	switch {
	case (r.Env == "") == (r.File == ""):
		add("%s: name the secret by env or by file, one of the two", where)
	case r.Env != "" && !envName.MatchString(r.Env):
		add("%s: env %q is not a variable name", where, r.Env)
	case strings.HasPrefix(r.Env, "SIGNARI_") || strings.HasPrefix(r.Env, "PG"):
		add("%s: %s is a setting of the engine or of its database connection, never another system's secret",
			where, r.Env)
	}
}

// secret is what the reference was resolved to, refused when nothing resolved
// it: the Admin API, or a caller that never asked.
func (r *SecretRef) secret(where string) (string, error) {
	if !r.resolved {
		return "", refuse("%s: the secret is named by reference (%s), which only `signari apply` reads, "+
			"on the machine the file is applied from", where, r)
	}
	return r.value, nil
}

// secretAt is one reference and where the file makes it.
type secretAt struct {
	where string
	ref   *SecretRef
}

// secretRefs is every reference the file makes.
func (f *File) secretRefs() []secretAt {
	var out []secretAt
	for _, w := range f.Providers {
		if w.Secret != nil {
			out = append(out, secretAt{w.where(), w.Secret})
		}
	}
	for _, w := range f.Subscriptions {
		if w.Secret != nil {
			out = append(out, secretAt{w.where(), w.Secret})
		}
	}
	// Both fields, whatever the kind: Validate refuses the one a kind does not
	// take, and a reference must be found wherever it is written.
	for _, w := range f.SCIMTargets {
		if w.Token != nil {
			out = append(out, secretAt{"scim_targets[" + w.Slug + "].token", w.Token})
		}
		if w.Credentials != nil {
			out = append(out, secretAt{"scim_targets[" + w.Slug + "].credentials", w.Credentials})
		}
	}
	for _, w := range f.RACConnections {
		if w.Login != nil {
			out = append(out, secretAt{w.at() + ".login", w.Login})
		}
		if w.Password != nil {
			out = append(out, secretAt{w.at() + ".password", w.Password})
		}
	}
	for _, w := range f.IdentityProviders {
		if w.ClientSecret != nil {
			out = append(out, secretAt{w.at() + ".client_secret", w.ClientSecret})
		}
	}
	return out
}

// SecretReferences says where the file names a secret by reference, for a
// caller that must not read one.
func (f *File) SecretReferences() []string {
	var out []string
	for _, s := range f.secretRefs() {
		out = append(out, s.where)
	}
	return out
}

// ResolveSecrets reads every secret the file names by reference with read,
// refusing one that is empty: a secret nobody set is not a secret.
func (f *File) ResolveSecrets(read func(SecretRef) (string, error)) error {
	for _, s := range f.secretRefs() {
		v, err := read(*s.ref)
		if err != nil {
			return fmt.Errorf("%s: %w", s.where, err)
		}
		if v == "" {
			return fmt.Errorf("%s: %s is empty", s.where, s.ref)
		}
		s.ref.value, s.ref.resolved = v, true
	}
	return nil
}

// Options are what a plan needs besides the file and the deployment.
type Options struct {
	// Root seals the secret of a thing the plan creates or gives a new one,
	// and opens the one a thing holds to compare with the secret a file names.
	// Without it a plan that would need it is refused, with the reason.
	Root *keys.RootKey
}

// Minted is a secret the engine made for something the apply created, shown
// this once: it is sealed, and nothing reads it back.
type Minted struct {
	Kind, Name, Secret string
}

// needsRoot refuses a change the plan cannot make without the root key.
func (p *Plan) needsRoot(kind, name, why string) error {
	if p.opts.Root != nil {
		return nil
	}
	return refuse("%s %s: %s needs SIGNARI_ROOT_KEY, which is not loaded here", kind, name, why)
}
