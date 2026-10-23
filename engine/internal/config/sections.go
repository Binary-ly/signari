package config

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The kinds a configuration file declares beyond the five whose code is in
// config.go and apply.go (6.19). Each is a section in a file of its own, run by
// Validate, BuildPlan, Apply and Export in the order of sections, so adding a
// kind is a file and a line here rather than a branch in each of four
// functions.

// section is one kind of thing a file declares.
type section interface {
	// kind is the plan's Kind for it, and how a deletion finds its section.
	kind() string
	// first reports whether it is applied before the five built-in kinds,
	// which a client's scopes, for one, are checked against.
	first() bool
	validate(f *File, add func(format string, args ...any))
	// plan adds the section's creates and updates, and with prune its
	// deletions, to p. It may refuse a file the deployment cannot honour,
	// which Validate, holding no database, could not.
	plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error
	// apply makes the creates and updates p plans.
	apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error
	// remove makes one planned deletion.
	remove(ctx context.Context, tx pgx.Tx, orgID, name string) error
	export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error
}

// ErrRefused is a file the plan refuses because the deployment cannot honour
// it; the message says why. A caller answers it as the caller's mistake, not
// the server's.
var ErrRefused = errors.New("the configuration cannot be applied to this deployment")

type refusal struct{ msg string }

func (r refusal) Error() string        { return r.msg }
func (r refusal) Is(target error) bool { return target == ErrRefused }

func refuse(format string, args ...any) error { return refusal{fmt.Sprintf(format, args...)} }

// sections are applied in this order; one that names another's thing comes
// after it, and deletions run in reverse.
var sections = []section{
	scopeSection{},
	attributeSection{},
	resourceSection{},
	signupSection{},
	mapperSection{},
	accessPolicySection,
	signInFlowSection,
	promptSection{},
	providerSection{},
	subscriptionSection{},
}

// sectionOf is the section a plan's Kind belongs to, nil for a built-in kind.
func sectionOf(kind string) section {
	for _, s := range sections {
		if s.kind() == kind {
			return s
		}
	}
	return nil
}

// planKeyed adds a section's creates, updates and, with prune, deletions for
// things identified by a name: want is the file's, have the deployment's, and
// diff what differs between one of each, "" for nothing.
func planKeyed[W, H any](p *Plan, kind string, want map[string]W, have map[string]H, prune bool,
	diff func(have H, want W) string, gone string) {
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h, ok := have[n]
		if !ok {
			p.Add(Change{Action: "create", Kind: kind, Name: n})
			continue
		}
		if d := diff(h, want[n]); d != "" {
			p.Add(Change{Action: "update", Kind: kind, Name: n, Detail: d})
		}
	}
	if !prune {
		return
	}
	for n := range have {
		if _, ok := want[n]; !ok {
			p.Add(Change{Action: "delete", Kind: kind, Name: n, Destructive: true, Detail: gone})
		}
	}
}

// seen refuses a name given twice in one list of the file.
func seen(add func(string, ...any), key string) func(i int, name string) bool {
	names := map[string]bool{}
	return func(i int, name string) bool {
		switch {
		case name == "":
			add("%s[%d]: a name is required", key, i)
			return false
		case names[name]:
			add("%s[%d]: %q appears twice", key, i, name)
			return false
		}
		names[name] = true
		return true
	}
}

// changed names the fields that differ, for a plan's detail.
type changed []string

func (c *changed) note(differs bool, field string) {
	if differs {
		*c = append(*c, field)
	}
}

func (c changed) String() string { return strings.Join(c, ", ") }
