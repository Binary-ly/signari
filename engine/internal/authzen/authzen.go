package authzen

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The OpenID AuthZEN Authorization API 1.0 wire format.
//
// Final on 12 January 2026. The shapes here are the specification's, field for
// field, because a PDP that speaks nearly the standard is a PDP every client
// library has to be patched for.
//
// # The one thing implementations get wrong
//
// A DENIAL is 200 with {"decision": false}. Not 403. The HTTP status describes
// whether the request was processed, not what the answer was -- a PDP that
// returns 403 for "no" is indistinguishable from one that is refusing to talk
// to the caller at all, and the caller cannot tell an authorization decision
// from an authentication failure. See Decide and the handler.

// Subject is who is asking.
type Subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is what they are asking about.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is what they want to do. `name`, not `id` -- the spec differs from
// Subject and Resource here, and matching it is not optional.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Request is POST /access/v1/evaluation.
type Request struct {
	Subject  Subject        `json:"subject"`
	Resource Resource       `json:"resource"`
	Action   Action         `json:"action"`
	Context  map[string]any `json:"context,omitempty"`
}

// Response is the answer.
type Response struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// Evaluations is POST /access/v1/evaluations -- the batch form.
//
// The top-level subject/resource/action are DEFAULTS; each entry overrides the
// parts it sets. That is what makes the batch worth having: twenty questions
// about one subject carry the subject once.
type Evaluations struct {
	Subject     *Subject       `json:"subject,omitempty"`
	Resource    *Resource      `json:"resource,omitempty"`
	Action      *Action        `json:"action,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
	Options     *Options       `json:"options,omitempty"`
	Evaluations []Request      `json:"evaluations"`
}

// Options controls how far the batch runs.
type Options struct {
	Semantic string `json:"evaluations_semantic,omitempty"`
}

// The batch semantics the specification defines.
const (
	// ExecuteAll evaluates everything. The default.
	ExecuteAll = "execute_all"
	// DenyOnFirstDeny stops at the first false.
	DenyOnFirstDeny = "deny_on_first_deny"
	// PermitOnFirstPermit stops at the first true.
	PermitOnFirstPermit = "permit_on_first_permit"
)

// EvaluationsResponse is the batch answer.
type EvaluationsResponse struct {
	Evaluations []Response `json:"evaluations"`
}

// SearchRequest is any of the three search endpoints.
//
// One struct for all three because the shapes differ only in which fields are
// partially specified, and three near-identical structs is three places to fix
// a field name.
type SearchRequest struct {
	Subject  *Subject       `json:"subject,omitempty"`
	Resource *Resource      `json:"resource,omitempty"`
	Action   *Action        `json:"action,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
	Page     *PageRequest   `json:"page,omitempty"`
}

// PageRequest asks for a page.
type PageRequest struct {
	Token      string         `json:"token,omitempty"`
	Limit      int            `json:"limit,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// SearchResponse is a page of results.
type SearchResponse struct {
	Page    *PageResponse  `json:"page,omitempty"`
	Context map[string]any `json:"context,omitempty"`
	Results []Item         `json:"results"`
}

// PageResponse describes the page returned.
type PageResponse struct {
	NextToken  string         `json:"next_token,omitempty"`
	Count      int            `json:"count,omitempty"`
	Total      int            `json:"total,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Item is one search result.
//
// The specification uses DIFFERENT shapes for different searches: subject and
// resource results carry `type` and `id`, action results carry `name` alone
// (sections 8.5.2 and 8.6.2). One struct with omitempty on each, because two
// structs is two places for a field name to drift -- and a client parsing
// action results looks for `name` and finds nothing if we send `id`.
type Item struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Reasons builds the response context the specification's example shows.
//
// TWO reasons, deliberately: one for the administrator and one for the user.
// Collapsing them means either the user is told which policy refused them --
// which tells an attacker what to change -- or the administrator is told
// "insufficient privileges", which tells them nothing at all. Every PDP that
// logs one string has picked one of those failures.
func Reasons(admin, user string) map[string]any {
	ctx := map[string]any{}
	if admin != "" {
		ctx["reason_admin"] = map[string]any{"403": admin}
	}
	if user != "" {
		ctx["reason_user"] = map[string]any{"403": user}
	}
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

// Ref is `type:id`, the form relations are stored in.
func Ref(typ, id string) string { return typ + ":" + id }

// ParseRef splits it again.
func ParseRef(ref string) (typ, id string, ok bool) {
	typ, id, ok = strings.Cut(ref, ":")
	if !ok || typ == "" || id == "" {
		return "", "", false
	}
	return typ, id, true
}

// Validate refuses a request that cannot be answered.
//
// Refused rather than denied. "No" and "that question was malformed" are
// different answers, and a PDP that returns false for both teaches callers that
// a denial might just mean they sent the wrong shape -- after which nobody
// trusts a denial.
func (r Request) Validate() error {
	var missing []string
	if r.Subject.Type == "" {
		missing = append(missing, "subject.type")
	}
	if r.Subject.ID == "" {
		missing = append(missing, "subject.id")
	}
	if r.Action.Name == "" {
		missing = append(missing, "action.name")
	}
	if r.Resource.Type == "" {
		missing = append(missing, "resource.type")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the request is missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// Merge applies batch defaults to one entry.
//
// Field by field rather than "use the default if the whole object is absent":
// an entry that sets only resource.id must still inherit resource.type, and an
// all-or-nothing merge would leave it typeless and unmatchable.
func (r Request) Merge(d Evaluations) Request {
	if d.Subject != nil {
		if r.Subject.Type == "" {
			r.Subject.Type = d.Subject.Type
		}
		if r.Subject.ID == "" {
			r.Subject.ID = d.Subject.ID
		}
		if r.Subject.Properties == nil {
			r.Subject.Properties = d.Subject.Properties
		}
	}
	if d.Resource != nil {
		if r.Resource.Type == "" {
			r.Resource.Type = d.Resource.Type
		}
		if r.Resource.ID == "" {
			r.Resource.ID = d.Resource.ID
		}
		if r.Resource.Properties == nil {
			r.Resource.Properties = d.Resource.Properties
		}
	}
	if d.Action != nil && r.Action.Name == "" {
		r.Action.Name = d.Action.Name
		if r.Action.Properties == nil {
			r.Action.Properties = d.Action.Properties
		}
	}
	if r.Context == nil {
		r.Context = d.Context
	}
	return r
}

// Decode reads a request body, refusing anything unexpected.
//
// Unknown fields are an ERROR. A caller who sends `subjects` instead of
// `subject` must be told, rather than receiving a confident denial about a
// subject we never saw.
func Decode(body []byte, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("the request body did not parse: %w", err)
	}
	return nil
}
