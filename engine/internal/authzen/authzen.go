// Package authzen implements the OpenID AuthZEN Authorization API.
//
// Written against **Authorization API 1.0, Final, 11 January 2026**
// (https://openid.net/specs/authorization-api-1_0.html).
//
// The version is recorded here because it was not recorded anywhere before, and
// that is how the Implementer's Draft this was originally written against could
// be superseded by a Final specification with nothing in the tree noticing. A
// package that names the text it implements can be checked against it; one that
// does not can only be checked against somebody's memory.
package authzen

import (
	"encoding/json"
	"fmt"
	"strings"

	"signari.dev/engine/internal/jsonstrict"
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
	// NextToken is always present, and empty when the result set is exhausted.
	//
	// §8.2.2: "next_token: REQUIRED. An opaque string value indicating the next
	// page of results to return. If there are no more results after this page,
	// its value MUST be an empty string."
	//
	// It carried `omitempty`, so a final page omitted the field entirely. A PEP
	// following §8.2.2 tests `next_token === ""` to learn it is done; an absent
	// field reads as undefined, which is a different thing in every language a
	// client is written in. §8.2 pairs with this: "A paginated response MUST be
	// clearly identified by the inclusion of a page object containing a
	// NON-EMPTY, opaque next_token" -- so empty and absent are meant to be
	// distinguishable, and omitempty collapsed them.
	NextToken  string         `json:"next_token"`
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
	// Authorization API 1.0 (Final, 11 January 2026), Resource: "`id`:
	// REQUIRED. A string value containing the unique identifier of the
	// Resource, scoped to the `type`."
	//
	// This was deliberately NOT checked, on the reasoning that "a search or a
	// type-level question does not have one". Half of that is answered by the
	// code: a search is a SearchRequest, a different type that does not reach
	// here. The other half is answered by the specification, which puts
	// type-level questions in the Resource Search API rather than in an
	// evaluation.
	//
	// The consequence of omitting it was not a security hole -- store.HoldsAny
	// compares object_id for equality, so an absent id matches no relation and
	// the answer is a denial. It was worse than that in one specific way: the
	// caller got `decision: false` for a request that was malformed, which is
	// the exact failure the 400 above exists to avoid. As the handler puts it,
	// "a PDP that returns false for both teaches callers that a denial might
	// just mean they sent the wrong shape".
	if r.Resource.ID == "" {
		missing = append(missing, "resource.id")
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

// Decode reads a request body, tolerating fields it does not know.
//
// §10.1.1 makes that a requirement rather than a courtesy:
//
//	"To ensure forward compatibility, receivers MUST ignore unknown fields
//	present in request or response bodies."
//
// And §4 says a later revision "MAY augment this API... Augmentation MAY include
// additional API methods or additional parameters to existing API methods." So
// the specification both anticipates new parameters and requires a receiver to
// tolerate them.
//
// This used to call DisallowUnknownFields, which is the exact inverse. The
// reasoning was sound and the mechanism was not: a caller sending `subjects`
// instead of `subject` should be told rather than handed "a confident denial
// about a subject we never saw". But refusing the whole body is not what tells
// them. With the stray field ignored, `subject` is simply absent, and Validate
// answers with the error §10.1.1 requires for exactly that case --
//
//	"If a required attribute in the information model is omitted, the server
//	MUST return a "Bad Request" error"
//
// -- which names the attribute that is MISSING rather than the one that was
// misspelled, and is the more useful of the two messages.
//
// What is given up: a typo in an OPTIONAL field is now silent. That is the
// trade the specification makes on purpose, because the alternative refuses
// every PEP speaking a later revision of the API -- and refuses it with a 400,
// so the caller cannot even learn whether they would have been allowed.
func Decode(body []byte, into any) error {
	// Duplicate members are refused before anything reads the body.
	//
	// §10.1.1: "Implementations MUST NOT assume a particular ordering of JSON
	// object members." A body carrying `subject` twice has a meaning that
	// depends on exactly that ordering, so there is no reading of it this server
	// is entitled to pick -- which makes refusing the only correct answer.
	//
	// It is also the concrete attack. Go's decoder MERGES a repeated object into
	// the value already decoded, so
	//
	//	{"subject":{"type":"user","id":"alice"},"subject":{}}
	//
	// evaluates as alice, while a proxy, WAF or audit shipper that takes the
	// LAST occurrence sees an empty subject. The decision and the record of the
	// decision then describe different requests, which is the one thing an
	// authorization audit trail may not do.
	//
	// The same rule, for the same reason, as the duplicate-parameter check on
	// the pushed authorization request endpoint. Shared with the Security Event
	// Token receiver through internal/jsonstrict rather than copied.
	if err := jsonstrict.NoDuplicateKeys(body); err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("the request body did not parse: %w", err)
	}
	return nil
}
