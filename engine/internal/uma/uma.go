// Package uma implements the UMA 2.0 grant.
//
// User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization, Kantara
// Recommendation, 7 January 2018.
//
// # What it adds to OAuth, in one sentence
//
// A resource server can ask this server what a caller would need, hand the
// caller an opaque ticket describing it, and let the caller come back with that
// ticket for a token scoped to exactly those permissions -- so the resource
// server never holds the policy.
//
//	client -> RS        (no token, or not enough)
//	RS     -> AS        POST /uma2/permission   {resource, scopes}  -> ticket
//	RS     -> client    401 + WWW-Authenticate: UMA as_uri=..., ticket=...
//	client -> AS        grant_type=urn:...:uma-ticket, ticket=...   -> RPT
//	client -> RS        Authorization: Bearer <RPT>
//
// # Where the decision comes from
//
// From internal/authzen, the same policy decision point that answers
// /access/v1/evaluation. UMA is a way of ASKING; it is not a second opinion
// about who may do what. A separate policy engine behind this endpoint would be
// a second answer to the same question, and the two would eventually disagree
// about something that matters.
//
// # What is implemented, and what is not
//
// Implemented: the permission endpoint, the `uma-ticket` grant, single-use
// tickets, and `request_denied` when policy refuses.
//
// NOT implemented, and therefore not advertised: pushed claims (`claim_token`),
// persisted claims tokens (`pct`), RPT upgrade (`rpt`), and interactive claims
// gathering -- which means `need_info` and `request_submitted` are never
// returned. Those need a claims interaction endpoint and a notion of a pending
// resource-owner decision; this server answers from policy alone, immediately.
// A client sending `claim_token` is refused rather than ignored, because a
// client that pushes claims and receives a token reasonably concludes the claims
// were considered.
package uma

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GrantType is §3.3.1's value.
const GrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

// TicketLifetime bounds how long a permission ticket is good for.
//
// Short, because the ticket exists only to cross from the resource server to the
// client and back. Anything longer is a window in which a ticket captured from a
// 401 response still works.
const TicketLifetime = 2 * time.Minute

// MaxPermissions bounds one request. A permission ticket naming a thousand
// resources is a thousand policy evaluations on the token endpoint's critical
// path, requested by whoever can reach the permission endpoint.
const MaxPermissions = 32

// Permission is one {resource, scopes} entry.
//
// `resource_type` is ours, and it is not in the specification. UMA identifies a
// resource by an opaque `resource_id` issued by the resource registration
// endpoint (Federated Authorization §2), which we do not implement -- so there is
// nothing that would tell us what KIND of thing an id refers to, and our
// authorization model is typed. Requiring the type is the honest way to bridge
// that: the alternative is a registration endpoint whose only purpose is to
// remember a string.
type Permission struct {
	ResourceType   string   `json:"resource_type"`
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

// Error is a token endpoint failure specific to this grant.
//
// §3.3.6 assigns 403 to need_info, request_denied and request_submitted, and
// 400 to invalid_grant. A client cannot act on the difference if everything is
// 400: request_denied is final, invalid_grant means fetch a new ticket.
type Error struct {
	Code        string
	Description string
	Status      int
	// Ticket accompanies need_info and request_submitted. Unused today; the
	// field exists so adding those does not change this type's shape.
	Ticket string
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

// Errors defined by §3.3.6.
func Denied(desc string) *Error {
	return &Error{Code: "request_denied", Description: desc, Status: http.StatusForbidden}
}

func InvalidGrant(desc string) *Error {
	return &Error{Code: "invalid_grant", Description: desc, Status: http.StatusBadRequest}
}

func InvalidRequest(desc string) *Error {
	return &Error{Code: "invalid_request", Description: desc, Status: http.StatusBadRequest}
}

// NewTicket mints a permission ticket.
//
// 32 bytes, the same width as an authorization code, because it is the same kind
// of thing: whoever holds it can obtain a token, subject to policy.
func NewTicket() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating a permission ticket: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ParsePermissions reads the permission endpoint's request body.
//
// Federated Authorization §3.1 allows a single object or an array of them; both
// are accepted, because a resource server asking about one resource should not
// have to wrap it.
func ParsePermissions(body []byte) ([]Permission, *Error) {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return nil, InvalidRequest("the permission request has no body")
	}

	var many []Permission
	if err := json.Unmarshal(body, &many); err != nil {
		var one Permission
		if err2 := json.Unmarshal(body, &one); err2 != nil {
			return nil, InvalidRequest("the permission request is neither a " +
				"permission object nor an array of them")
		}
		many = []Permission{one}
	}
	if len(many) == 0 {
		return nil, InvalidRequest("the permission request names no resources")
	}
	if len(many) > MaxPermissions {
		return nil, InvalidRequest(fmt.Sprintf(
			"a permission request may name at most %d resources; this one names %d",
			MaxPermissions, len(many)))
	}

	for i := range many {
		p := &many[i]
		p.ResourceType = strings.TrimSpace(p.ResourceType)
		p.ResourceID = strings.TrimSpace(p.ResourceID)
		if p.ResourceID == "" {
			return nil, InvalidRequest("a permission must name a resource_id")
		}
		if p.ResourceType == "" {
			return nil, InvalidRequest("a permission must name a resource_type: " +
				"this server's authorization model is typed, and \"document 42\" and " +
				"\"invoice 42\" are different things")
		}
		if len(p.ResourceScopes) == 0 {
			return nil, InvalidRequest("a permission must name at least one " +
				"resource_scope; asking for no scopes on a resource is not a question")
		}
		for _, s := range p.ResourceScopes {
			if strings.TrimSpace(s) == "" {
				return nil, InvalidRequest("a resource_scope may not be empty")
			}
		}
	}
	return many, nil
}

// Scopes flattens the permissions into the scope string an RPT carries.
//
// Formatted `type:id#scope`, which keeps the resource identity in the token
// rather than only the verb. A resource server receiving an RPT whose scope
// said merely `read` would have to trust that it was read on the right thing.
func Scopes(ps []Permission) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range ps {
		for _, s := range p.ResourceScopes {
			v := p.ResourceType + ":" + p.ResourceID + "#" + s
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}
