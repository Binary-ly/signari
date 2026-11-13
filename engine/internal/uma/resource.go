package uma

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"signari.dev/engine/internal/jsonstrict"
)

// A resource description (Federated Authorization §3.1, specs/uma-fedauthz.txt:209-231),
// as a resource server registers one.

// Bounds on a description. None is in the specification; each keeps what one
// resource server registers from being what every page that lists it carries.
const (
	MaxResourceScopes = 64
	maxScopeLength    = 256
	maxNameLength     = 256
	maxDescription    = 4096
)

// ResourceDescription is §3.1's document.
type ResourceDescription struct {
	// ResourceScopes is REQUIRED: the scopes available for this resource.
	ResourceScopes []string `json:"resource_scopes"`
	Description    string   `json:"description,omitempty"`
	IconURI        string   `json:"icon_uri,omitempty"`
	Name           string   `json:"name,omitempty"`
	// Type is OPTIONAL in the specification and required here: it names a type of
	// the organisation's authorization model, which is what decides about the
	// resource, and an untyped object is one no model can decide about.
	Type string `json:"type,omitempty"`
}

// ParseResourceDescription reads a create or update body, refusing what §3.2 has
// answered 400: a required parameter missing, a value that is not one, a parameter
// given twice (specs/uma-fedauthz.txt:263). A member it does not know is ignored, as
// the grant has a receiver do (specs/uma.txt §1.1).
func ParseResourceDescription(body []byte) (ResourceDescription, *Error) {
	if err := jsonstrict.NoDuplicateKeys(body); err != nil {
		return ResourceDescription{}, InvalidRequest(err.Error())
	}
	var d ResourceDescription
	if err := json.Unmarshal(body, &d); err != nil {
		return ResourceDescription{}, InvalidRequest("the body is not a resource description: " + err.Error())
	}
	d.Type, d.Name = strings.TrimSpace(d.Type), strings.TrimSpace(d.Name)
	switch {
	case len(d.ResourceScopes) == 0:
		return ResourceDescription{}, InvalidRequest("resource_scopes is required, and names at least one scope")
	case len(d.ResourceScopes) > MaxResourceScopes:
		return ResourceDescription{}, InvalidRequest(fmt.Sprintf("a resource may have at most %d scopes",
			MaxResourceScopes))
	case d.Type == "":
		return ResourceDescription{}, InvalidRequest("type is required here: it names the type of this " +
			"organisation's authorization model the resource is, which is what decides who may reach it")
	case len(d.Name) > maxNameLength || len(d.Description) > maxDescription:
		return ResourceDescription{}, InvalidRequest("the name or description is too long")
	}
	seen := map[string]bool{}
	for i, s := range d.ResourceScopes {
		s = strings.TrimSpace(s)
		switch {
		case s == "" || len(s) > maxScopeLength:
			return ResourceDescription{}, InvalidRequest("a resource scope is a string of 1 to 256 characters")
		case seen[s]:
			return ResourceDescription{}, InvalidRequest(fmt.Sprintf("the scope %q is named twice", s))
		}
		seen[s], d.ResourceScopes[i] = true, s
	}
	if d.IconURI != "" {
		if u, err := url.Parse(d.IconURI); err != nil || !u.IsAbs() || (u.Scheme != "https" && u.Scheme != "http") {
			return ResourceDescription{}, InvalidRequest("icon_uri is an absolute http or https URI")
		}
	}
	return d, nil
}
