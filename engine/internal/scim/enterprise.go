package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The enterprise user extension, onto the organisation's own user attributes.
//
// Not columns: a department is what an organisation says it is. An attribute it
// has declared already has a type, a decision about whether it is personal and
// so sealed under the subject's key, and a way to reach a token through a claim
// mapper, and none of that has to be decided again here. One it has not declared
// is not stored, as a phone number is not, because a value nobody has decided
// anything about has no erasure story.

// EnterpriseSchema is the extension's URN.
const EnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// EnterpriseAttributes are the extension's attributes and the user attribute
// each is held in, whose names are lower-case by constraint.
var EnterpriseAttributes = []struct{ SCIM, Attribute string }{
	{"employeeNumber", "employee_number"},
	{"costCenter", "cost_center"},
	{"organization", "organization"},
	{"division", "division"},
	{"department", "department"},
	{"manager", "manager"},
}

func enterpriseAttribute(name string) (string, bool) {
	for _, a := range EnterpriseAttributes {
		if strings.EqualFold(a.SCIM, name) {
			return a.Attribute, true
		}
	}
	return "", false
}

// enterprisePath reads a path inside the extension: what follows its URN, which
// is empty for the extension whole. A PATCH names it in full (specs/rfc7644.txt:1911).
func enterprisePath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if len(p) < len(EnterpriseSchema) || !strings.EqualFold(p[:len(EnterpriseSchema)], EnterpriseSchema) {
		return "", false
	}
	rest := p[len(EnterpriseSchema):]
	if rest == "" {
		return "", true
	}
	if rest[0] != ':' {
		return "", false
	}
	return rest[1:], true
}

// assignEnterprise records a value, nil to clear it.
func (p *UserPatch) assignEnterprise(attr string, raw json.RawMessage) error {
	if attr == "" {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return fmt.Errorf("the enterprise extension is an object: %w", err)
		}
		for k, v := range object {
			if err := p.assignEnterprise(k, v); err != nil {
				return err
			}
		}
		return nil
	}
	name, sub, _ := strings.Cut(attr, ".")
	target, known := enterpriseAttribute(name)
	switch {
	case !known, sub != "" && !(target == "manager" && strings.EqualFold(sub, "value")):
		// The manager's displayName and $ref are read from the manager.
		p.Unsupported = append(p.Unsupported, EnterpriseSchema+":"+attr)
		return nil
	}
	value, err := parseEnterpriseValue(target, raw)
	if err != nil {
		return fmt.Errorf("%s: %w", attr, err)
	}
	if p.Enterprise == nil {
		p.Enterprise = map[string]*string{}
	}
	p.Enterprise[target] = value
	return nil
}

func (p *UserPatch) removeEnterprise(attr string) {
	if p.Enterprise == nil {
		p.Enterprise = map[string]*string{}
	}
	if attr == "" {
		for _, a := range EnterpriseAttributes {
			p.Enterprise[a.Attribute] = nil
		}
		return
	}
	name, _, _ := strings.Cut(attr, ".")
	if target, ok := enterpriseAttribute(name); ok {
		p.Enterprise[target] = nil
		return
	}
	p.Unsupported = append(p.Unsupported, EnterpriseSchema+":"+attr)
}

// parseEnterpriseValue reads a string, or for the manager whatever an upstream
// sends for one: a bare id, an object with a value, or an array of one. Null and
// an empty value clear it (specs/rfc7644.txt:1652).
func parseEnterpriseValue(target string, raw json.RawMessage) (*string, error) {
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil {
		if target != "manager" {
			return nil, fmt.Errorf("%s is not a string", string(raw))
		}
		if s, err = parseManager(raw); err != nil {
			return nil, err
		}
	}
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil, nil
	}
	v := strings.TrimSpace(*s)
	return &v, nil
}

func parseManager(raw json.RawMessage) (*string, error) {
	type reference struct {
		Value *string `json:"value"`
	}
	var one reference
	if err := json.Unmarshal(raw, &one); err == nil {
		return one.Value, nil
	}
	var many []reference
	if err := json.Unmarshal(raw, &many); err != nil || len(many) > 1 {
		return nil, fmt.Errorf("%s is not a manager", string(raw))
	}
	if len(many) == 0 {
		return nil, nil
	}
	return many[0].Value, nil
}

// EnterpriseValues reads the extension of a whole resource, nil when it was not
// sent. replacing is PUT, where an attribute left out of it is cleared. The
// extension left out altogether is not: a client that does not send it may not
// understand it, which the RFC lets a server weigh (specs/rfc7644.txt:1646).
func (u User) EnterpriseValues(replacing bool) (map[string]*string, error) {
	if u.Enterprise == nil {
		return nil, nil
	}
	p := &UserPatch{}
	if replacing {
		p.removeEnterprise("")
	}
	if err := p.assignEnterprise("", u.Enterprise); err != nil {
		return nil, err
	}
	return p.Enterprise, nil
}
