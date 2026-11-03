// Package oid4vp is the verifier's half of OpenID for Verifiable Presentations
// 1.0 (specs/oid4vp.txt): the query a wallet is asked, the request object that
// carries it, and the checks a presentation must pass before anybody is signed
// in by it (12.12).
//
// One credential, of one format: an IETF SD-JWT VC, `dc+sd-jwt`
// (specs/oid4vp.txt:3479-3481), always with key binding. A presentation without
// a Key Binding JWT can be replayed by anybody who has seen it once (:1950-1956),
// which for signing somebody in is the whole of the attack, so this verifier
// never asks for one and never accepts one.
package oid4vp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Format is the credential format asked for, B.3.1.
const Format = "dc+sd-jwt"

// Ask is what a verifier asks a wallet for: one credential of one of the
// accepted types, carrying the claims it needs.
type Ask struct {
	// ID names the credential in the query and in the vp_token that answers it.
	ID string
	// VCTValues are the credential types accepted, B.3.5's vct_values.
	VCTValues []string
	// Claims are the claims asked for. Each is requested, and each must be in
	// what comes back.
	Claims []Path
}

// Path is a claims path pointer: "a non-empty array of strings, nulls and
// non-negative integers" (specs/oid4vp.txt:1115).
type Path []any

// ParsePath reads a path as an operator writes it: a JSON array such as
// ["address","country"], or a bare name for a top-level claim.
func ParsePath(s string) (Path, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("a claim path is empty")
	}
	if !strings.HasPrefix(s, "[") {
		return Path{s}, nil
	}
	var raw []any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("claim path %s is not a JSON array: %w", s, err)
	}
	p := make(Path, 0, len(raw))
	for _, c := range raw {
		switch v := c.(type) {
		case string, nil:
			p = append(p, v)
		case json.Number:
			n, err := v.Int64()
			if err != nil || n < 0 {
				return nil, fmt.Errorf("claim path %s holds %s, and an index is a non-negative integer", s, v)
			}
			p = append(p, int(n))
		default:
			return nil, fmt.Errorf("claim path %s holds %v, which is not a string, null or index", s, c)
		}
	}
	if err := p.valid(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p Path) valid() error {
	if len(p) == 0 {
		return fmt.Errorf("a claim path is empty")
	}
	for _, c := range p {
		switch v := c.(type) {
		case string, nil:
		case int:
			if v < 0 {
				return fmt.Errorf("claim path %s has a negative index", p)
			}
		default:
			return fmt.Errorf("claim path %s holds %v", p, c)
		}
	}
	return nil
}

// String is the path as JSON, as an operator wrote it.
func (p Path) String() string {
	b, err := json.Marshal([]any(p))
	if err != nil {
		return fmt.Sprint([]any(p))
	}
	return string(b)
}

// Validate refuses an ask no wallet could answer, and one this verifier could
// not check.
func (a Ask) Validate() error {
	if !queryID(a.ID) {
		return fmt.Errorf("the credential query id %q must be letters, digits, _ and - "+
			"(specs/oid4vp.txt:806-808)", a.ID)
	}
	if len(a.VCTValues) == 0 {
		return fmt.Errorf("name at least one credential type: vct_values is REQUIRED " +
			"(specs/oid4vp.txt:3612-3614)")
	}
	for _, v := range a.VCTValues {
		if v == "" {
			return fmt.Errorf("an empty credential type")
		}
	}
	seen := map[string]bool{}
	for _, p := range a.Claims {
		if err := p.valid(); err != nil {
			return err
		}
		// "Verifiers MUST NOT point to the same claim more than once in a single
		// query" (specs/oid4vp.txt:850-851).
		if seen[p.String()] {
			return fmt.Errorf("claim %s is asked for twice", p)
		}
		seen[p.String()] = true
	}
	return nil
}

// queryID is a credential query id: "a non-empty string consisting of
// alphanumeric, underscore (_), or hyphen (-) characters".
func queryID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Query is the DCQL query for a (specs/oid4vp.txt:780-858). It asks for key
// binding by leaving require_cryptographic_holder_binding at its default, true
// (:840-845), and leaves out claim_sets, so every claim listed is asked for
// (:1032-1033).
func (a Ask) Query() map[string]any {
	cq := map[string]any{
		"id":     a.ID,
		"format": Format,
		"meta":   map[string]any{"vct_values": a.VCTValues},
	}
	if len(a.Claims) > 0 {
		claims := make([]any, 0, len(a.Claims))
		for _, p := range a.Claims {
			claims = append(claims, map[string]any{"path": []any(p)})
		}
		cq["claims"] = claims
	}
	return map[string]any{"credentials": []any{cq}}
}

// Select applies a claims path pointer to a processed credential, section 7.1.1
// (specs/oid4vp.txt:1140-1168), and returns what it selects. An empty selection
// is an error, as the section says it is.
func Select(credential map[string]any, p Path) ([]any, error) {
	if err := p.valid(); err != nil {
		return nil, err
	}
	selected := []any{credential}
	for _, c := range p {
		var next []any
		for _, el := range selected {
			switch key := c.(type) {
			case string:
				obj, ok := el.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("%s: %q is applied to something that is not an object", p, key)
				}
				if v, ok := obj[key]; ok {
					next = append(next, v)
				}
			case nil:
				arr, ok := el.([]any)
				if !ok {
					return nil, fmt.Errorf("%s: null is applied to something that is not an array", p)
				}
				next = append(next, arr...)
			case int:
				arr, ok := el.([]any)
				if !ok {
					return nil, fmt.Errorf("%s: index %d is applied to something that is not an array", p, key)
				}
				if key < len(arr) {
					next = append(next, arr[key])
				}
			}
		}
		selected = next
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("the credential has no %s", p)
	}
	return selected, nil
}
