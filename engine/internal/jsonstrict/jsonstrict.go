// Package jsonstrict refuses JSON documents whose meaning depends on the parser.
//
// # The one rule here
//
// A JSON object that names a member twice has no single meaning. RFC 8259 §4
// says the names within an object SHOULD be unique and that behaviour is
// unpredictable when they are not, and implementations genuinely differ: some
// take the first occurrence, some the last, and Go MERGES a repeated object into
// the value already decoded, so the first occurrence's populated fields survive
// while a later empty one appears to have been ignored.
//
// That divergence is the problem. Two components reading the same bytes reach
// different conclusions, and neither is wrong. When one of them is an
// authorization decision and the other is the record of that decision — a proxy,
// a WAF, an audit shipper, a SIEM — the system ends up proving something that
// did not happen.
//
// Shared rather than copied into each caller, because a rule this subtle
// re-implemented per package is a rule that drifts: one copy gains a depth limit
// or loses the array case and nothing says so.
package jsonstrict

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NoDuplicateKeys reports an error if any object in the document names a member
// more than once, at any depth.
//
// A token walk, not a second unmarshal into map[string]any — that would collapse
// the duplicates before they could be seen, which is the whole difficulty.
//
// Malformed JSON is NOT reported here. The caller's own decode produces a better
// message, one that names the offending position, and returning a second opinion
// about the same bytes only makes the error harder to read.
func NoDuplicateKeys(body []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	// Numbers are never inspected, so precision does not matter; UseNumber only
	// avoids the float conversion on the way past.
	dec.UseNumber()
	return walk(dec, nil)
}

func walk(dec *json.Decoder, path []string) error {
	tok, err := dec.Token()
	if err != nil {
		return nil // malformed: the caller's decode will say so, and say it better
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, kerr := dec.Token()
			if kerr != nil {
				return nil
			}
			key, _ := keyTok.(string)
			if seen[key] {
				where := "the document"
				if len(path) > 0 {
					where = strings.Join(path, ".")
				}
				return fmt.Errorf("%s names %q more than once; which one applies "+
					"depends on the parser, so this has no single meaning", where, key)
			}
			seen[key] = true
			if verr := walk(dec, append(path, key)); verr != nil {
				return verr
			}
		}
		_, _ = dec.Token() // closing brace
	case '[':
		for dec.More() {
			if verr := walk(dec, path); verr != nil {
				return verr
			}
		}
		_, _ = dec.Token() // closing bracket
	}
	return nil
}
