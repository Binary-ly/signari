package scim

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Path is a parsed SCIM attribute path.
type Path struct {
	// Schema is the URN prefix when the path was fully qualified, without the
	// trailing colon. RFC 7644 §3.5.2 permits `urn:...:User:emails`.
	Schema string
	// Attr is the attribute name, lower-cased for comparison.
	Attr string
	// Sub is the sub-attribute after the value filter or a dot, lower-cased.
	Sub string
	// Filter is the value filter inside brackets, nil when there was none.
	Filter *Filter
}

// String renders the path approximately as it arrived, for error messages.
func (p *Path) String() string {
	var b strings.Builder
	b.WriteString(p.Attr)
	if p.Filter != nil {
		b.WriteString("[…]")
	}
	if p.Sub != "" {
		b.WriteString("." + p.Sub)
	}
	return b.String()
}

// Filter is a value filter: comparisons joined by and/or, optionally negated.
type Filter struct {
	// Op is one of the RFC 7644 §3.4.2.2 operators, or "and"/"or"/"not".
	Op string
	// Attr and Value are set for a comparison.
	Attr  string
	Value any
	// Left and Right are set for and/or; Left alone for not.
	Left, Right *Filter
}

// ParsePath reads an attribute path.
func ParsePath(s string) (*Path, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil, fmt.Errorf("empty path")
	}

	p := &Path{}

	// A fully qualified path carries a schema URN, and the attribute is whatever
	// follows the last colon that is not inside brackets. Entra sends these for
	// extension attributes.
	if strings.HasPrefix(strings.ToLower(raw), "urn:") {
		if i := lastColonOutsideBrackets(raw); i > 0 {
			p.Schema, raw = raw[:i], raw[i+1:]
		}
	}

	// The value filter, if any.
	if open := strings.Index(raw, "["); open >= 0 {
		close := strings.LastIndex(raw, "]")
		if close < open {
			return nil, fmt.Errorf("path %q opens a value filter and never closes it", s)
		}
		attr := raw[:open]
		inner := raw[open+1 : close]
		rest := raw[close+1:]

		f, err := parseFilter(inner)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", s, err)
		}
		p.Filter = f
		p.Attr = strings.ToLower(strings.TrimSpace(attr))
		if rest = strings.TrimSpace(rest); rest != "" {
			if !strings.HasPrefix(rest, ".") {
				return nil, fmt.Errorf("path %q has trailing text %q after the value "+
					"filter; only a sub-attribute may follow", s, rest)
			}
			p.Sub = strings.ToLower(strings.TrimSpace(rest[1:]))
		}
		if p.Attr == "" {
			return nil, fmt.Errorf("path %q has a value filter but no attribute", s)
		}
		return p, nil
	}

	// No filter: attr or attr.sub.
	if dot := strings.Index(raw, "."); dot >= 0 {
		p.Attr = strings.ToLower(strings.TrimSpace(raw[:dot]))
		p.Sub = strings.ToLower(strings.TrimSpace(raw[dot+1:]))
	} else {
		p.Attr = strings.ToLower(strings.TrimSpace(raw))
	}
	if p.Attr == "" {
		return nil, fmt.Errorf("path %q names no attribute", s)
	}
	return p, nil
}

// lastColonOutsideBrackets finds the schema/attribute boundary.
//
// Brackets are skipped because a filter may contain a colon inside a quoted
// value -- `emails[value eq "urn:x"]` -- and splitting there would take the
// attribute from the middle of somebody's data.
func lastColonOutsideBrackets(s string) int {
	depth, last := 0, -1
	inQuote := false
	for i, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case inQuote:
		case r == '[':
			depth++
		case r == ']':
			depth--
		case r == ':' && depth == 0:
			last = i
		}
	}
	return last
}

// comparisonOps are RFC 7644 §3.4.2.2's attribute operators.
//
// `pr` (present) is unary and is handled separately: it takes no value, and a
// parser that expects one after it treats the next token as a comparand.
var comparisonOps = map[string]bool{
	"eq": true, "ne": true, "co": true, "sw": true, "ew": true,
	"gt": true, "lt": true, "ge": true, "le": true,
}

// parseFilter reads a value filter.
func parseFilter(s string) (*Filter, error) {
	toks, err := tokenizeFilter(s)
	if err != nil {
		return nil, err
	}
	p := &filterParser{toks: toks}
	f, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q in filter", p.toks[p.pos].text)
	}
	return f, nil
}

type token struct {
	text   string
	quoted bool
}

func tokenizeFilter(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		switch c := s[i]; {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			out = append(out, token{text: string(c)})
			i++
		case c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					b.WriteByte(s[j+1])
					j += 2
					continue
				}
				if s[j] == '"' {
					break
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string in filter")
			}
			out = append(out, token{text: b.String(), quoted: true})
			i = j + 1
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '(' && s[j] != ')' {
				j++
			}
			out = append(out, token{text: s[i:j]})
			i = j
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty filter")
	}
	return out, nil
}

type filterParser struct {
	toks []token
	pos  int
}

func (p *filterParser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{}, false
}

func (p *filterParser) parseOr() (*Filter, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.quoted || !strings.EqualFold(t.text, "or") {
			return left, nil
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Filter{Op: "or", Left: left, Right: right}
	}
}

func (p *filterParser) parseAnd() (*Filter, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.quoted || !strings.EqualFold(t.text, "and") {
			return left, nil
		}
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &Filter{Op: "and", Left: left, Right: right}
	}
}

func (p *filterParser) parseUnary() (*Filter, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("filter ended early")
	}
	if !t.quoted && strings.EqualFold(t.text, "not") {
		p.pos++
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Filter{Op: "not", Left: inner}, nil
	}
	if !t.quoted && t.text == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		c, ok := p.peek()
		if !ok || c.text != ")" {
			return nil, fmt.Errorf("unclosed ( in filter")
		}
		p.pos++
		return inner, nil
	}
	return p.parseComparison()
}

func (p *filterParser) parseComparison() (*Filter, error) {
	attrTok, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("filter ended where an attribute was expected")
	}
	p.pos++
	opTok, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("filter attribute %q has no operator", attrTok.text)
	}
	p.pos++
	op := strings.ToLower(opTok.text)

	// `pr` is unary: "attribute is present". No comparand follows.
	if op == "pr" {
		return &Filter{Op: "pr", Attr: strings.ToLower(attrTok.text)}, nil
	}
	if !comparisonOps[op] {
		return nil, fmt.Errorf("unknown filter operator %q", opTok.text)
	}
	valTok, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("filter operator %q has no value", op)
	}
	p.pos++
	return &Filter{Op: op, Attr: strings.ToLower(attrTok.text),
		Value: literal(valTok)}, nil
}

func literal(t token) any {
	if t.quoted {
		return t.text
	}
	switch strings.ToLower(t.text) {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if n, err := strconv.ParseFloat(t.text, 64); err == nil {
		return n
	}
	return t.text
}

// Matches evaluates the filter against one multi-valued attribute element.
//
// Comparison is case-insensitive for strings, which RFC 7644 §3.4.2.2 specifies
// for `eq` on caseExact:false attributes -- and every attribute this server
// filters on (`type`, `value`, `primary`) is caseExact:false in the core schema.
func (f *Filter) Matches(obj map[string]any) bool {
	if f == nil {
		return true
	}
	switch f.Op {
	case "and":
		return f.Left.Matches(obj) && f.Right.Matches(obj)
	case "or":
		return f.Left.Matches(obj) || f.Right.Matches(obj)
	case "not":
		return !f.Left.Matches(obj)
	case "pr":
		v, ok := obj[f.Attr]
		return ok && v != nil && v != ""
	}

	have, ok := lookupFold(obj, f.Attr)
	if !ok {
		return false
	}
	switch want := f.Value.(type) {
	case string:
		s, ok := have.(string)
		if !ok {
			return false
		}
		return compareStrings(f.Op, s, want)
	case bool:
		b, ok := have.(bool)
		return ok && f.Op == "eq" && b == want
	case float64:
		n, ok := toFloat(have)
		if !ok {
			return false
		}
		return compareNumbers(f.Op, n, want)
	}
	return false
}

func lookupFold(obj map[string]any, key string) (any, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func compareStrings(op, have, want string) bool {
	h, w := strings.ToLower(have), strings.ToLower(want)
	switch op {
	case "eq":
		return h == w
	case "ne":
		return h != w
	case "co":
		return strings.Contains(h, w)
	case "sw":
		return strings.HasPrefix(h, w)
	case "ew":
		return strings.HasSuffix(h, w)
	case "gt":
		return h > w
	case "lt":
		return h < w
	case "ge":
		return h >= w
	case "le":
		return h <= w
	}
	return false
}

func compareNumbers(op string, have, want float64) bool {
	switch op {
	case "eq":
		return have == want
	case "ne":
		return have != want
	case "gt":
		return have > want
	case "lt":
		return have < want
	case "ge":
		return have >= want
	case "le":
		return have <= want
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
