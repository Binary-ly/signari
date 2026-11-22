// Package sdkgen makes the Admin API's client libraries from its OpenAPI
// document (6.18): a Go package and a TypeScript module, one method for each
// operation the router registers, typed by the schemas the document carries.
//
// The document is docs/admin-openapi.json, drawn from the router by
// adminapi's TestThePublishedOpenAPIDocumentIsCurrent, so a client made from
// it is a client of the server that exists. TestTheClientsAreCurrent makes
// both again and fails on any difference from what is committed in sdk/, the
// same way: a route added, or a field, and the clients say so until they are
// made again.
package sdkgen

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

type schema struct {
	Type                 any                `json:"type"`
	Properties           map[string]*schema `json:"properties"`
	Items                *schema            `json:"items"`
	Required             []string           `json:"required"`
	Ref                  string             `json:"$ref"`
	Format               string             `json:"format"`
	AdditionalProperties any                `json:"additionalProperties"`
}

type content struct {
	Content map[string]struct {
		Schema *schema `json:"schema"`
	} `json:"content"`
}

func (c *content) schema() *schema {
	if c == nil {
		return nil
	}
	if j, ok := c.Content["application/json"]; ok {
		return j.Schema
	}
	return nil
}

type operation struct {
	ID         string `json:"operationId"`
	Summary    string `json:"summary"`
	Parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	} `json:"parameters"`
	RequestBody *content              `json:"requestBody"`
	Responses   map[string]*content   `json:"responses"`
	Security    []map[string][]string `json:"security"`
	Privileged  string                `json:"x-privileged-scope"`

	method, path string
}

type document struct {
	Paths      map[string]map[string]*operation `json:"paths"`
	Components struct {
		Schemas map[string]*schema `json:"schemas"`
	} `json:"components"`
}

// operations reads the document's operations, in operationId order.
func operations(raw []byte) (*document, []*operation, error) {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("sdkgen: reading the OpenAPI document: %w", err)
	}
	var ops []*operation
	for path, item := range doc.Paths {
		for method, op := range item {
			if op.ID == "" {
				return nil, nil, fmt.Errorf("sdkgen: %s %s has no operationId", method, path)
			}
			op.method, op.path = strings.ToUpper(method), path
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID })
	return &doc, ops, nil
}

// success is the schema of an operation's successful answer.
func (op *operation) success() *schema {
	codes := make([]string, 0, len(op.Responses))
	for code := range op.Responses {
		if strings.HasPrefix(code, "2") {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	if len(codes) == 0 {
		return nil
	}
	return op.Responses[codes[0]].schema()
}

func (op *operation) pathParams() []string {
	var out []string
	for _, p := range op.Parameters {
		if p.In == "path" {
			out = append(out, p.Name)
		}
	}
	return out
}

// scopes says what the operation needs, for its comment.
func (op *operation) scopes() string {
	var s []string
	for _, sec := range op.Security {
		for _, v := range sec {
			s = append(s, v...)
		}
	}
	out := "Any token; each operation in it is held to its own scope."
	if len(s) > 0 {
		out = "Needs " + strings.Join(s, ", ") + "."
	}
	if op.Privileged != "" {
		out += " A target that may impersonate others also needs " + op.Privileged + "."
	}
	return out
}

// kind is what a schema is, for both languages.
type kind int

const (
	kAny kind = iota
	kString
	kInt
	kFloat
	kBool
	kArray
	kMap
	kNamed
)

type typeRef struct {
	kind     kind
	elem     *typeRef
	name     string
	nullable bool
}

type field struct {
	json     string
	t        typeRef
	required bool
}

type structDef struct {
	name   string
	fields []field
}

// model collects the named types an operation's schemas need.
type model struct {
	structs map[string]*structDef
	order   []string
}

func newModel() *model { return &model{structs: map[string]*structDef{}} }

// types answers the type list and whether null is one of them.
func typesOf(s *schema) ([]string, bool) {
	var out []string
	null := false
	switch t := s.Type.(type) {
	case string:
		out = []string{t}
	case []any:
		for _, v := range t {
			if str, ok := v.(string); ok {
				if str == "null" {
					null = true
				} else {
					out = append(out, str)
				}
			}
		}
	}
	return out, null
}

// resolve turns a schema into a type, naming each object it meets after
// where it is.
func (m *model) resolve(s *schema, name string) typeRef {
	if s == nil {
		return typeRef{kind: kAny}
	}
	if s.Ref != "" {
		return typeRef{kind: kNamed, name: pascal(s.Ref[strings.LastIndex(s.Ref, "/")+1:])}
	}
	types, null := typesOf(s)
	base := ""
	if len(types) == 1 {
		base = types[0]
	}
	var t typeRef
	switch base {
	case "string":
		t = typeRef{kind: kString}
	case "integer":
		t = typeRef{kind: kInt}
	case "number":
		t = typeRef{kind: kFloat}
	case "boolean":
		t = typeRef{kind: kBool}
	case "array":
		elem := m.resolve(s.Items, name+"Item")
		t = typeRef{kind: kArray, elem: &elem}
	case "object":
		if len(s.Properties) == 0 {
			t = typeRef{kind: kMap}
			break
		}
		m.define(name, s)
		t = typeRef{kind: kNamed, name: name}
	default:
		t = typeRef{kind: kAny}
	}
	t.nullable = null
	return t
}

// define names an object's struct, its fields in name order.
func (m *model) define(name string, s *schema) {
	if _, ok := m.structs[name]; ok {
		return
	}
	def := &structDef{name: name}
	m.structs[name] = def
	m.order = append(m.order, name)
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	keys := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		def.fields = append(def.fields, field{json: k, t: m.resolve(s.Properties[k], name+pascal(k)),
			required: required[k]})
	}
}

// initialisms are written in capitals in Go names.
var initialisms = map[string]string{"id": "ID", "ids": "IDs", "url": "URL", "urls": "URLs", "uri": "URI",
	"uris": "URIs", "api": "API", "acs": "ACS", "http": "HTTP", "https": "HTTPS", "json": "JSON", "jwks": "JWKS",
	"jwt": "JWT", "uuid": "UUID", "saml": "SAML", "scim": "SCIM", "ssf": "SSF", "rac": "RAC", "oidc": "OIDC",
	"ttl": "TTL", "acr": "ACR", "amr": "AMR", "idp": "IdP", "sms": "SMS", "otp": "OTP", "totp": "TOTP",
	"uma": "UMA", "dn": "DN", "ldap": "LDAP", "ip": "IP", "sid": "SID", "cidr": "CIDR", "radius": "RADIUS"}

// pascal is a name in PascalCase: snake_case, kebab-case and camelCase
// words, each capitalised, initialisms in capitals.
func pascal(s string) string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = nil
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ' || r == ':' || r == '/':
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(runes[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	var b strings.Builder
	for _, w := range words {
		if up, ok := initialisms[strings.ToLower(w)]; ok {
			b.WriteString(up)
			continue
		}
		rs := []rune(w)
		rs[0] = unicode.ToUpper(rs[0])
		b.WriteString(string(rs))
	}
	out := b.String()
	if out == "" || unicode.IsDigit([]rune(out)[0]) {
		out = "X" + out
	}
	return out
}

// camel is a name in camelCase, for parameters.
func camel(s string) string {
	p := pascal(s)
	rs := []rune(p)
	// A leading initialism goes to lower case whole: ID -> id, IdP -> idp.
	i := 0
	for i < len(rs) && unicode.IsUpper(rs[i]) {
		i++
	}
	switch {
	case i == 0:
	case i == 1 || i == len(rs):
		for j := 0; j < i; j++ {
			rs[j] = unicode.ToLower(rs[j])
		}
	default:
		for j := 0; j < i-1; j++ {
			rs[j] = unicode.ToLower(rs[j])
		}
	}
	out := string(rs)
	switch out {
	case "ctx", "body", "opts", "type", "func", "default", "interface", "select", "case", "range", "map",
		"package", "import", "return", "go", "var", "const", "struct", "chan", "else", "for", "if", "switch",
		"break", "continue", "goto", "fallthrough", "defer", "delete", "new", "function", "class", "export":
		out += "Param"
	}
	return out
}

// goPath is the operation's path as a Go expression.
func goPath(path string) string {
	parts := []string{}
	rest := path
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			if rest != "" {
				parts = append(parts, fmt.Sprintf("%q", rest))
			}
			break
		}
		closeAt := strings.IndexByte(rest, '}')
		if open > 0 {
			parts = append(parts, fmt.Sprintf("%q", rest[:open]))
		}
		parts = append(parts, "url.PathEscape("+camel(rest[open+1:closeAt])+")")
		rest = rest[closeAt+1:]
	}
	return strings.Join(parts, " + ")
}

// tsPath is the operation's path as a TypeScript template literal.
func tsPath(path string) string {
	var b strings.Builder
	b.WriteByte('`')
	rest := path
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			b.WriteString(rest)
			break
		}
		closeAt := strings.IndexByte(rest, '}')
		b.WriteString(rest[:open])
		b.WriteString("${encodeURIComponent(" + camel(rest[open+1:closeAt]) + ")}")
		rest = rest[closeAt+1:]
	}
	b.WriteByte('`')
	return b.String()
}

// comment folds text into comment lines of at most width.
func comment(prefix, text string, width int) string {
	var b strings.Builder
	line := prefix
	for _, w := range strings.Fields(text) {
		if len(line)+len(w)+1 > width && line != prefix {
			b.WriteString(strings.TrimRight(line, " ") + "\n")
			line = prefix
		}
		line += w + " "
	}
	if line != prefix {
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	return b.String()
}
