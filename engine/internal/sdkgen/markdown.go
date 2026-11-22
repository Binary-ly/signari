package sdkgen

import (
	"fmt"
	"strings"
)

// Markdown renders the document as a reference to read (6.22): each
// operation with what it needs, the fields it takes and the fields it
// answers, grouped by the first segment of its path. Made with the clients,
// from the same document, and held current by the same test.
func Markdown(raw []byte) ([]byte, error) {
	doc, ops, err := operations(raw)
	if err != nil {
		return nil, err
	}
	m := newModel()
	defineComponents(m, doc)

	var b strings.Builder
	b.WriteString("# Admin API reference\n\n" +
		"Generated from [admin-openapi.json](admin-openapi.json), which the router draws, by\n" +
		"`engine/internal/sdkgen`; do not edit it by hand. What each operation is for, and the\n" +
		"rules around it, are in [admin-api.md](admin-api.md). Every write takes `If-Match` and is\n" +
		"refused with `412` when the configuration moved since the version it names.\n\n")

	groups := map[string][]*operation{}
	var order []string
	for _, op := range ops {
		g := section(op.path)
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], op)
	}
	sortStringsStable(order)
	b.WriteString("| Section | Operations |\n|---|---|\n")
	for _, g := range order {
		fmt.Fprintf(&b, "| [%s](#%s) | %d |\n", g, anchor(g), len(groups[g]))
	}
	b.WriteString("\n")

	for _, g := range order {
		fmt.Fprintf(&b, "## %s\n\n", g)
		ops := groups[g]
		sortOps(ops)
		for _, op := range ops {
			fmt.Fprintf(&b, "### `%s %s`\n\n%s %s\n\n", op.method, op.path, op.Summary, op.scopes())
			fmt.Fprintf(&b, "Go `%s`, TypeScript `%s`.\n\n", pascal(op.ID), lowerFirst(pascal(op.ID)))
			if s := op.RequestBody.schema(); s != nil {
				t := m.resolve(s, pascal(op.ID)+"Request")
				writeFields(&b, m, "Takes", t, true)
			}
			if s := op.success(); s != nil {
				t := m.resolve(s, pascal(op.ID)+"Response")
				writeFields(&b, m, "Answers", t, false)
			}
		}
	}
	return []byte(strings.TrimRight(b.String(), "\n") + "\n"), nil
}

// section is the part of the path an operation is filed under.
func section(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(parts) >= 4 && parts[1] == "organizations":
		return parts[3]
	case len(parts) >= 4 && (parts[1] == "instances" || parts[1] == "users" || parts[1] == "clients" ||
		parts[1] == "groups"):
		return parts[1] + " / " + parts[3]
	case len(parts) >= 2:
		return parts[1]
	}
	return path
}

func anchor(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

func lowerFirst(s string) string { return strings.ToLower(s[:1]) + s[1:] }

// writeFields lists an object's fields, one level of nesting written out.
func writeFields(b *strings.Builder, m *model, label string, t typeRef, request bool) {
	if t.kind == kArray && t.elem != nil {
		t = *t.elem
		label += " a list, each"
	}
	def, ok := m.structs[t.name]
	if t.kind != kNamed || !ok || len(def.fields) == 0 {
		fmt.Fprintf(b, "%s %s.\n\n", label, mdType(t))
		return
	}
	fmt.Fprintf(b, "%s:\n\n| Field | Type | |\n|---|---|---|\n", label)
	for _, f := range def.fields {
		note := ""
		if !request && f.required {
			note = "always"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", f.json, mdType(f.t), note)
	}
	b.WriteString("\n")
}

// mdType names a type for the reference.
func mdType(t typeRef) string {
	var s string
	switch t.kind {
	case kString:
		s = "string"
	case kInt:
		s = "integer"
	case kFloat:
		s = "number"
	case kBool:
		s = "boolean"
	case kArray:
		s = "list of " + mdType(*t.elem)
	case kMap:
		s = "object"
	case kNamed:
		s = "object"
	default:
		s = "any"
	}
	if t.nullable {
		s += " or null"
	}
	return s
}

func sortStringsStable(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func sortOps(ops []*operation) {
	key := func(op *operation) string { return op.path + " " + op.method }
	for i := 1; i < len(ops); i++ {
		for j := i; j > 0 && key(ops[j]) < key(ops[j-1]); j-- {
			ops[j], ops[j-1] = ops[j-1], ops[j]
		}
	}
}
