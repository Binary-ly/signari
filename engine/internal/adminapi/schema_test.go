package adminapi

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The OpenAPI schemas are the contract a generated client is built from, so a
// handler that answers differently from its schema breaks every such client
// silently (6.02). These hold the two together.

// Every registered operation has a schema, and every schema an operation.
func TestEveryOperationHasASchema(t *testing.T) {
	s := routerOnly(t)
	registered := map[string]bool{}
	for _, op := range s.ops {
		name := strings.ToUpper(op.method) + " " + op.path
		registered[name] = true
		if _, ok := opSchemas[name]; !ok {
			t.Errorf("%s is registered and has no schema in openapischema.go", name)
		}
	}
	for name := range opSchemas {
		if !registered[name] {
			t.Errorf("%s has a schema and no route", name)
		}
	}
}

// Every operation is called through a fixture, and what it answers matches its
// schema exactly: its status, its required fields, the type of every field,
// and no field the schema does not declare. The body each fixture sends is
// held to the request schema too, so the two descriptions of a request (the
// type the handler decodes and what callers send) agree.
func TestEveryResponseMatchesItsSchema(t *testing.T) {
	s, _ := newTestServer(t)
	exercised := map[string]bool{}
	check := func(name, method, path, body string) {
		t.Helper()
		sc, ok := opSchemas[name]
		if !ok {
			t.Errorf("%s: no schema", name)
			return
		}
		exercised[name] = true
		if body != "" && sc.Request != nil {
			var sent any
			if err := json.Unmarshal([]byte(body), &sent); err != nil {
				t.Errorf("%s: the fixture body is not JSON: %v", name, err)
			} else {
				for _, p := range validate(sent, requestSchema(sc.Request), "request") {
					t.Errorf("%s: the fixture sends what the handler's type does not read: %s", name, p)
				}
			}
		}
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, body, ""))
		if rec.Code != sc.Status {
			t.Errorf("%s answered %d, its schema says %d: %s", name, rec.Code, sc.Status, truncate(rec.Body.String(), 200))
			return
		}
		if sc.Response == nil {
			if rec.Body.Len() != 0 {
				t.Errorf("%s has no response schema and answered %s", name, truncate(rec.Body.String(), 120))
			}
			return
		}
		var got any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Errorf("%s answered something that is not JSON: %v", name, err)
			return
		}
		for _, p := range validate(got, sc.Response, "response") {
			t.Errorf("%s: %s", name, p)
		}
	}
	for _, rt := range allReadRoutes() {
		check(rt.name, http.MethodGet, rt.path(t, s), "")
	}
	for _, rt := range allMutatingRoutes() {
		path := rt.path(t, s)
		check(rt.name, rt.method, path, rt.body(t, s, path))
	}

	var missed []string
	for name := range opSchemas {
		if !exercised[name] {
			missed = append(missed, name)
		}
	}
	sort.Strings(missed)
	for _, name := range missed {
		t.Errorf("%s is never called here, so its schema is held to nothing; add a fixture", name)
	}
}

// The validator checks itself on the cases the schemas rely on.
func TestTheSchemaValidatorRefusesWhatItShould(t *testing.T) {
	s := object([]string{"id"}, map[string]jsonSchema{"id": uuidStr(), "at": dateTime(), "n": integer(),
		"maybe": nullable(str())})
	for _, c := range []struct {
		doc string
		ok  bool
		why string
	}{
		{`{"id":"3e9b1a1e-0c84-4a3c-9f3e-1d1f1c1b1a19","at":"2026-10-22T14:51:46.035024+02:00","n":3,"maybe":null}`, true, "a valid one"},
		{`{"at":"2026-10-22T14:51:46Z"}`, false, "a required field missing"},
		{`{"id":"3e9b1a1e-0c84-4a3c-9f3e-1d1f1c1b1a19","extra":1}`, false, "an undeclared field"},
		{`{"id":"3e9b1a1e-0c84-4a3c-9f3e-1d1f1c1b1a19","at":"2026-10-22T14:51:46.035024+02"}`, false, "an offset without its minutes"},
		{`{"id":"3e9b1a1e-0c84-4a3c-9f3e-1d1f1c1b1a19","at":"2026-10-22 14:51:46+02:00"}`, false, "a space for the T"},
		{`{"id":"not-a-uuid"}`, false, "a malformed uuid"},
		{`{"id":"3e9b1a1e-0c84-4a3c-9f3e-1d1f1c1b1a19","n":1.5}`, false, "a fraction for an integer"},
		{`{"id":"3e9b1a1e-0c84-4a3c-9f3e-1d1f1c1b1a19","maybe":3}`, false, "a number for a nullable string"},
	} {
		var v any
		if err := json.Unmarshal([]byte(c.doc), &v); err != nil {
			t.Fatal(err)
		}
		if got := len(validate(v, s, "")) == 0; got != c.ok {
			t.Errorf("%s: valid = %v, want %v (%v)", c.why, got, c.ok, validate(v, s, ""))
		}
	}
}

// validate reports every way v departs from s.
func validate(v any, s jsonSchema, at string) []string {
	var out []string
	if t, ok := s["type"]; ok && !typeMatches(v, t) {
		return append(out, fmt.Sprintf("%s is %s, the schema says %v", at, jsonKind(v), t))
	}
	if str, ok := v.(string); ok {
		switch s["format"] {
		case "date-time":
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				out = append(out, fmt.Sprintf("%s %q is not an RFC 3339 date-time", at, str))
			}
		case "uuid":
			if _, err := uuid.Parse(str); err != nil {
				out = append(out, fmt.Sprintf("%s %q is not a uuid", at, str))
			}
		}
	}
	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, present := obj[r.(string)]; !present {
					out = append(out, fmt.Sprintf("%s lacks the required %q", at, r))
				}
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if ps, ok := props[k].(jsonSchema); ok {
				out = append(out, validate(obj[k], ps, at+"."+k)...)
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					out = append(out, fmt.Sprintf("%s has %q, which its schema does not declare", at, k))
				}
			case jsonSchema:
				out = append(out, validate(obj[k], ap, at+"."+k)...)
			}
		}
	}
	if list, ok := v.([]any); ok {
		if item, ok := s["items"].(jsonSchema); ok {
			for i, e := range list {
				out = append(out, validate(e, item, fmt.Sprintf("%s[%d]", at, i))...)
			}
		}
	}
	return out
}

func typeMatches(v any, t any) bool {
	switch tt := t.(type) {
	case string:
		return kindIs(v, tt)
	case []any:
		for _, e := range tt {
			if kindIs(v, e.(string)) {
				return true
			}
		}
	}
	return false
}

func kindIs(v any, t string) bool {
	switch t {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	case "number":
		_, ok := v.(float64)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "null":
		return v == nil
	}
	return false
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	}
	return fmt.Sprintf("%T", v)
}
