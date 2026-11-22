package adminapi

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A write naming an organisation that does not exist is the caller's mistake,
// and must be answered as one (0.23). Creating a user, client, group or
// invitation, or declaring a scope, a protected host or a WebAuthn policy, in
// an unknown organisation answered 500 server_error from the foreign key the
// insert tripped, and a body org_id that was not a uuid did the same from the
// cast. Automation that mistyped an id was told the server had failed, and
// retried.
//
// Which writes name an organisation is derived, not listed: every route in
// allMutatingRoutes (itself held to the router) with {orgID} in its pattern,
// and every route whose request type has an org_id field, which the fixture
// body is given when it leaves the field out.
func TestAWriteToAnUnknownOrganisationIsTheCallersMistake(t *testing.T) {
	s, _ := newTestServer(t)

	tested := 0
	for _, rt := range allMutatingRoutes() {
		inPath := strings.Contains(rt.name, "{orgID}")
		inBody := hasJSONField(opSchemas[rt.name].Request, "org_id")
		if !inPath && !inBody {
			continue
		}
		tested++
		t.Run(rt.name, func(t *testing.T) {
			path := rt.path(t, s)
			body := rt.body(t, s, path)
			for _, c := range []struct {
				id   string
				want int
			}{
				{uuid.NewString(), 404},
				{"not-an-organisation", 400},
				// Another spelling of a uuid PostgreSQL would accept.
				{strings.ToUpper(uuid.NewString()), 400},
			} {
				p, b := path, body
				if inPath {
					p = withPathOrg(t, path, c.id)
				}
				if inBody {
					b = withBodyOrg(t, body, c.id)
				}
				rec := httptest.NewRecorder()
				s.Routes().ServeHTTP(rec, adminReq(t, rt.method, p, b, ""))
				var answer struct {
					Error string `json:"error"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &answer)
				if rec.Code != c.want || answer.Error == "server_error" {
					t.Errorf("organisation %q answered %d, want %d: %s",
						c.id, rec.Code, c.want, rec.Body.String())
				}
			}
		})
	}
	if tested < 15 {
		t.Fatalf("only %d writes name an organisation; the derivation has stopped "+
			"seeing the routes it exists for", tested)
	}
}

// hasJSONField reports whether a request type decodes a top-level field.
func hasJSONField(t reflect.Type, name string) bool {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		if tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); tag == name {
			return true
		}
	}
	return false
}

// withPathOrg replaces the organisation segment of /admin/organizations/{orgID}/...
func withPathOrg(t *testing.T, path, org string) string {
	t.Helper()
	const prefix = "/admin/organizations/"
	if !strings.HasPrefix(path, prefix) {
		t.Fatalf("%s has {orgID} in its pattern and the fixture path %q does not start %s",
			path, path, prefix)
	}
	rest := strings.TrimPrefix(path, prefix)
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	return prefix + org + rest[end:]
}

// withBodyOrg sets org_id in a JSON object body, adding it if absent.
func withBodyOrg(t *testing.T, body, org string) string {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if body != "" {
		if err := json.Unmarshal([]byte(body), &fields); err != nil {
			t.Fatalf("fixture body is not a JSON object: %v: %s", err, body)
		}
	}
	fields["org_id"], _ = json.Marshal(org)
	out, _ := json.Marshal(fields)
	return string(out)
}
