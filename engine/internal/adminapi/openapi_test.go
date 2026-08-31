package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The OpenAPI document is derived, so it cannot drift from the server.
//
// `docs/cli.md` once listed eight commands that had never existed. The fix there
// was to derive the list from the dispatch, and this is the same fix applied to
// the surface with the most consumers — an API document is not read by a person
// who will notice it is wrong, it is fed to a generator that produces a client
// which fails at runtime.

func openAPIDoc(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json gave %d: %s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// Every registered route appears, and nothing else does.
func TestTheOpenAPIDocumentMatchesTheRouter(t *testing.T) {
	s, _ := newTestServer(t)
	doc := openAPIDoc(t, s)

	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("the document has no paths; it is being generated from nothing")
	}

	// Build the set the document describes.
	documented := map[string]bool{}
	for path, item := range paths {
		methods, _ := item.(map[string]any)
		for method := range methods {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	// And the set the router registered.
	registered := map[string]bool{}
	for _, op := range s.routeTable() {
		registered[strings.ToUpper(op.method)+" "+op.path] = true
	}

	for op := range registered {
		if !documented[op] {
			t.Errorf("%s is registered and absent from the document. A client "+
				"generated from this cannot call it.", op)
		}
	}
	for op := range documented {
		if !registered[op] {
			t.Errorf("the document describes %s and nothing serves it. Somebody "+
				"will generate a client for it and find out at runtime.", op)
		}
	}
}

// Every operation carries the scope it actually requires.
//
// The part a hand-written document gets wrong most often, and the part an
// integrator most needs: a 403 that names a scope only helps if you could have
// found out which scope the operation wanted beforehand.
func TestEveryOperationDeclaresItsScope(t *testing.T) {
	s, _ := newTestServer(t)
	doc := openAPIDoc(t, s)
	paths := doc["paths"].(map[string]any)

	// The scope each route was registered with, straight from the router.
	want := map[string]string{}
	for _, op := range s.routeTable() {
		want[strings.ToUpper(op.method)+" "+op.path] = op.scope
	}

	for path, item := range paths {
		for method, raw := range item.(map[string]any) {
			entry := raw.(map[string]any)
			sec, _ := entry["security"].([]any)
			if len(sec) == 0 {
				t.Errorf("%s %s declares no security", strings.ToUpper(method), path)
				continue
			}
			scopes, _ := sec[0].(map[string]any)["bearerAuth"].([]any)
			if len(scopes) != 1 {
				t.Errorf("%s %s declares %d scopes, want 1", strings.ToUpper(method), path, len(scopes))
				continue
			}
			got, _ := scopes[0].(string)
			key := strings.ToUpper(method) + " " + path
			if got != want[key] {
				t.Errorf("%s declares scope %q; the router enforces %q",
					key, got, want[key])
			}
		}
	}
}

// Every operation has a summary.
//
// The map is keyed by route pattern, so a route added without one produces an
// empty summary rather than a plausible-looking default. A generated client with
// undocumented methods is worse than one with none, because it looks finished.
func TestEveryOperationHasASummary(t *testing.T) {
	s, _ := newTestServer(t)
	for _, op := range s.routeTable() {
		if strings.TrimSpace(op.summary) == "" {
			t.Errorf("%s %s has no summary. Add one to `summaries` in openapi.go.",
				strings.ToUpper(op.method), op.path)
		}
	}
}

// Mutations advertise the precondition, reads do not.
//
// The conditional write is this API's differentiator and the thing an integrator
// most needs to be told about — a document that omitted it would leave them
// writing exactly the lost-update bug it exists to prevent.
func TestMutationsAdvertiseTheIfMatchPrecondition(t *testing.T) {
	s, _ := newTestServer(t)
	doc := openAPIDoc(t, s)

	for path, item := range doc["paths"].(map[string]any) {
		for method, raw := range item.(map[string]any) {
			entry := raw.(map[string]any)
			params, _ := entry["parameters"].([]any)
			hasIfMatch := false
			for _, p := range params {
				if p.(map[string]any)["name"] == "If-Match" {
					hasIfMatch = true
				}
			}
			responses := entry["responses"].(map[string]any)
			_, has412 := responses["412"]

			if method == "get" {
				if hasIfMatch || has412 {
					t.Errorf("GET %s advertises a write precondition", path)
				}
				continue
			}
			if !hasIfMatch {
				t.Errorf("%s %s does not advertise If-Match", strings.ToUpper(method), path)
			}
			if !has412 {
				t.Errorf("%s %s does not document 412", strings.ToUpper(method), path)
			}
		}
	}
}

// Path parameters come from the pattern, so they cannot disagree with the router.
func TestPathParametersMatchTheRoutePattern(t *testing.T) {
	s, _ := newTestServer(t)
	doc := openAPIDoc(t, s)

	for path, item := range doc["paths"].(map[string]any) {
		want := map[string]bool{}
		for _, name := range pathParams(path) {
			want[name] = true
		}
		for method, raw := range item.(map[string]any) {
			params, _ := raw.(map[string]any)["parameters"].([]any)
			got := map[string]bool{}
			for _, p := range params {
				pm := p.(map[string]any)
				if pm["in"] == "path" {
					got[pm["name"].(string)] = true
				}
			}
			for name := range want {
				if !got[name] {
					t.Errorf("%s %s does not declare path parameter %q",
						strings.ToUpper(method), path, name)
				}
			}
			for name := range got {
				if !want[name] {
					t.Errorf("%s %s declares path parameter %q, which is not in the pattern",
						strings.ToUpper(method), path, name)
				}
			}
		}
	}
}

// The document is served without a token.
//
// It describes the shape of the API and no data. Requiring a token to read the
// description of how to use a token costs an integrator an hour and an attacker
// nothing.
func TestTheOpenAPIDocumentNeedsNoToken(t *testing.T) {
	s, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	// No Authorization header at all.
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("gave %d without a token, want 200", rec.Code)
	}
}
