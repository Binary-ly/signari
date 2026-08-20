package httpapi

import (
	"net/http"
	"testing"
)

// RFC 7644 §4: "An HTTP GET to the endpoint "/Schemas" SHALL return all
// supported schemas in ListResponse format."
//
// The endpoint did not exist. §4 names three discovery endpoints and we served
// two, so a provisioning client doing the ordinary thing — fetch
// /ServiceProviderConfig, /ResourceTypes and /Schemas before its first sync —
// got a 404 on the one that tells it which attributes it may send.
func TestSCIMSchemasEndpointExists(t *testing.T) {
	f := newSCIMFixture(t)

	code, body := f.do(t, http.MethodGet, "/scim/v2/Schemas", "")
	if code != http.StatusOK {
		t.Fatalf("GET /scim/v2/Schemas gave %d; §4 makes this a discovery "+
			"endpoint a client fetches before its first sync", code)
	}
	if got, _ := body["schemas"].([]any); len(got) == 0 || got[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Errorf("the response is not in ListResponse form: %v", body["schemas"])
	}
	res, _ := body["Resources"].([]any)
	if len(res) == 0 {
		t.Fatal("no schemas returned")
	}
	if body["totalResults"] != float64(len(res)) {
		t.Errorf("totalResults %v disagrees with %d resources returned — an "+
			"upstream that reads the count and receives a different number syncs "+
			"the wrong set", body["totalResults"], len(res))
	}
	ids := map[string]bool{}
	for _, r := range res {
		m, _ := r.(map[string]any)
		id, _ := m["id"].(string)
		ids[id] = true
	}
	for _, want := range []string{schemaURIUser, schemaURIGroup} {
		if !ids[want] {
			t.Errorf("no schema for %s, but /ResourceTypes advertises that type", want)
		}
	}
}

// "Individual schema definitions can be returned by appending the schema URI to
// the /Schemas endpoint", and §4: the single object is returned "in the same way
// that a single User or Group is retrieved" — not wrapped in a ListResponse.
func TestSCIMSingleSchemaIsNotWrappedInAListResponse(t *testing.T) {
	f := newSCIMFixture(t)

	code, body := f.do(t, http.MethodGet, "/scim/v2/Schemas/"+schemaURIUser, "")
	if code != http.StatusOK {
		t.Fatalf("GET a single schema gave %d", code)
	}
	if body["id"] != schemaURIUser {
		t.Errorf("id = %v, want %q", body["id"], schemaURIUser)
	}
	if _, wrapped := body["Resources"]; wrapped {
		t.Error("a single schema came back wrapped in a ListResponse; §4 says it " +
			"is returned the way a single User or Group is")
	}

	code, _ = f.do(t, http.MethodGet, "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Nonsense", "")
	if code != http.StatusNotFound {
		t.Errorf("an unknown schema URI gave %d, want 404", code)
	}
}

// The published schemas must describe what this engine actually stores.
//
// RFC 7643's full core User schema names givenName, phoneNumbers, addresses,
// photos and more. Publishing that document would have a client map those
// attributes, send them, and watch them vanish — which is worse than publishing
// nothing, and is the failure this project's discovery rule exists to prevent.
func TestPublishedSchemasDescribeWhatWeActuallyStore(t *testing.T) {
	f := newSCIMFixture(t)
	_, body := f.do(t, http.MethodGet, "/scim/v2/Schemas/"+schemaURIUser, "")

	attrs, _ := body["attributes"].([]any)
	got := map[string]bool{}
	for _, a := range attrs {
		m, _ := a.(map[string]any)
		if n, ok := m["name"].(string); ok {
			got[n] = true
		}
	}
	// Everything scimUserResource returns.
	for _, want := range []string{"userName", "externalId", "displayName", "active", "emails"} {
		if !got[want] {
			t.Errorf("the User schema omits %q, which we do return", want)
		}
	}
	// Nothing we silently drop.
	for _, unwanted := range []string{"name", "phoneNumbers", "addresses", "photos", "entitlements"} {
		if got[unwanted] {
			t.Errorf("the User schema advertises %q, which this engine does not "+
				"store — a client will map it, send it, and lose the data", unwanted)
		}
	}
}

// §4: "If a "filter" is provided, the service provider SHOULD respond with HTTP
// status code 403 (Forbidden) to ensure that clients cannot incorrectly assume
// that any matching conditions specified in a filter are true."
//
// The reasoning in that sentence is the point: a client that filters and gets
// 200 with every resource concludes they all matched. Silently ignoring the
// filter is the failure mode.
func TestFilteringTheDiscoveryEndpointsIsForbidden(t *testing.T) {
	f := newSCIMFixture(t)
	for _, path := range []string{
		`/scim/v2/Schemas?filter=name+eq+"User"`,
		`/scim/v2/ResourceTypes?filter=name+eq+"User"`,
	} {
		code, _ := f.do(t, http.MethodGet, path, "")
		if code != http.StatusForbidden {
			t.Errorf("GET %s gave %d, want 403: a filtered 200 lets the client "+
				"assume every resource returned matched the filter", path, code)
		}
	}
}

// RFC 7644 §3.4.2.4, Table 6: "A negative value SHALL be interpreted as "0"",
// and count=0 means "no resource results are to be returned except for
// totalResults".
//
// A negative count used to fall through to the default page size, so a client
// asking for nothing was sent a hundred records — wrong in the direction that
// returns more data than was asked for.
func TestNegativeCountReturnsNoResources(t *testing.T) {
	f := newSCIMFixture(t)

	for _, path := range []string{
		"/scim/v2/Users?count=-1",
		"/scim/v2/Users?count=0",
		"/scim/v2/Groups?count=-5",
		"/scim/v2/Groups?count=0",
	} {
		code, body := f.do(t, http.MethodGet, path, "")
		if code != http.StatusOK {
			t.Fatalf("GET %s gave %d: %v", path, code, body)
		}
		res, _ := body["Resources"].([]any)
		if len(res) != 0 {
			t.Errorf("GET %s returned %d resources; a count of zero or less means "+
				"none, with only totalResults", path, len(res))
		}
		// totalResults must still be reported — that is the whole purpose of
		// count=0.
		if _, ok := body["totalResults"]; !ok {
			t.Errorf("GET %s omitted totalResults, which is the one thing a "+
				"count=0 request is asking for", path)
		}
	}
}

// startIndex below 1 "SHALL be interpreted as 1" — the other half of Table 6,
// checked so the fix above cannot regress it.
func TestStartIndexBelowOneIsTreatedAsOne(t *testing.T) {
	f := newSCIMFixture(t)
	for _, path := range []string{"/scim/v2/Users?startIndex=0", "/scim/v2/Users?startIndex=-3"} {
		code, body := f.do(t, http.MethodGet, path, "")
		if code != http.StatusOK {
			t.Fatalf("GET %s gave %d", path, code)
		}
		if body["startIndex"] != float64(1) {
			t.Errorf("GET %s reported startIndex %v, want 1", path, body["startIndex"])
		}
	}
}
