package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// declare gives the fixture's organisation a root key and these attributes.
func (f *scimFixture) declare(t *testing.T, attrs ...store.Attribute) *keys.RootKey {
	t.Helper()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, a := range attrs {
		if a.ValueType == "" {
			a.ValueType = "string"
		}
		if _, err := store.DeclareAttribute(ctx, tx, f.orgID, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return root
}

func (f *scimFixture) patch(t *testing.T, id, ops string) (int, map[string]any) {
	t.Helper()
	return f.do(t, http.MethodPatch, "/scim/v2/Users/"+id,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":`+ops+`}`)
}

func enterpriseOf(t *testing.T, resource map[string]any) map[string]any {
	t.Helper()
	extension, _ := resource[scim.EnterpriseSchema].(map[string]any)
	return extension
}

// The row (7.12): what an upstream PATCHes reads back, and clears. The forms are
// those of TestAnEnterprisePatchIsReadInEveryShape, end to end through the store
// and the router, as an upstream's next GET would see them.
func TestAnEnterprisePatchRoundTrips(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "department", Personal: true}, store.Attribute{Name: "cost_center"},
		store.Attribute{Name: "manager"}, store.Attribute{Name: "employee_number", Personal: true})
	id := f.userA
	ext := scim.EnterpriseSchema

	status, body := f.patch(t, id, fmt.Sprintf(`[
		{"op":"Add","path":"%[1]s:department","value":"Engineering"},
		{"op":"Add","path":"%[1]s:manager","value":"%[2]s"},
		{"op":"Replace","value":{"%[1]s:costCenter":"4130"}},
		{"op":"Add","value":{"%[1]s":{"employeeNumber":"701984"}}}]`, ext, f.userB))
	if status != http.StatusOK {
		t.Fatalf("answered %d: %v", status, body)
	}
	for _, resource := range []map[string]any{body, f.read(t, id)} {
		e := enterpriseOf(t, resource)
		if e["department"] != "Engineering" || e["costCenter"] != "4130" || e["employeeNumber"] != "701984" {
			t.Errorf("read back %v", e)
		}
		if m, _ := e["manager"].(map[string]any); m["value"] != f.userB {
			t.Errorf("the manager read back as %v", e["manager"])
		}
		schemas, _ := resource["schemas"].([]any)
		if !slices.Contains(schemas, any(ext)) {
			t.Errorf("schemas is %v: a resource names the extension it uses", schemas)
		}
	}

	if status, body := f.patch(t, id, fmt.Sprintf(`[{"op":"Remove","path":"%[1]s:manager"},
		{"op":"Replace","path":"%[1]s:department","value":"Finance"}]`, ext)); status != http.StatusOK {
		t.Fatalf("answered %d: %v", status, body)
	}
	e := enterpriseOf(t, f.read(t, id))
	if _, kept := e["manager"]; kept || e["department"] != "Finance" || e["costCenter"] != "4130" {
		t.Errorf("after removing one and replacing another: %v", e)
	}

	// Removing what is not set is not an error: a retry is the same request.
	if status, body := f.patch(t, id, `[{"op":"Remove","path":"`+ext+`:manager"}]`); status != http.StatusOK {
		t.Errorf("answered %d: %v", status, body)
	}

	// The trail says which moved and never what to: an attribute can be a claim,
	// and this table outlives the person it describes.
	var recorded, wholeRow string
	if err := f.pool.QueryRow(context.Background(), `
		SELECT detail->>'attributes', detail::text FROM core.audit_events
		 WHERE org_id = $1::uuid AND subject_id = $2::uuid AND event_type = 'scim.user_patched'
		   AND detail ? 'attributes' ORDER BY id LIMIT 1`, f.orgID, f.userIDFor(t, id)).Scan(&recorded, &wholeRow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recorded, "department") || !strings.Contains(recorded, "employee_number") {
		t.Errorf("the trail names %s", recorded)
	}
	if strings.Contains(wholeRow, "Engineering") || strings.Contains(wholeRow, "701984") {
		t.Errorf("the trail holds a value: %s", wholeRow)
	}
}

func (f *scimFixture) read(t *testing.T, id string) map[string]any {
	t.Helper()
	status, body := f.do(t, http.MethodGet, "/scim/v2/Users/"+id, "")
	if status != http.StatusOK {
		t.Fatalf("GET answered %d: %v", status, body)
	}
	return body
}

// The declaration decides, through the one writer. A personal attribute is
// sealed, so it goes with the subject's key; the rest is the organisation's.
func TestAnEnterpriseValueIsWhatItsDeclarationSays(t *testing.T) {
	f := newSCIMFixture(t)
	root := f.declare(t, store.Attribute{Name: "department", Personal: true}, store.Attribute{Name: "cost_center"})
	f.patch(t, f.userA, fmt.Sprintf(`[{"op":"add","value":{"%[1]s":{"department":"Eng","costCenter":"42"}}}]`,
		scim.EnterpriseSchema))

	ctx := context.Background()
	userID := f.userIDFor(t, f.userA)
	rows, err := f.pool.Query(ctx, `
		SELECT s.name, a.value IS NOT NULL, a.value_sealed IS NOT NULL
		  FROM core.user_attributes a JOIN core.user_attribute_schema s ON s.id = a.attribute_id
		 WHERE a.user_id = $1::uuid`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	stored := map[string][2]bool{}
	for rows.Next() {
		var name string
		var clear, sealed bool
		if err := rows.Scan(&name, &clear, &sealed); err != nil {
			t.Fatal(err)
		}
		stored[name] = [2]bool{clear, sealed}
	}
	if stored["department"] != [2]bool{false, true} {
		t.Errorf("a personal value was stored %v, want sealed", stored["department"])
	}
	if stored["cost_center"] != [2]bool{true, false} {
		t.Errorf("an organisation's value was stored %v, want clear", stored["cost_center"])
	}

	// What a claim mapper reads: the value reaches the rest of the product.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	values, err := store.UserAttributes(ctx, tx, userID, f.orgID, root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, v := range values {
		seen[v.Name] = v.Value
	}
	if seen["department"] != "Eng" || seen["cost_center"] != "42" {
		t.Errorf("the profile read %v", seen)
	}
}

// Nothing declared, nothing kept, nothing promised, and the sync goes on: as a
// phone number is treated, because a value nobody has decided anything about
// has no erasure story.
func TestAnUndeclaredAttributeIsNotStoredOrOffered(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "department"})
	ext := scim.EnterpriseSchema

	status, body := f.patch(t, f.userA, `[{"op":"add","value":{"`+ext+`":{"department":"Eng","division":"X"}}}]`)
	if status != http.StatusOK {
		t.Fatalf("answered %d: %v", status, body)
	}
	e := enterpriseOf(t, body)
	if e["department"] != "Eng" {
		t.Errorf("read %v", e)
	}
	if _, kept := e["division"]; kept {
		t.Errorf("an undeclared attribute was kept: %v", e)
	}

	// Discovery offers what is declared, and only that.
	status, schema := f.do(t, http.MethodGet, "/scim/v2/Schemas/"+ext, "")
	if status != http.StatusOK {
		t.Fatalf("the extension's schema answered %d", status)
	}
	attrs, _ := schema["attributes"].([]any)
	if len(attrs) != 1 || attrs[0].(map[string]any)["name"] != "department" {
		t.Errorf("published %v", attrs)
	}
	_, types := f.do(t, http.MethodGet, "/scim/v2/ResourceTypes", "")
	user := types["Resources"].([]any)[0].(map[string]any)
	if extensions, _ := user["schemaExtensions"].([]any); len(extensions) != 1 {
		t.Errorf("the User type offers %v", user["schemaExtensions"])
	}
}

func TestNoDeclarationMeansNoExtensionInDiscovery(t *testing.T) {
	f := newSCIMFixture(t)
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Schemas/"+scim.EnterpriseSchema, ""); status != http.StatusNotFound {
		t.Errorf("the extension's schema answered %d with nothing declared", status)
	}
	_, types := f.do(t, http.MethodGet, "/scim/v2/ResourceTypes", "")
	user := types["Resources"].([]any)[0].(map[string]any)
	if _, offered := user["schemaExtensions"]; offered {
		t.Errorf("the User type offers %v with nothing declared", user["schemaExtensions"])
	}
	// And a value sent anyway is dropped without failing the request.
	status, body := f.patch(t, f.userA, `[{"op":"add","path":"`+scim.EnterpriseSchema+`:department","value":"Eng"}]`)
	if status != http.StatusOK || enterpriseOf(t, body) != nil {
		t.Errorf("answered %d: %v", status, body)
	}
}

func TestAnEnterpriseCreateAndReplace(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "department"}, store.Attribute{Name: "cost_center"})
	ext := scim.EnterpriseSchema
	name := fmt.Sprintf("created-%d", time.Now().UnixNano())

	status, body := f.do(t, http.MethodPost, "/scim/v2/Users", fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","%[1]s"],"externalId":"ext-%[2]s","userName":"%[2]s",
		  "%[1]s":{"department":"Eng","costCenter":"42"}}`, ext, name))
	if status != http.StatusCreated {
		t.Fatalf("created %d: %v", status, body)
	}
	id := body["id"].(string)
	if e := enterpriseOf(t, body); e["department"] != "Eng" || e["costCenter"] != "42" {
		t.Errorf("created with %v", e)
	}

	// A PUT with the extension replaces it: what it leaves out is cleared.
	put := func(extension string) map[string]any {
		t.Helper()
		status, body := f.do(t, http.MethodPut, "/scim/v2/Users/"+id, fmt.Sprintf(
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"ext-%s","userName":%q%s}`,
			name, name, extension))
		if status != http.StatusOK {
			t.Fatalf("PUT answered %d: %v", status, body)
		}
		return enterpriseOf(t, body)
	}
	if e := put(fmt.Sprintf(`,"%s":{"department":"Finance"}`, ext)); e["department"] != "Finance" || e["costCenter"] != nil {
		t.Errorf("replaced to %v", e)
	}
	// One without it leaves it: a client that does not send it may not know it.
	if e := put(""); e["department"] != "Finance" {
		t.Errorf("a PUT that never mentioned the extension left %v", e)
	}
	if e := put(fmt.Sprintf(`,"%s":{"department":null}`, ext)); e != nil {
		t.Errorf("a null left %v", e)
	}
}

// Held to the declaration, and told so in a way an upstream stops on.
func TestAnEnterpriseValueThatDoesNotFitIsRefused(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "employee_number", ValueType: "number"},
		store.Attribute{Name: "department", Required: true})
	ext := scim.EnterpriseSchema

	status, body := f.patch(t, f.userA, `[{"op":"add","path":"`+ext+`:employeeNumber","value":"E-12"}]`)
	if status != http.StatusBadRequest || body["scimType"] != "invalidValue" {
		t.Errorf("a word for a number answered %d %v", status, body)
	}
	status, body = f.patch(t, f.userA, `[{"op":"add","path":"`+ext+`:department","value":5}]`)
	if status != http.StatusBadRequest {
		t.Errorf("a number for a string answered %d %v", status, body)
	}
	if status, _ := f.patch(t, f.userA, `[{"op":"add","path":"`+ext+`:department","value":"Eng"}]`); status != http.StatusOK {
		t.Fatalf("setting it answered %d", status)
	}
	status, body = f.patch(t, f.userA, `[{"op":"remove","path":"`+ext+`:department"}]`)
	if status != http.StatusBadRequest || body["scimType"] != "invalidValue" {
		t.Errorf("clearing a required attribute answered %d %v", status, body)
	}
	// Refused whole: the transaction took nothing else with it.
	if e := enterpriseOf(t, f.read(t, f.userA)); e["department"] != "Eng" {
		t.Errorf("read %v", e)
	}
}

// An attribute can be a claim, and a claim can be what a relying party decides
// on, so an upstream may no more rewrite an administrator's than their address.
// Resent as it stands is not a rewrite: that would fail a sync for ever.
func TestAnUpstreamCannotRewriteAnAdministratorsAttributes(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "department", Personal: true})
	ext := scim.EnterpriseSchema
	if status, _ := f.patch(t, f.userA, `[{"op":"add","path":"`+ext+`:department","value":"Eng"}]`); status != http.StatusOK {
		t.Fatalf("setting it answered %d", status)
	}
	userID := f.userIDFor(t, f.userA)
	group, _ := f.localGroup(t, fmt.Sprintf("may-act-%d", time.Now().UnixNano()), true)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, userID, f.orgID); err != nil {
		t.Fatal(err)
	}

	if status, body := f.patch(t, f.userA, `[{"op":"add","path":"`+ext+`:department","value":"Eng"}]`); status != http.StatusOK {
		t.Errorf("the same value again answered %d: %v", status, body)
	}
	if status, body := f.patch(t, f.userA, `[{"op":"add","path":"`+ext+`:department","value":"Finance"}]`); status != http.StatusForbidden {
		t.Errorf("a changed value answered %d: %v", status, body)
	}
	if status, body := f.patch(t, f.userA, `[{"op":"remove","path":"`+ext+`:department"}]`); status != http.StatusForbidden {
		t.Errorf("clearing it answered %d: %v", status, body)
	}
	if e := enterpriseOf(t, f.read(t, f.userA)); e["department"] != "Eng" {
		t.Errorf("read %v", e)
	}
}

// A list answers with the extension and does not ask once per person: a personal
// attribute is the default, so every value on a page is sealed.
func TestAPageOfPeopleReadsTheExtensionInOneGo(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "department", Personal: true})
	ext := scim.EnterpriseSchema
	for _, id := range []string{f.userA, f.userB} {
		if status, _ := f.patch(t, id, `[{"op":"add","path":"`+ext+`:department","value":"Eng"}]`); status != http.StatusOK {
			t.Fatal(status)
		}
	}
	count := func() (int64, map[string]any) {
		t.Helper()
		before := f.queries.n.Load()
		status, body := f.do(t, http.MethodGet, "/scim/v2/Users?count=200", "")
		if status != http.StatusOK {
			t.Fatalf("answered %d", status)
		}
		return f.queries.n.Load() - before, body
	}
	few, body := count()
	for _, r := range body["Resources"].([]any) {
		if enterpriseOf(t, r.(map[string]any))["department"] != "Eng" {
			t.Errorf("a resource read %v", r)
		}
	}
	for range 5 {
		_, id := f.provisionUser(t, "more")
		f.patch(t, id, `[{"op":"add","path":"`+ext+`:department","value":"Eng"}]`)
	}
	if many, _ := count(); many != few {
		t.Errorf("a page of 2 took %d statements and of 7 took %d", few, many)
	}
}

// Erasure destroys the key. The person's resource stays answerable, without a
// value nobody can read any more.
func TestAnErasedValueIsNotShown(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "department", Personal: true}, store.Attribute{Name: "cost_center"})
	ext := scim.EnterpriseSchema
	f.patch(t, f.userA, `[{"op":"add","value":{"`+ext+`":{"department":"Eng","costCenter":"42"}}}]`)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.subject_keys SET wrapped_dek = NULL, erased_at = now() WHERE subject_id = $1::uuid`,
		f.userIDFor(t, f.userA)); err != nil {
		t.Fatal(err)
	}
	e := enterpriseOf(t, f.read(t, f.userA))
	if _, shown := e["department"]; shown || e["costCenter"] != "42" {
		t.Errorf("read %v: the organisation's value stays, the person's is gone", e)
	}
}
