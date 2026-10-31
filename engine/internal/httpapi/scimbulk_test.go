package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

type bulkLine struct {
	Location string         `json:"location"`
	Method   string         `json:"method"`
	BulkID   string         `json:"bulkId"`
	Status   string         `json:"status"`
	Response map[string]any `json:"response"`
}

// bulk sends operations and returns one line per operation that ran.
func (f *scimFixture) bulk(t *testing.T, extra, operations string) []bulkLine {
	t.Helper()
	status, body := f.do(t, http.MethodPost, "/scim/v2/Bulk",
		`{"schemas":["`+scimBulkRequest+`"]`+extra+`,"Operations":`+operations+`}`)
	if status != http.StatusOK {
		t.Fatalf("answered %d: %v", status, body)
	}
	schemas, _ := body["schemas"].([]any)
	if !slices.Contains(schemas, any(scimBulkResponse)) {
		t.Errorf("schemas is %v", schemas)
	}
	raw, err := json.Marshal(body["Operations"])
	if err != nil {
		t.Fatal(err)
	}
	var lines []bulkLine
	if err := json.Unmarshal(raw, &lines); err != nil {
		t.Fatal(err)
	}
	return lines
}

func idOf(t *testing.T, l bulkLine) string {
	t.Helper()
	i := strings.LastIndex(l.Location, "/")
	if i < 0 {
		t.Fatalf("no location: %+v", l)
	}
	return l.Location[i+1:]
}

func bulkUser(bulkID, name string) string {
	return fmt.Sprintf(`{"method":"POST","path":"/Users","bulkId":%q,
		"data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"ext-%s","userName":%q}}`,
		bulkID, name, name)
}

// RFC 7644 §3.7.2's own job: a person, and a group with them in it.
func TestABulkRequestCreatesAPersonAndTheirGroup(t *testing.T) {
	f := newSCIMFixture(t)
	name := fmt.Sprintf("alice-%d", time.Now().UnixNano())
	group := func(id string) string {
		return fmt.Sprintf(`{"method":"POST","path":"/Groups","bulkId":"group",
			"data":{"externalId":"ext-g-%s","displayName":"Tour %s","members":[{"value":%q}]}}`, name, id, "bulkId:person")
	}

	lines := f.bulk(t, "", `[`+bulkUser("person", name)+`,`+group("1")+`]`)
	if len(lines) != 2 || lines[0].Status != "201" || lines[1].Status != "201" {
		t.Fatalf("answered %+v", lines)
	}
	if lines[0].Method != "POST" || lines[0].BulkID != "person" || lines[1].BulkID != "group" {
		t.Errorf("answered %+v: a client maps a bulkId back from these", lines)
	}
	if !f.inGroup(t, idOf(t, lines[1]), idOf(t, lines[0])) {
		t.Error("the person is not in the group: the reference was not replaced")
	}
	if status, body := f.do(t, http.MethodGet, lines[0].Location, ""); status != http.StatusOK {
		t.Errorf("the location answered %d: %v", status, body)
	}
}

// The group named first: it waits for the person, and the answer stays in the
// order the client asked in.
func TestAReferenceWaitsForWhatItNames(t *testing.T) {
	f := newSCIMFixture(t)
	name := fmt.Sprintf("forward-%d", time.Now().UnixNano())
	lines := f.bulk(t, "", fmt.Sprintf(`[
		{"method":"POST","path":"/Groups","bulkId":"group",
		 "data":{"externalId":"ext-g-%[1]s","displayName":"Forward %[1]s","members":[{"value":"bulkId:person"}]}},
		%[2]s]`, name, bulkUser("person", name)))
	if len(lines) != 2 || lines[0].BulkID != "group" || lines[1].BulkID != "person" {
		t.Fatalf("answered %+v", lines)
	}
	if lines[0].Status != "201" || lines[1].Status != "201" {
		t.Fatalf("answered %+v", lines)
	}
	if !f.inGroup(t, idOf(t, lines[0]), idOf(t, lines[1])) {
		t.Error("the person is not in the group")
	}
}

// A bulkId names a resource in a path as it does in data, and an operation runs
// exactly as its single request would.
func TestABulkRequestChangesAndDeletes(t *testing.T) {
	f := newSCIMFixture(t)
	name := fmt.Sprintf("life-%d", time.Now().UnixNano())
	lines := f.bulk(t, "", fmt.Sprintf(`[%s,
		{"method":"PATCH","path":"/Users/bulkId:person","data":{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}},
		{"method":"PUT","path":"/Users/%[2]s","data":{"externalId":"whatever","userName":%[3]q,"displayName":"Put"}},
		{"method":"DELETE","path":"/Users/%[4]s"}]`, bulkUser("person", name), f.userA, f.nameA, f.userB))
	if len(lines) != 4 {
		t.Fatalf("answered %+v", lines)
	}
	for i, want := range []string{"201", "200", "200", "204"} {
		if lines[i].Status != want {
			t.Errorf("operation %d answered %+v, want %s", i, lines[i], want)
		}
	}
	if lines[1].Location != "/scim/v2/Users/"+idOf(t, lines[0]) {
		t.Errorf("a PATCH's location is %q", lines[1].Location)
	}
	if got := f.read(t, idOf(t, lines[0]))["displayName"]; got != "Renamed" {
		t.Errorf("read %v", got)
	}
	if got := f.read(t, f.userA)["displayName"]; got != "Put" {
		t.Errorf("read %v", got)
	}
	// This source's policy is to deactivate, and a bulk DELETE keeps to it.
	if got := f.read(t, f.userB)["active"]; got != false {
		t.Errorf("the deleted person reads active %v", got)
	}
}

// A failure is the operation's and the rest carry on, each reported as its single
// request would have been, and a failed POST has no location.
func TestABulkFailureIsTheOperations(t *testing.T) {
	f := newSCIMFixture(t)
	name := fmt.Sprintf("after-%d", time.Now().UnixNano())
	lines := f.bulk(t, "", fmt.Sprintf(`[
		{"method":"POST","path":"/Users","bulkId":"bad","data":{"userName":"no-external-id"}},
		{"method":"DELETE","path":"/Users/00000000-0000-0000-0000-000000000000"},
		{"method":"PATCH","path":"/Users/%s","data":{"Operations":[{"op":"explode"}]}},
		%s]`, f.userA, bulkUser("good", name)))
	if len(lines) != 4 {
		t.Fatalf("answered %+v", lines)
	}
	want := []string{"400", "404", "400", "201"}
	for i := range want {
		if lines[i].Status != want[i] {
			t.Errorf("operation %d answered %+v, want %s", i, lines[i], want[i])
		}
	}
	if lines[0].Location != "" {
		t.Errorf("a failed POST has a location: %q", lines[0].Location)
	}
	if lines[1].Location == "" || lines[2].Location == "" {
		t.Errorf("a failed change names what it was of: %+v", lines[1:3])
	}
	for _, l := range lines[:3] {
		if l.Response == nil || l.Response["detail"] == "" {
			t.Errorf("a failure came without its error: %+v", l)
		}
	}
	if lines[3].Response != nil {
		t.Errorf("a success came with a body: %+v", lines[3])
	}
}

// failOnErrors stops the job, and what never ran is not reported as run.
func TestFailOnErrorsStopsTheJob(t *testing.T) {
	f := newSCIMFixture(t)
	name := fmt.Sprintf("never-%d", time.Now().UnixNano())
	bad := `{"method":"DELETE","path":"/Users/00000000-0000-0000-0000-000000000000"}`
	lines := f.bulk(t, `,"failOnErrors":2`, `[`+bad+`,`+bad+`,`+bulkUser("never", name)+`]`)
	if len(lines) != 2 {
		t.Fatalf("answered %+v", lines)
	}
	if got := f.list(t, "Users", `userName eq "`+name+`"`); len(got) != 0 {
		t.Errorf("an operation past the limit ran: %v", got)
	}
	lines = f.bulk(t, `,"failOnErrors":2`, `[`+bad+`,`+bulkUser("ran", name)+`]`)
	if len(lines) != 2 || lines[1].Status != "201" {
		t.Errorf("under the limit answered %+v", lines)
	}
}

func TestABulkReferenceThatCannotBeKept(t *testing.T) {
	f := newSCIMFixture(t)
	run := time.Now().UnixNano()
	member := func(bulkID, ref string, n int) string {
		return fmt.Sprintf(`{"method":"POST","path":"/Groups","bulkId":%q,
			"data":{"externalId":"ext-%[1]s-%[3]d","displayName":"Refs %[1]s %[3]d","members":[{"value":"bulkId:%[2]s"}]}}`,
			bulkID, ref, n, run)
	}
	// Names nothing in the request.
	lines := f.bulk(t, "", `[`+member("a", "nobody", 1)+`]`)
	if len(lines) != 1 || lines[0].Status != "400" {
		t.Errorf("a reference to nothing answered %+v", lines)
	}
	// Names what failed: quietly leaving the member out would be a group the
	// client believes is complete.
	lines = f.bulk(t, "", `[
		{"method":"POST","path":"/Users","bulkId":"bad","data":{"userName":"no-external-id"}},`+
		member("b", "bad", 2)+`]`)
	if len(lines) != 2 || lines[1].Status != "409" {
		t.Errorf("a reference to a failure answered %+v", lines)
	}
	// Names each other. This engine's groups hold people, so a cycle takes two
	// that wait on one another, which the RFC lets a server answer with a 409.
	lines = f.bulk(t, "", `[`+member("c", "d", 3)+`,`+member("d", "c", 4)+`,`+
		bulkUser("free", fmt.Sprintf("free-%d", run))+`]`)
	if len(lines) != 3 {
		t.Fatalf("answered %+v", lines)
	}
	if lines[0].Status != "409" || lines[1].Status != "409" || lines[2].Status != "201" {
		t.Errorf("a cycle answered %+v", lines)
	}
	// Used twice, the second is refused and the first stands.
	name := fmt.Sprintf("twice-%d", run)
	lines = f.bulk(t, "", `[`+bulkUser("same", name)+`,`+bulkUser("same", name+"-2")+`]`)
	if len(lines) != 2 || lines[0].Status != "201" || lines[1].Status != "400" {
		t.Errorf("a repeated bulkId answered %+v", lines)
	}
	// A POST needs one.
	lines = f.bulk(t, "", `[{"method":"POST","path":"/Users","data":{}}]`)
	if len(lines) != 1 || lines[0].Status != "400" {
		t.Errorf("a POST with no bulkId answered %+v", lines)
	}
}

// RFC 7644's example of an extension's reference, with nothing in this code
// knowing what a manager is.
func TestAnExtensionsReferenceIsReplaced(t *testing.T) {
	f := newSCIMFixture(t)
	f.declare(t, store.Attribute{Name: "manager"}, store.Attribute{Name: "employee_number"})
	run := time.Now().UnixNano()
	lines := f.bulk(t, "", fmt.Sprintf(`[%s,
		{"method":"POST","path":"/Users","bulkId":"bob","data":{
			"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","%[2]s"],
			"externalId":"ext-bob-%[3]d","userName":"bob-%[3]d",
			"%[2]s":{"employeeNumber":"11250","manager":{"value":"bulkId:alice"}}}}]`,
		bulkUser("alice", fmt.Sprintf("alice-%d", run)), scim.EnterpriseSchema, run))
	if len(lines) != 2 || lines[1].Status != "201" {
		t.Fatalf("answered %+v", lines)
	}
	e := enterpriseOf(t, f.read(t, idOf(t, lines[1])))
	if m, _ := e["manager"].(map[string]any); m["value"] != idOf(t, lines[0]) {
		t.Errorf("the manager is %v", e["manager"])
	}
}

// What is refused alone is refused in a bulk: there is no second path through.
func TestABulkOperationIsHeldToWhatARequestIs(t *testing.T) {
	f := newSCIMFixture(t)
	group, _ := f.localGroup(t, fmt.Sprintf("may-act-%d", time.Now().UnixNano()), true)
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, f.userIDFor(t, f.userA), f.orgID); err != nil {
		t.Fatal(err)
	}
	lines := f.bulk(t, "", fmt.Sprintf(`[{"method":"PATCH","path":"/Users/%s","data":{"Operations":[
		{"op":"replace","path":"emails[primary eq true].value","value":"attacker@example.test"}]}}]`, f.userA))
	if len(lines) != 1 || lines[0].Status != "403" {
		t.Errorf("changing an administrator's address answered %+v", lines)
	}

	// Another source's resource is another source's, and not found.
	other := newSCIMFixture(t)
	lines = other.bulk(t, "", fmt.Sprintf(`[{"method":"DELETE","path":"/Users/%s"}]`, f.userB))
	if len(lines) != 1 || lines[0].Status != "404" {
		t.Errorf("another source's person answered %+v", lines)
	}
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Users/"+f.userB, ""); status != http.StatusOK {
		t.Errorf("the person answered %d", status)
	}

	// Only what the RFC lists, at what it can reach.
	for _, op := range []string{
		`{"method":"GET","path":"/Users/` + f.userA + `"}`,
		`{"method":"POST","path":"/Users/` + f.userA + `","bulkId":"x"}`,
		`{"method":"DELETE","path":"/Users"}`,
		`{"method":"DELETE","path":"/Users/"}`,
		`{"method":"PATCH","path":"/ServiceProviderConfig"}`,
		`{"method":"POST","path":"/Bulk","bulkId":"y","data":{}}`,
		`{"method":"DELETE","path":"Users/` + f.userA + `"}`,
		`{"method":"DELETE","path":"/Users/` + f.userA + `/extra"}`,
	} {
		lines := f.bulk(t, "", `[`+op+`]`)
		if len(lines) != 1 || lines[0].Status != "400" {
			t.Errorf("%s answered %+v", op, lines)
		}
	}
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Users/"+f.userA, ""); status != http.StatusOK {
		t.Errorf("the person answered %d", status)
	}
}

func TestABulkRequestIsHeldToItsLimits(t *testing.T) {
	f := newSCIMFixture(t)
	_, config := f.do(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	bulk, _ := config["bulk"].(map[string]any)
	if bulk["supported"] != true || bulk["maxOperations"] != float64(scimMaxBulkOperations) ||
		bulk["maxPayloadSize"] != float64(scimMaxBulkPayload) {
		t.Errorf("ServiceProviderConfig says %v", bulk)
	}

	one := `{"method":"DELETE","path":"/Users/00000000-0000-0000-0000-000000000000"}`
	status, body := f.do(t, http.MethodPost, "/scim/v2/Bulk", `{"schemas":["`+scimBulkRequest+`"],"Operations":[`+
		strings.TrimSuffix(strings.Repeat(one+",", scimMaxBulkOperations+1), ",")+`]}`)
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(fmt.Sprint(body["detail"]), "maxOperations") {
		t.Errorf("too many operations answered %d %v", status, body)
	}
	status, body = f.do(t, http.MethodPost, "/scim/v2/Bulk", `{"schemas":["`+scimBulkRequest+`"],"pad":"`+
		strings.Repeat("x", scimMaxBulkPayload)+`"}`)
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(fmt.Sprint(body["detail"]), fmt.Sprint(scimMaxBulkPayload)) {
		t.Errorf("too large a body answered %d %v", status, body)
	}

	for name, sent := range map[string]string{
		"not JSON":         `{`,
		"no schema":        `{"Operations":[` + one + `]}`,
		"no operations":    `{"schemas":["` + scimBulkRequest + `"],"Operations":[]}`,
		"a zero limit":     `{"schemas":["` + scimBulkRequest + `"],"failOnErrors":0,"Operations":[` + one + `]}`,
		"a limit of words": `{"schemas":["` + scimBulkRequest + `"],"failOnErrors":"one","Operations":[` + one + `]}`,
	} {
		if status, body := f.do(t, http.MethodPost, "/scim/v2/Bulk", sent); status != http.StatusBadRequest {
			t.Errorf("%s answered %d %v", name, status, body)
		}
	}
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Bulk", ""); status != http.StatusMethodNotAllowed {
		t.Errorf("a GET answered %d", status)
	}
	f.token = "not-a-token"
	if status, _ := f.do(t, http.MethodPost, "/scim/v2/Bulk", `{}`); status != http.StatusUnauthorized {
		t.Errorf("no token answered %d", status)
	}
}
