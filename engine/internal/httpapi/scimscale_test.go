package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// statementCount counts what a fixture's pool sends, so a cost that grows with
// the data shows as a number rather than as a slow machine.
type statementCount struct{ n atomic.Int64 }

func (c *statementCount) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	_ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *statementCount) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// seedPeople provisions n people straight into the tables and removes them
// with the test: the fixture's own cleanup cannot, since users hold their
// organisation.
func (f *scimFixture) seedPeople(t *testing.T, n int) []string {
	t.Helper()
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		SELECT $1::uuid, sha256(($1::text || i::text)::bytea), 'seed-' || i || '@example.test'
		FROM generate_series(1, $2::int) i`, f.orgID, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `
			DELETE FROM core.users WHERE org_id = $1::uuid AND email LIKE 'seed-%'`, f.orgID); err != nil {
			t.Errorf("removing the seeded people: %v", err)
		}
	})
	rows, err := f.pool.Query(ctx, `
		INSERT INTO core.scim_source_links (source_id, external_id, user_id, user_name)
		SELECT $1::uuid, u.email, u.id, u.email FROM core.users u
		WHERE u.org_id = $2::uuid AND u.email LIKE 'seed-%'
		RETURNING resource_id::text`, f.srcID, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// The members an upstream sends: each with its reference and display name,
// which is most of the body.
func memberList(ids []string) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf(`{"value":%q,"$ref":"https://idp.example.test/scim/v2/Users/%s","display":"Person %d"}`,
			id, id, i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func (f *scimFixture) memberCount(t *testing.T, groupResourceID string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.group_members gm
		JOIN core.scim_source_group_links l ON l.group_id = gm.group_id
		WHERE l.resource_id = $1::uuid`, groupResourceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A group of ten thousand fits in a request, as it did not (7.13): an
// upstream's body carries a reference and a name per member, past the megabyte
// a group was allowed, and the refusal said the body was not JSON. The ids are
// not provisioned, so the request is read in full and refused for that, which
// proves the limit without making ten thousand people.
func TestAGroupOfTenThousandFitsInARequest(t *testing.T) {
	f := newSCIMFixture(t)
	gid := f.createGroup(t, "Everyone")
	ids := make([]string, 10000)
	for i := range ids {
		ids[i] = uuid.NewString()
	}
	members := memberList(ids)
	if len(members) <= 1<<20 {
		t.Fatalf("the body is %d bytes, which the old limit took; it proves nothing", len(members))
	}
	for name, c := range map[string]struct{ method, body string }{
		"PUT":   {http.MethodPut, fmt.Sprintf(`{"displayName":"Everyone","members":%s}`, members)},
		"PATCH": {http.MethodPatch, fmt.Sprintf(`{"Operations":[{"op":"add","path":"members","value":%s}]}`, members)},
	} {
		status, out := f.do(t, c.method, "/scim/v2/Groups/"+gid, c.body)
		if status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["detail"]), ids[0]) {
			t.Errorf("%s of 10,000 unknown members gave %d %v; want them read, and the first named", name, status, out)
		}
	}
}

// Replacing a group is one statement for the members however many there are
// (7.13): it was two for each, reading each member past the index.
func TestTheCostOfAGroupDoesNotGrowWithItsMembers(t *testing.T) {
	f := newSCIMFixture(t)
	people := f.seedPeople(t, 300)
	gid := f.createGroup(t, "Everyone")
	path := "/scim/v2/Groups/" + gid
	spend := func(method, body string) (int64, time.Duration, map[string]any) {
		t.Helper()
		before, began := f.queries.n.Load(), time.Now()
		status, out := f.do(t, method, path, body)
		took := time.Since(began)
		if status != http.StatusOK {
			detail, _ := out["detail"].(string)
			t.Fatalf("%s gave %d: %s", method, status, detail)
		}
		return f.queries.n.Load() - before, took, out
	}
	replace := func(ids []string) (int64, time.Duration) {
		t.Helper()
		n, took, _ := spend(http.MethodPut, fmt.Sprintf(`{"displayName":"Everyone","members":%s}`, memberList(ids)))
		return n, took
	}

	few, _ := replace(people[:3])
	all, _ := replace(people)
	if got := f.memberCount(t, gid); got != len(people) {
		t.Fatalf("the group holds %d, want %d", got, len(people))
	}
	if all != few {
		t.Errorf("replacing 3 members took %d statements and %d took %d; the cost grows with the group",
			few, len(people), all)
	}

	// The same for a change to part of it, added and removed.
	patch := func(op string, ids []string) int64 {
		t.Helper()
		n, _, _ := spend(http.MethodPatch, fmt.Sprintf(`{"Operations":[{"op":%q,"path":"members","value":%s}]}`,
			op, memberList(ids)))
		return n
	}
	lessOne, lessMany := patch("remove", people[:1]), patch("remove", people[1:201])
	if got := f.memberCount(t, gid); got != len(people)-201 {
		t.Fatalf("after removing 201 the group holds %d", got)
	}
	if lessOne != lessMany {
		t.Errorf("removing 1 member took %d statements and 200 took %d", lessOne, lessMany)
	}
	moreOne, moreMany := patch("add", people[:1]), patch("add", people[1:201])
	if got := f.memberCount(t, gid); got != len(people) {
		t.Fatalf("after adding them back the group holds %d", got)
	}
	if moreOne != moreMany {
		t.Errorf("adding 1 member took %d statements and 200 took %d", moreOne, moreMany)
	}

	// Named twice is a member once, as a statement per member made it.
	replace([]string{people[0], people[0], people[1]})
	if got := f.memberCount(t, gid); got != 2 {
		t.Errorf("a list naming somebody twice left %d members, want 2", got)
	}
	// And one that is not provisioned still refuses the whole request, naming it.
	if status, out := f.do(t, http.MethodPut, path, fmt.Sprintf(
		`{"displayName":"Everyone","members":[{"value":%q},{"value":"00000000-0000-0000-0000-000000000000"}]}`,
		people[9])); status != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(out["detail"]), "00000000-0000-0000-0000-000000000000") {
		t.Errorf("an unknown member among known ones gave %d %v", status, out)
	}
	if got := f.memberCount(t, gid); got != 2 {
		t.Errorf("a refused replacement left %d members, want the 2 it had", got)
	}
}

// A page of groups reads their members once, not once per group (7.13), and
// each group keeps its own.
func TestAPageOfGroupsCostsTheSameHoweverLong(t *testing.T) {
	f := newSCIMFixture(t)
	people := f.seedPeople(t, 6)
	own := map[string][]string{}
	for i := 0; i < 3; i++ {
		ids := people[i*2 : i*2+2]
		own[f.createGroup(t, fmt.Sprintf("Page group %d", i), ids...)] = ids
	}
	list := func(query string) (int64, map[string]any) {
		t.Helper()
		before := f.queries.n.Load()
		status, out := f.do(t, http.MethodGet, "/scim/v2/Groups?"+query, "")
		if status != http.StatusOK {
			t.Fatalf("listing gave %d: %v", status, out)
		}
		return f.queries.n.Load() - before, out
	}
	one, _ := list("count=1")
	three, out := list("count=3")
	if one != three {
		t.Errorf("a page of 1 took %d statements and a page of 3 took %d", one, three)
	}
	resources, _ := out["Resources"].([]any)
	if len(resources) != 3 {
		t.Fatalf("the page held %d groups, want 3", len(resources))
	}
	for _, r := range resources {
		g, _ := r.(map[string]any)
		id, _ := g["id"].(string)
		got := memberIDs(g)
		want := append([]string(nil), own[id]...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("group %s lists %v, want %v", id, got, want)
		}
	}
}

// Walking the collection a page at a time meets everyone once, in both
// collections: index paging is what RFC 7644 §3.4.2.4 defines, and the read
// behind a page changed.
func TestWalkingAPageAtATimeMeetsEveryoneOnce(t *testing.T) {
	f := newSCIMFixture(t)
	people := f.seedPeople(t, 7)
	made := map[string]bool{}
	for i := 0; i < 5; i++ {
		made[f.createGroup(t, fmt.Sprintf("Walk group %d", i), people[i])] = true
	}
	walk := func(collection string) map[string]int {
		t.Helper()
		seen, total := map[string]int{}, 0
		for start := 1; ; start += 2 {
			status, out := f.do(t, http.MethodGet, fmt.Sprintf("/scim/v2/%s?startIndex=%d&count=2", collection, start), "")
			if status != http.StatusOK {
				t.Fatalf("page at %d gave %d: %v", start, status, out)
			}
			if got, _ := out["startIndex"].(float64); int(got) != start {
				t.Errorf("startIndex answered %v at %d", out["startIndex"], start)
			}
			n, _ := out["totalResults"].(float64)
			total = int(n)
			resources, _ := out["Resources"].([]any)
			if len(resources) == 0 {
				break
			}
			for _, r := range resources {
				res, _ := r.(map[string]any)
				id, _ := res["id"].(string)
				seen[id]++
			}
		}
		if len(seen) != total {
			t.Errorf("%s: met %d of %d", collection, len(seen), total)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("%s: met %s %d times", collection, id, n)
			}
		}
		return seen
	}
	if got := walk("Users"); len(got) != 9 { // the fixture's two and the seven
		t.Errorf("met %d users, want 9", len(got))
	}
	groups := walk("Groups")
	if len(groups) != len(made) {
		t.Errorf("met %d groups, want %d", len(groups), len(made))
	}
	for id := range made {
		if groups[id] != 1 {
			t.Errorf("group %s was not met", id)
		}
	}
}

// An id that cannot be a resource id is no such resource, on every verb and
// both collections. Comparing the uuid column rather than its text, which is
// what lets the index serve the read, must not make it a 500 an upstream
// retries forever.
func TestAnIdThatCannotBeOneIsNoSuchResource(t *testing.T) {
	f := newSCIMFixture(t)
	gid := f.createGroup(t, "Real")
	for _, id := range []string{"not-a-uuid", "1", strings.ToUpper(gid), "{" + gid + "}",
		strings.ReplaceAll(gid, "-", "")} {
		for _, collection := range []string{"Users", "Groups"} {
			for method, body := range map[string]string{
				http.MethodGet:    "",
				http.MethodPut:    `{"displayName":"x","userName":"x@example.test","externalId":"x","active":true}`,
				http.MethodPatch:  `{"Operations":[{"op":"replace","path":"displayName","value":"x"}]}`,
				http.MethodDelete: "",
			} {
				status, out := f.do(t, method, "/scim/v2/"+collection+"/"+id, body)
				if status != http.StatusNotFound {
					raw, _ := json.Marshal(out)
					t.Errorf("%s /%s/%s gave %d %s, want 404", method, collection, id, status, raw)
				}
			}
		}
	}
	// Named as a member, it is the upstream's mistake, with the reason.
	for _, value := range []string{"not-a-uuid", strings.ToUpper(f.userA)} {
		status, out := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, fmt.Sprintf(
			`{"Operations":[{"op":"add","path":"members","value":[{"value":%q}]}]}`, value))
		if status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["detail"]), "provision") {
			t.Errorf("member %q gave %d %v, want 400 with the reason", value, status, out)
		}
	}
}
