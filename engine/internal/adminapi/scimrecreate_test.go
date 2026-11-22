package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/store"
)

// listedTarget is a fake target that lists its accounts, answers for what it no
// longer has, and can lose them.
func listedTarget(t *testing.T) *fakeTarget {
	t.Helper()
	f := newFakeTarget(t)
	f.lists = true
	return f
}

type recreateFixture struct {
	s    *Server
	org  string
	fake *fakeTarget
	base string
}

func newRecreateFixture(t *testing.T, onDeactivate string, recreate bool, people int) *recreateFixture {
	t.Helper()
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	fake := listedTarget(t)
	s.targetClient = func() (*http.Client, error) { return fake.Client(), nil }
	if err := provision.AddTarget(ctx, s.db, s.root, org, provision.TargetSpec{Slug: "drift", BaseURL: fake.URL,
		Token: "a-token-the-target-issued", OnDeactivate: onDeactivate, RecreateMissing: recreate}); err != nil {
		t.Fatal(err)
	}
	f := &recreateFixture{s: s, org: org, fake: fake, base: "/admin/organizations/" + org + "/scim-targets/drift"}
	for i := range people {
		f.person(t, fmt.Sprintf("p%d-%d", i, time.Now().UnixNano()))
	}
	return f
}

func (f *recreateFixture) person(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := f.s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, username, email, status, user_handle)
		VALUES ($1::uuid, $2, $2 || '@example.test', 'active', decode(md5(random()::text) || md5(random()::text) ||
		        md5(random()::text) || md5(random()::text), 'hex'))
		RETURNING id::text`, f.org, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// Before the organisation's cleanup, which a person in it would refuse.
	t.Cleanup(func() { _, _ = f.s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id) })
	return id
}

func (f *recreateFixture) sync(t *testing.T, apply bool) map[string]any {
	t.Helper()
	rec := call(t, f.s, http.MethodPost, f.base+"/sync", testToken, map[string]any{"apply": apply})
	if rec.Code != http.StatusOK {
		t.Fatalf("syncing: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// linkOf reads who holds what at the target.
func (f *recreateFixture) links(t *testing.T) map[string]string {
	t.Helper()
	rows, err := f.s.db.Query(context.Background(), `SELECT l.user_id::text, l.remote_id FROM core.scim_links l
		JOIN core.scim_targets t ON t.id = l.target_id WHERE t.org_id = $1::uuid`, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var user, remote string
		if err := rows.Scan(&user, &remote); err != nil {
			t.Fatal(err)
		}
		out[user] = remote
	}
	return out
}

// lose deletes accounts at the target, as somebody there would by hand.
func (f *recreateFixture) lose(ids ...string) {
	f.fake.mu.Lock()
	defer f.fake.mu.Unlock()
	for _, id := range ids {
		delete(f.fake.users, id)
	}
}

// An account deleted at the target stays deleted, with a link that says it is
// there: nothing looked. Asked to, a sync finds out and gives it back.
func TestASyncGivesBackAnAccountTheTargetLost(t *testing.T) {
	f := newRecreateFixture(t, "deactivate", true, 8)
	if got := f.sync(t, true); got["created"] != float64(8) || got["recreated"] != float64(0) {
		t.Fatalf("the first sync: %v", got)
	}
	before := f.links(t)
	var user, remote string
	for user, remote = range before {
		break
	}
	f.lose(remote)

	// A preview says so and sends nothing.
	if got := f.sync(t, false); got["recreated"] != float64(1) || got["created"] != float64(1) {
		t.Errorf("the preview: %v", got)
	}
	if after := f.links(t); after[user] != remote {
		t.Errorf("a preview moved the link to %q", after[user])
	}

	if got := f.sync(t, true); got["recreated"] != float64(1) || got["created"] != float64(1) || got["failed"] != float64(0) {
		t.Errorf("the sync: %v", got)
	}
	after := f.links(t)
	if after[user] == remote || after[user] == "" {
		t.Errorf("the link is %q, was %q", after[user], remote)
	}
	f.fake.mu.Lock()
	there := f.fake.users[after[user]]
	f.fake.mu.Unlock()
	if !there {
		t.Errorf("the target has no %q", after[user])
	}

	// Once. An account that is there is left alone.
	if got := f.sync(t, true); got["recreated"] != float64(0) || got["created"] != float64(0) {
		t.Errorf("another sync: %v", got)
	}
}

// Off, which is the default: somebody removed there may have been meant to be,
// and looking means listing the target on every sync.
func TestAMissingAccountStaysMissingUnlessAskedFor(t *testing.T) {
	f := newRecreateFixture(t, "deactivate", false, 1)
	f.sync(t, true)
	for _, remote := range f.links(t) {
		f.lose(remote)
	}
	f.fake.mu.Lock()
	f.fake.listed = 0
	f.fake.mu.Unlock()
	if got := f.sync(t, true); got["created"] != float64(0) || got["recreated"] != float64(0) {
		t.Errorf("the sync: %v", got)
	}
	f.fake.mu.Lock()
	listed := f.fake.listed
	f.fake.mu.Unlock()
	if listed != 0 {
		t.Errorf("the target was listed %d times", listed)
	}
}

// A list that came back wrong is everybody having been deleted, and creating
// everybody again is a duplicate of the company at a target that allows one.
func TestAWrongListRecreatesNobody(t *testing.T) {
	f := newRecreateFixture(t, "deactivate", true, 8)
	f.sync(t, true)
	before := f.links(t)
	f.fake.mu.Lock()
	f.fake.listNothing = true
	f.fake.mu.Unlock()

	got := f.sync(t, true)
	if got["created"] != float64(0) || got["recreated"] != float64(0) || got["failed"] != float64(1) {
		t.Fatalf("the sync: %v", got)
	}
	failures, _ := got["failures"].([]any)
	if len(failures) != 1 || !strings.Contains(fmt.Sprint(failures[0]), "8 of the 8") {
		t.Errorf("it said %v", failures)
	}
	after := f.links(t)
	for user, remote := range before {
		if after[user] != remote {
			t.Errorf("a link moved to %q", after[user])
		}
	}

	// A few of many is believed.
	f.fake.mu.Lock()
	f.fake.listNothing = false
	f.fake.mu.Unlock()
	lost := 0
	for _, remote := range before {
		if lost == 2 {
			break
		}
		f.lose(remote)
		lost++
	}
	if got := f.sync(t, true); got["recreated"] != float64(2) {
		t.Errorf("two of eight: %v", got)
	}
}

// Five is a share to doubt and four is not, so a small organisation is not held
// to a percentage of nobody.
func TestASmallLossIsNotDoubted(t *testing.T) {
	f := newRecreateFixture(t, "deactivate", true, 4)
	f.sync(t, true)
	for _, remote := range f.links(t) {
		f.lose(remote)
	}
	if got := f.sync(t, true); got["recreated"] != float64(4) {
		t.Errorf("all four: %v", got)
	}
}

// Somebody who left, whose account the target no longer has, is done with: a
// deactivation answered 404 was a failure on every sync for ever.
func TestDeactivatingWhatIsAlreadyGoneIsDone(t *testing.T) {
	for _, onDeactivate := range []string{"deactivate", "delete"} {
		t.Run(onDeactivate, func(t *testing.T) {
			f := newRecreateFixture(t, onDeactivate, false, 1)
			f.sync(t, true)
			var user, remote string
			for user, remote = range f.links(t) {
				break
			}
			f.lose(remote)
			f.fake.mu.Lock()
			f.fake.strict = true
			f.fake.mu.Unlock()
			if _, err := f.s.db.Exec(context.Background(), `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, user); err != nil {
				t.Fatal(err)
			}
			got := f.sync(t, true)
			if got["failed"] != float64(0) {
				t.Errorf("the sync: %v", got)
			}
			if got := f.sync(t, true); got["failed"] != float64(0) || got["deactivated"] != float64(0) || got["deleted"] != float64(0) {
				t.Errorf("the next sync: %v", got)
			}
			if links := f.links(t); len(links) != 0 {
				t.Errorf("links are %v", links)
			}
		})
	}
}

func TestRecreateIsSetLikeAnyOtherSetting(t *testing.T) {
	f := newRecreateFixture(t, "deactivate", false, 0)
	read := func() bool {
		t.Helper()
		got, err := store.SCIMTargets(context.Background(), f.s.db, f.org)
		if err != nil || len(got) != 1 {
			t.Fatalf("read %v, %v", got, err)
		}
		return got[0].RecreateMissing
	}
	if read() {
		t.Fatal("on by default")
	}
	if rec := call(t, f.s, http.MethodPatch, f.base, testToken, map[string]any{"recreate_missing": true}); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if !read() {
		t.Error("not set")
	}
	rec := call(t, f.s, http.MethodGet, "/admin/organizations/"+f.org+"/scim-targets", testToken, nil)
	if !strings.Contains(rec.Body.String(), `"recreate_missing":true`) {
		t.Errorf("the list read %s", rec.Body.String())
	}
}
