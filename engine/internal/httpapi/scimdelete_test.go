package httpapi

import (
	"context"
	"net/http"
	"testing"
)

// RFC 7644 §3.6 (specs/rfc7644.txt:2641-2644): a service provider "MUST return
// a 404 (Not Found) error code for all operations associated with the
// previously deleted resource". A second DELETE is one of them, as is a DELETE
// of an id that was never issued, which answered 204 as if somebody had gone.
func TestDeletingWhatIsGoneIsNotFound(t *testing.T) {
	f := newSCIMFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.scim_sources SET on_delete = 'delete' WHERE id = $1::uuid`, f.srcID); err != nil {
		t.Fatal(err)
	}
	gid := f.createGroup(t, "Going")
	for _, path := range []string{"/scim/v2/Groups/" + gid, "/scim/v2/Users/" + f.userA} {
		if status, out := f.do(t, http.MethodDelete, path, ""); status != http.StatusNoContent {
			t.Fatalf("DELETE %s gave %d %v", path, status, out)
		}
		for _, method := range []string{http.MethodDelete, http.MethodGet} {
			if status, out := f.do(t, method, path, ""); status != http.StatusNotFound {
				t.Errorf("%s %s after it was deleted gave %d %v, want 404", method, path, status, out)
			}
		}
	}
	for _, collection := range []string{"Users", "Groups"} {
		path := "/scim/v2/" + collection + "/00000000-0000-0000-0000-000000000000"
		if status, out := f.do(t, http.MethodDelete, path, ""); status != http.StatusNotFound {
			t.Errorf("DELETE of an id never issued gave %d %v, want 404", status, out)
		}
	}
}
