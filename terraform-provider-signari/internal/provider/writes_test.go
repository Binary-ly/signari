package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// versionedServer holds one configuration version for the whole deployment,
// as the Admin API does: every write must name it in If-Match, when it sends
// one, and moves it on by one. foreign is a write made by somebody else.
type versionedServer struct {
	mu      sync.Mutex
	version int64
	refused int
}

func (s *versionedServer) foreign() {
	s.mu.Lock()
	s.version++
	s.mu.Unlock()
}

func newVersionedServer(t *testing.T, version int64) (*versionedServer, *httptest.Server) {
	t.Helper()
	vs := &versionedServer{version: version}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs.mu.Lock()
		defer vs.mu.Unlock()
		if r.Method != http.MethodGet {
			if m := r.Header.Get("If-Match"); m != "" {
				want, _ := strconv.ParseInt(strings.Trim(m, `"`), 10, 64)
				if want != vs.version {
					vs.refused++
					w.WriteHeader(http.StatusPreconditionFailed)
					fmt.Fprintf(w, `{"error":"precondition_failed","expected_version":%d,"current_version":%d}`,
						want, vs.version)
					return
				}
			}
			vs.version++
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, vs.version))
		fmt.Fprintf(w, `{"client_id":"app","display_name":"An app","org_id":"org-1","client_type":"confidential",
			"enabled":true,"redirect_uris":["https://app.example/cb"],"config_version":%d}`, vs.version)
	}))
	t.Cleanup(srv.Close)
	return vs, srv
}

// update runs one resource's update, its state read at version read.
func update(t *testing.T, r *clientResource, read int64) *resource.UpdateResponse {
	t.Helper()
	_, ty := clientSchema(t)
	resp := &resource.UpdateResponse{State: clientState(t, r, ty, true, 0)}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  tfsdk.Plan(clientState(t, r, ty, false, 0)),
		State: clientState(t, r, ty, true, read),
	}, resp)
	return resp
}

// Two resources changed in one apply both land (0.45). The version is the
// deployment's, so the first write moves it past what the plan read for the
// second; the second was refused with 412, the apply's own write reported as
// somebody else's.
func TestEveryWriteOfOneApplyLands(t *testing.T) {
	vs, srv := newVersionedServer(t, 10)
	r := newResource(t, srv.URL, true)
	for i := range 3 {
		if resp := update(t, r, 10); resp.Diagnostics.HasError() {
			t.Fatalf("write %d of the apply, every resource read at 10: %v", i+1, resp.Diagnostics)
		}
	}
	// And in parallel, as Terraform applies them.
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := update(t, r, 10); resp.Diagnostics.HasError() {
				errs <- fmt.Sprint(resp.Diagnostics)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("a parallel write of the apply was refused: %s", e)
	}
	if vs.refused != 0 {
		t.Errorf("the server refused %d of the apply's own writes", vs.refused)
	}
}

// What the guarantee is for still holds: a write by somebody else, before the
// apply or between two of its writes, is refused, not overwritten.
func TestAWriteBySomebodyElseIsStillRefused(t *testing.T) {
	vs, srv := newVersionedServer(t, 10)
	r := newResource(t, srv.URL, true)
	vs.foreign()
	if resp := update(t, r, 10); !resp.Diagnostics.HasError() {
		t.Fatal("a write made after the plan read 10 was overwritten")
	}

	vs, srv = newVersionedServer(t, 20)
	r = newResource(t, srv.URL, true)
	if resp := update(t, r, 20); resp.Diagnostics.HasError() {
		t.Fatalf("the apply's first write: %v", resp.Diagnostics)
	}
	vs.foreign()
	if resp := update(t, r, 20); !resp.Diagnostics.HasError() {
		t.Fatal("a write made between two of the apply's writes was overwritten")
	}
	// Nor does a resource read after it inherit the apply's head.
	if resp := update(t, r, 22); resp.Diagnostics.HasError() {
		t.Fatalf("a resource read after the other write, at 22: %v", resp.Diagnostics)
	}
}
