package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The operations cap, RFC 7644 §3.5.2 plus a limit the RFC does not set.
//
// The body cap bounds a PATCH in bytes; this bounds it in WORK. A minimal
// operation is about thirty bytes, so a compliant 1 MB body carries tens of
// thousands of them, and on a group PATCH each one can be a membership write.
func opsJSON(n int, op string) PatchRequest {
	var b strings.Builder
	b.WriteString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"op":%q,"path":"members","value":[{"value":"u-%d"}]}`, op, i)
	}
	b.WriteString(`]}`)

	var req PatchRequest
	if err := json.Unmarshal([]byte(b.String()), &req); err != nil {
		panic(err)
	}
	return req
}

func TestAPatchIsBoundedInWorkNotOnlyInBytes(t *testing.T) {
	// At the limit: accepted. A cap that rejects the boundary would silently
	// break a client batching to exactly the documented number.
	if _, err := ApplyGroupPatch(opsJSON(MaxPatchOperations, "add")); err != nil {
		t.Fatalf("%d operations refused, but that is the documented limit: %v",
			MaxPatchOperations, err)
	}
	if _, err := ApplyUserPatch(opsJSON(MaxPatchOperations, "add")); err != nil {
		t.Fatalf("user PATCH at the limit refused: %v", err)
	}

	// One over: refused, and refused as tooMany so the caller can split and
	// retry rather than treat it as a permanent failure.
	for name, apply := range map[string]func(PatchRequest) error{
		"group": func(r PatchRequest) error { _, err := ApplyGroupPatch(r); return err },
		"user":  func(r PatchRequest) error { _, err := ApplyUserPatch(r); return err },
	} {
		err := apply(opsJSON(MaxPatchOperations+1, "add"))
		if err == nil {
			t.Errorf("%s: %d operations accepted; one authorised call becomes an "+
				"unbounded amount of work", name, MaxPatchOperations+1)
			continue
		}
		if !errors.Is(err, ErrTooManyOperations) {
			t.Errorf("%s: refused, but not as ErrTooManyOperations, so the handler "+
				"cannot answer with scimType tooMany: %v", name, err)
		}
	}

	// The pre-existing rule still holds: no operations is still an error, not a
	// silent success. A PATCH read as a no-op is reported to the upstream as
	// done, and a deactivation that never happened looks applied.
	if _, err := ApplyGroupPatch(opsJSON(0, "add")); err == nil {
		t.Error("a PATCH with no operations was accepted")
	}
}
