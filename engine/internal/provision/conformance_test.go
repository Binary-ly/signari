package provision

import "testing"

// Every provisioner must satisfy the same interface.
//
// A compile-time assertion rather than a runtime one: a target that does not
// implement the whole interface should fail to build, not fail on the first
// account somebody tries to create.
var (
	_ Provisioner = (*Google)(nil)
	_ Provisioner = (*Entra)(nil)
	_ Provisioner = SCIM{}
)

func TestProvisionersConform(t *testing.T) {
	// The assertions above are the test. This exists so the file is a test file
	// and the assertions are checked by `go test` as well as `go build`.
}
