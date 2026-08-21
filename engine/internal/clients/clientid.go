package clients

import (
	"fmt"
	"regexp"
)

// uuidShaped matches the canonical 8-4-4-4-12 hexadecimal form.
//
// Deliberately shape-only. Whether the value is a *real* user's identifier is
// not the question and could not be answered here anyway -- the point is that
// nothing which LOOKS like a subject may sit in a claim that is compared against
// one.
var uuidShaped = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateClientID refuses an identifier that could be mistaken for a person.
//
// # The confusion this prevents
//
// RFC 9700 §2.6: authorization servers "SHOULD NOT allow clients to influence
// their `client_id` or any other claim that could cause confusion with a genuine
// resource owner".
//
// In this engine a user's `sub` is their UUID, and the client_credentials grant
// puts the CLIENT's identifier in `sub` -- correctly, because the client is the
// subject when it acts for itself. Those two facts are individually right and
// together they mean a client registered as `550e8400-e29b-41d4-a716-446655440000`
// obtains tokens whose `sub` is indistinguishable from that user's.
//
// # Why this is not already covered
//
// Our own /userinfo is safe, and only by coincidence: it requires the `openid`
// scope, and the client_credentials grant refuses `openid` because there is no
// user to authenticate. Two separate decisions happen to line up. Nothing states
// the property, no test asserts it, and either decision could be revisited for
// good reasons by somebody who never learns what else it was holding up.
//
// It also does nothing for the resource servers we do not write. A customer's API
// that reads `sub` and looks up a user is the ordinary way to build one, and it
// would be confused. That is the deputy this refusal protects.
//
// Dynamic registration is already safe -- it mints `dyn_` plus 24 random bytes and
// the client cannot influence it -- so this is for the paths where an operator or
// an import chooses the value.
func ValidateClientID(id string) error {
	if id == "" {
		return fmt.Errorf("a client_id is required")
	}
	if uuidShaped.Match([]byte(id)) {
		return fmt.Errorf("%q is shaped like a UUID, and a user's subject identifier "+
			"is a UUID. The client_credentials grant puts the client_id in `sub`, so "+
			"this client's tokens would be indistinguishable from that user's at any "+
			"resource server that reads `sub` (RFC 9700 section 2.6). Choose a name "+
			"rather than an identifier", id)
	}
	return nil
}
