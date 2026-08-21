package oauth

import (
	"strings"
	"testing"
)

// CIBA §7.3, the three separate requirements on `auth_req_id`, asserted rather
// than described.
//
// `NewAuthReqID` carries a careful comment about all three — including a
// correction to an earlier version of that comment which had softened the
// entropy MUST into "It is RECOMMENDED". The code was right both times. Nothing
// tested it either time.
//
// That is the pattern this sweep keeps finding: a deliberate decision recorded
// in prose and defended by nothing. Changing `RawURLEncoding` to `StdEncoding`
// is a one-character edit that produces `+`, `/` and `=` — every one of them
// outside the permitted set — and until now no test would have noticed.

// §7.3: "The OpenID Provider MUST restrict the characters used to 'A'-'Z',
// 'a'-'z', '0'-'9', '.', '-' and '_', to reduce the chance of the client
// incorrectly decoding or re-encoding the auth_req_id".
func permitted(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '.', r == '-', r == '_':
		return true
	}
	return false
}

func TestAuthReqIDMeetsSection73(t *testing.T) {
	const runs = 2000
	seen := make(map[string]bool, runs)

	for i := 0; i < runs; i++ {
		id, err := NewAuthReqID()
		if err != nil {
			t.Fatalf("generating an auth_req_id: %v", err)
		}

		// 1. The character set. A client that has to decode or re-encode the
		//    value is where the restriction comes from, so a stray `+` or `=` is
		//    an interop failure at somebody else's URL parser.
		for _, r := range id {
			if !permitted(r) {
				t.Fatalf("auth_req_id %q contains %q, outside the set §7.3 permits "+
					"('A'-'Z', 'a'-'z', '0'-'9', '.', '-', '_')", id, r)
			}
		}
		if strings.Contains(id, "=") {
			t.Fatalf("auth_req_id %q is padded; padding is not in the permitted set", id)
		}

		// 2. The entropy floor is a MUST of "a minimum of 128 bits while 160 bits
		//    is recommended". 128 bits is 22 base64url characters; 160 is 27.
		if len(id) < 27 {
			t.Fatalf("auth_req_id %q is %d characters, which is under the 160 bits "+
				"§7.3 recommends (%d would be the 128-bit floor)", id, len(id), 22)
		}

		// 3. Uniqueness. "Brute force guessing or forgery of a valid auth_req_id"
		//    is what the entropy is for, and a generator that repeats has none of
		//    it however long its output is.
		if seen[id] {
			t.Fatalf("auth_req_id %q was generated twice in %d attempts", id, runs)
		}
		seen[id] = true
	}
}

// The interval this server advertises must be the one it enforces. A client
// told to wait five seconds and throttled at ten is a client that looks
// misbehaved in somebody's logs for obeying us.
func TestTheAdvertisedPollIntervalIsPositive(t *testing.T) {
	if CIBAMinPollInterval <= 0 {
		t.Fatalf("CIBAMinPollInterval = %d; §7.3 says a client that receives no "+
			"interval defaults to 5, so advertising zero or less is worse than "+
			"advertising nothing", CIBAMinPollInterval)
	}
}
