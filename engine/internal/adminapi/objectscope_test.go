package adminapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every handler that addresses a client or a group by id must check whether
// this token may act on it.
//
// # Why a guard and not a convention
//
// The per-object restriction is nine call sites today. A tenth handler added
// next month inherits the organisation check for free — `requireOrg` is
// unavoidable because the handler needs the org id anyway — and inherits this
// one not at all. The failure is silent and in the permissive direction: a
// token restricted to one application quietly regains the ability to act on
// every other one through whichever endpoint was added last.
//
// That is the same shape as `TestTheMutatingRouteListCoversEveryRegisteredRoute`
// and it is caught the same way: derive the list of handlers from the source
// rather than trusting that everyone remembered.
//
// # An empty allow-list means NOTHING, not everything
//
// `nil` is unrestricted; `[]` is no objects at all. Getting that backwards would
// turn the whole feature into a widening one the first time somebody cleared a
// list intending to revoke access — see Principal.mayActOnObject.

var (
	readsClientID = regexp.MustCompile(`r\.PathValue\("clientID"\)`)
	readsGroupID  = regexp.MustCompile(`r\.PathValue\("groupID"\)`)
	callsClient   = regexp.MustCompile(`requireClient\(ctx,`)
	callsGroup    = regexp.MustCompile(`requireGroup\(ctx,`)
	// A handler starts at a func on *Server taking an http.ResponseWriter.
	handlerStart = regexp.MustCompile(`(?m)^func \(s \*Server\) (\w+)\(w http\.ResponseWriter`)
)

func TestEveryHandlerAddressingAnObjectChecksTheToken(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(e.Name())
		if rerr != nil {
			t.Fatal(rerr)
		}
		body := string(src)

		// Split the file into handler bodies, so a check in one handler cannot
		// satisfy the requirement for another in the same file. That was the
		// first version's flaw: it matched per FILE, and clients.go already
		// called requireClient once, which made every other handler in it pass.
		locs := handlerStart.FindAllStringSubmatchIndex(body, -1)
		for i, loc := range locs {
			name := body[loc[2]:loc[3]]
			end := len(body)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			fn := body[loc[0]:end]

			if readsClientID.MatchString(fn) {
				checked++
				if !callsClient.MatchString(fn) {
					t.Errorf("%s.%s addresses a client by id and never calls "+
						"requireClient.\n\nA token restricted to named clients "+
						"would be able to act on any of them through this "+
						"handler. requireOrg is not enough: it decides the "+
						"tenant, not the object.", e.Name(), name)
				}
			}
			if readsGroupID.MatchString(fn) {
				checked++
				if !callsGroup.MatchString(fn) {
					t.Errorf("%s.%s addresses a group by id and never calls "+
						"requireGroup.\n\nGroup membership decides which "+
						"applications people reach, so a token restricted to "+
						"named groups must not act on others here.",
						e.Name(), name)
				}
			}
		}
	}

	// Vacuity guard. If the shape of a handler changes and this stops matching
	// anything, it must say so rather than pass.
	if checked < 8 {
		t.Fatalf("only %d object-addressing handlers were found; there were 9 "+
			"when this was written, so the pattern has stopped matching and "+
			"this guard is checking almost nothing", checked)
	}
}
