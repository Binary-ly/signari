package radius

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// codeAuth needs a code of everybody, as an organisation refusing a password
// alone does.
type codeAuth struct {
	fakeAuth
	asked []string
}

func (a *codeAuth) Authenticate(_ context.Context, u, p string) error {
	if u == "alice" && p == "correct-horse-battery" {
		return ErrSecondFactor
	}
	return errors.New("invalid credentials")
}

func (a *codeAuth) VerifyCode(_ context.Context, u, code string) error {
	a.asked = append(a.asked, u+":"+code)
	if u == "alice" && code == "123456" {
		return nil
	}
	return errors.New("wrong code")
}

func newCodeServer(t *testing.T, a Authenticator) *Server {
	t.Helper()
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	s, err := New(Config{Clients: []Client{{Net: n, Secret: testSecret, Name: "test"}}}, a,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A challenge for alice, and the State it carried.
func challengeFor(t *testing.T, s *Server) []byte {
	t.Helper()
	reply := exchange(t, s, buildRequest(t, testSecret, "alice", "correct-horse-battery", true))
	if reply == nil || reply.Code != CodeAccessChallenge {
		t.Fatalf("a right password with no code answered %+v, want Access-Challenge", reply)
	}
	state, ok := reply.Attr(AttrState)
	if !ok || len(state) != 16 {
		t.Fatalf("the challenge carried state %x", state)
	}
	if prompt, _ := reply.Attr(AttrReplyMessage); string(prompt) == "" {
		t.Error("the challenge asks for nothing a device can show")
	}
	return state
}

func answer(t *testing.T, s *Server, username, code string, state []byte) *Packet {
	t.Helper()
	return exchange(t, s, withSecondAttribute(t, buildRequest(t, testSecret, username, code, true), AttrState, state))
}

// A right password is not an Accept for somebody who owes a code: it is a
// challenge, and only the code, once, with the state it issued, finishes it
// (7.05). A state is what stands between a device and skipping the password.
func TestAPasswordIsChallengedAndTheCodeFinishesIt(t *testing.T) {
	a := &codeAuth{}
	s := newCodeServer(t, a)

	state := challengeFor(t, s)
	if reply := answer(t, s, "alice", "123456", state); reply == nil || reply.Code != CodeAccessAccept {
		t.Fatalf("the right code answered %+v, want Access-Accept", reply)
	}
	if reply := answer(t, s, "alice", "123456", state); reply == nil || reply.Code != CodeAccessReject {
		t.Errorf("a spent state answered %+v, want Access-Reject", reply)
	}

	state = challengeFor(t, s)
	if reply := answer(t, s, "alice", "000000", state); reply == nil || reply.Code != CodeAccessReject {
		t.Errorf("a wrong code answered %+v, want Access-Reject", reply)
	}
	if reply := answer(t, s, "alice", "123456", state); reply == nil || reply.Code != CodeAccessReject {
		t.Errorf("a second guess on one state answered %+v, want Access-Reject", reply)
	}

	state = challengeFor(t, s)
	before := len(a.asked)
	if reply := answer(t, s, "bob", "123456", state); reply == nil || reply.Code != CodeAccessReject {
		t.Errorf("alice's state with bob's name answered %+v", reply)
	}
	if reply := answer(t, s, "alice", "123456", []byte("made-up-state-16")); reply == nil || reply.Code != CodeAccessReject {
		t.Errorf("a state never issued answered %+v", reply)
	}
	if len(a.asked) != before {
		t.Errorf("a code was tried for a state that was not good: %v", a.asked[before:])
	}
}

func TestAStateIsGoodForOneDeviceAndNotForLong(t *testing.T) {
	s := newCodeServer(t, &codeAuth{})
	now := time.Now()
	state := "0123456789abcdef"
	for name, p := range map[string]pendingCode{
		"another device's": {username: "alice", client: "other", expires: now.Add(time.Minute)},
		"an expired":       {username: "alice", client: "test", expires: now.Add(-time.Second)},
	} {
		s.codes.add(state, p, now.Add(-time.Hour))
		if reply := answer(t, s, "alice", "123456", []byte(state)); reply == nil || reply.Code != CodeAccessReject {
			t.Errorf("%s state answered %+v", name, reply)
		}
	}
}

// With nothing to check a code, a password that needs one is refused rather
// than challenged into a conversation nothing can finish, and never accepted.
func TestAPasswordThatNeedsACodeIsNotAcceptedWithoutAWayToCheckIt(t *testing.T) {
	s := newCodeServer(t, needsCodeOnly{})
	reply := exchange(t, s, buildRequest(t, testSecret, "alice", "correct-horse-battery", true))
	if reply == nil || reply.Code != CodeAccessReject {
		t.Errorf("answered %+v, want Access-Reject", reply)
	}
}

type needsCodeOnly struct{}

func (needsCodeOnly) Authenticate(context.Context, string, string) error { return ErrSecondFactor }

func TestWaitingForCodesIsBounded(t *testing.T) {
	var c pendingCodes
	now := time.Now()
	for i := 0; i < maxPendingCodes; i++ {
		if !c.add(string(rune(i+1)), pendingCode{expires: now.Add(time.Minute)}, now) {
			t.Fatalf("refused at %d", i)
		}
	}
	if c.add("one more", pendingCode{expires: now.Add(time.Minute)}, now) {
		t.Error("the bound was passed")
	}
	if !c.add("after they lapsed", pendingCode{expires: now.Add(3 * time.Minute)}, now.Add(2*time.Minute)) {
		t.Error("lapsed ones still held a place")
	}
}
