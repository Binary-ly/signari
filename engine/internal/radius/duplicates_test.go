package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// A request means one thing (7.17). A second User-Name was refused while a
// second User-Password, or a second State, was ignored, the first one read;
// so what a request asserted depended on which a reader took, and a proxy
// reading the other would have checked something else.

// withSecondAttribute appends an attribute to a signed request and signs it
// again, so its Message-Authenticator still verifies.
func withSecondAttribute(t *testing.T, pkt []byte, typ byte, value []byte) []byte {
	t.Helper()
	out := append(append([]byte(nil), pkt...), typ, byte(len(value)+2))
	out = append(out, value...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	ma := -1
	for i := headerLen; i+2 <= len(out); {
		l := int(out[i+1])
		if l < 2 {
			t.Fatal("malformed fixture")
		}
		if out[i] == AttrMessageAuthenticator {
			ma = i
			for j := i + 2; j < i+l; j++ {
				out[j] = 0
			}
		}
		i += l
	}
	mac := hmac.New(md5.New, []byte(testSecret))
	mac.Write(out)
	copy(out[ma+2:ma+18], mac.Sum(nil))
	return out
}

func TestTwoUserPasswordsAreRefused(t *testing.T) {
	s, a := newServer(t)
	// The right password first, so a server reading the first would accept.
	pkt := buildRequest(t, testSecret, "alice", "correct-horse-battery", true)
	if reply := exchange(t, s, pkt); reply == nil || reply.Code != CodeAccessAccept {
		t.Fatalf("the fixture is not accepted alone: %+v", reply)
	}
	second := make([]byte, 16)
	if _, err := rand.Read(second); err != nil {
		t.Fatal(err)
	}
	calls := a.calls
	reply := exchange(t, s, withSecondAttribute(t, pkt, AttrUserPassword, second))
	if reply == nil || reply.Code != CodeAccessReject {
		t.Fatalf("a request with two User-Passwords answered %+v, want Access-Reject", reply)
	}
	if a.calls != calls {
		t.Error("a password was checked for a request carrying two")
	}
}

func TestTwoStatesEndTheConversation(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})
	sup := &supplicant{t: t, server: srv, conn: newFakePacketConn(),
		secret: []byte("a-secret-of-sufficient-length"), cert: pki.issue(t, "bob@corp.test", true, 0),
		pool: pki.pool, identity: "anonymous", secondState: []byte("another-conversation")}
	code, _, err := sup.run()
	if err != nil {
		t.Fatal(err)
	}
	if code != CodeAccessReject {
		t.Fatalf("a conversation whose requests carried two States ended %d, want Access-Reject", code)
	}
}

// A supplicant that declares no length cannot grow the reassembly past the
// cap: it held only for a declared one.
func TestALengthlessFragmentStreamStopsAtTheCap(t *testing.T) {
	s := &Server{}
	sess := &eapSession{}
	chunk := make([]byte, eapTLSMaxFragment)
	sent := 0
	for sent <= maxReassembly+len(chunk) {
		resp := &EAPPacket{Code: EAPResponse, Identifier: 1, Type: EAPTypeTLS,
			Data: (&EAPTLSFrame{More: true, Data: chunk}).Encode()}
		_, done, ok := s.continueEAPTLS(sess, resp)
		sent += len(chunk)
		if done {
			if ok || sent <= maxReassembly {
				t.Fatalf("ended at %d bytes, ok=%v; want refused just past %d", sent, ok, maxReassembly)
			}
			return
		}
	}
	t.Fatalf("%d bytes with no length declared were taken, past the %d cap", sent, maxReassembly)
}
