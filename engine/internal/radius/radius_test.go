package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

const testSecret = "a-sufficiently-long-shared-secret"

// buildRequest assembles an Access-Request the way a network device does.
func buildRequest(t *testing.T, secret, username, password string, withMAC bool) []byte {
	t.Helper()

	var auth [16]byte
	if _, err := io.ReadFull(rand.Reader, auth[:]); err != nil {
		t.Fatal(err)
	}

	// User-Password, obfuscated per RFC 2865 §5.2.
	pw := []byte(password)
	for len(pw)%16 != 0 {
		pw = append(pw, 0)
	}
	ct := make([]byte, 0, len(pw))
	prev := auth[:]
	for i := 0; i < len(pw); i += 16 {
		h := md5.New()
		h.Write([]byte(secret))
		h.Write(prev)
		key := h.Sum(nil)
		block := make([]byte, 16)
		for j := 0; j < 16; j++ {
			block[j] = pw[i+j] ^ key[j]
		}
		ct = append(ct, block...)
		prev = block
	}

	body := []byte{}
	add := func(typ byte, v []byte) {
		body = append(body, typ, byte(len(v)+2))
		body = append(body, v...)
	}
	add(AttrUserName, []byte(username))
	add(AttrUserPassword, ct)
	if withMAC {
		add(AttrMessageAuthenticator, make([]byte, 16))
	}

	length := headerLen + len(body)
	pkt := make([]byte, headerLen)
	pkt[0], pkt[1] = CodeAccessRequest, 42
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	copy(pkt[4:20], auth[:])
	pkt = append(pkt, body...)

	if withMAC {
		mac := hmac.New(md5.New, []byte(secret))
		mac.Write(pkt)
		sum := mac.Sum(nil)
		// Find the attribute and write the HMAC into it.
		for i := headerLen; i+2 <= len(pkt); {
			l := int(pkt[i+1])
			if pkt[i] == AttrMessageAuthenticator {
				copy(pkt[i+2:i+2+16], sum)
				break
			}
			i += l
		}
	}
	return pkt
}

type fakeAuth struct{ calls int }

func (f *fakeAuth) Authenticate(_ context.Context, u, p string) error {
	f.calls++
	if u == "alice" && p == "correct-horse-battery" {
		return nil
	}
	return errors.New("invalid credentials")
}

func newServer(t *testing.T) (*Server, *fakeAuth) {
	t.Helper()
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	a := &fakeAuth{}
	s, err := New(Config{Clients: []Client{{Net: n, Secret: testSecret, Name: "test"}}}, a,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, a
}

// exchange sends a packet and returns the reply, or nil on silence.
func exchange(t *testing.T, s *Server, packet []byte) *Packet {
	t.Helper()
	srvConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvConn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx, srvConn) }()

	cli, err := net.Dial("udp", srvConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()

	if _, err := cli.Write(packet); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, maxPacket)
	n, err := cli.Read(buf)
	if err != nil {
		return nil // silence
	}
	p, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("the reply did not decode: %v", err)
	}
	return p
}

func TestValidRequestIsAccepted(t *testing.T) {
	s, _ := newServer(t)
	reply := exchange(t, s, buildRequest(t, testSecret, "alice", "correct-horse-battery", true))
	if reply == nil {
		t.Fatal("no reply")
	}
	if reply.Code != CodeAccessAccept {
		t.Fatalf("code = %d, want Access-Accept", reply.Code)
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	s, _ := newServer(t)
	reply := exchange(t, s, buildRequest(t, testSecret, "alice", "wrong", true))
	if reply == nil || reply.Code != CodeAccessReject {
		t.Fatalf("reply = %+v, want Access-Reject", reply)
	}
}

// TestRequestWithoutMessageAuthenticatorIsRefused is CVE-2024-3596.
//
// Without this attribute the response is protected only by an MD5 Response
// Authenticator, which is forgeable by chosen-prefix collision -- an attacker on
// the path turns an Access-Reject into an Access-Accept. Accepting such a
// request IS the vulnerability.
func TestRequestWithoutMessageAuthenticatorIsRefused(t *testing.T) {
	s, a := newServer(t)
	reply := exchange(t, s, buildRequest(t, testSecret, "alice", "correct-horse-battery", false))
	if reply != nil {
		t.Fatalf("a request with no Message-Authenticator got a reply (code %d); "+
			"the response would be forgeable by MD5 collision", reply.Code)
	}
	// And the credential was never checked: the refusal is structural.
	if a.calls != 0 {
		t.Errorf("the authenticator ran %d time(s) for an unauthenticated request", a.calls)
	}
}

// TestTamperedMessageAuthenticatorIsRefused.
func TestTamperedMessageAuthenticatorIsRefused(t *testing.T) {
	s, _ := newServer(t)
	pkt := buildRequest(t, testSecret, "alice", "correct-horse-battery", true)
	// Flip a bit inside the HMAC.
	for i := headerLen; i+2 <= len(pkt); {
		l := int(pkt[i+1])
		if pkt[i] == AttrMessageAuthenticator {
			pkt[i+2] ^= 0x01
			break
		}
		i += l
	}
	if reply := exchange(t, s, pkt); reply != nil {
		t.Fatal("a request with a tampered Message-Authenticator got a reply")
	}
}

// TestWrongSharedSecretIsRefused. The secret is what makes the HMAC mean
// anything.
func TestWrongSharedSecretIsRefused(t *testing.T) {
	s, _ := newServer(t)
	pkt := buildRequest(t, "a-different-but-long-enough-secret", "alice",
		"correct-horse-battery", true)
	if reply := exchange(t, s, pkt); reply != nil {
		t.Fatal("a request signed with the wrong shared secret got a reply")
	}
}

// TestResponseCarriesMessageAuthenticatorFirst.
//
// The published mitigation specifies it as the FIRST attribute in accept and
// reject responses.
func TestResponseCarriesMessageAuthenticatorFirst(t *testing.T) {
	s, _ := newServer(t)
	req := buildRequest(t, testSecret, "alice", "correct-horse-battery", true)
	sentRequestAuthenticator := append([]byte(nil), req[4:20]...)
	reply := exchange(t, s, req)
	if reply == nil {
		t.Fatal("no reply")
	}
	if len(reply.Attributes) == 0 {
		t.Fatal("the reply has no attributes")
	}
	if reply.Attributes[0].Type != AttrMessageAuthenticator {
		t.Errorf("the first attribute is %d, want Message-Authenticator (%d)",
			reply.Attributes[0].Type, AttrMessageAuthenticator)
	}
	// A response is verified against the REQUEST authenticator, not its own --
	// see VerifyMessageAuthenticatorWith. Verifying it against its own bytes
	// fails every time, which is what real network equipment would do to our
	// Access-Accept if we had this wrong.
	var reqAuth [16]byte
	copy(reqAuth[:], sentRequestAuthenticator)
	if err := reply.VerifyMessageAuthenticatorWith([]byte(testSecret), reqAuth[:]); err != nil {
		t.Errorf("our own response failed our own verification: %v", err)
	}
}

// TestRejectMessageIsAlwaysTheSame. A device shows this to whoever is typing;
// distinguishing "no such user" from "wrong password" makes the network login
// screen a user-enumeration oracle.
func TestRejectMessageIsAlwaysTheSame(t *testing.T) {
	s, _ := newServer(t)
	var messages []string
	for _, u := range []string{"alice", "nobody-at-all"} {
		reply := exchange(t, s, buildRequest(t, testSecret, u, "wrong-password", true))
		if reply == nil || reply.Code != CodeAccessReject {
			t.Fatalf("%s: reply = %+v", u, reply)
		}
		v, _ := reply.Attr(AttrReplyMessage)
		messages = append(messages, string(v))
	}
	if messages[0] != messages[1] {
		t.Errorf("the reply messages differ, so users can be enumerated: %q vs %q",
			messages[0], messages[1])
	}
}

// TestEmptyPasswordIsRejected, matching the LDAP shim's rule.
func TestEmptyPasswordIsRejected(t *testing.T) {
	s, a := newServer(t)
	reply := exchange(t, s, buildRequest(t, testSecret, "alice", "", true))
	if reply == nil || reply.Code != CodeAccessReject {
		t.Fatalf("reply = %+v, want Access-Reject", reply)
	}
	if a.calls != 0 {
		t.Error("an empty password reached the credential checker")
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	for _, pw := range []string{
		"short", "correct-horse-battery",
		"exactly-16-chars",
		"a much longer password that spans several sixteen byte blocks!!",
		"pass\x00with-embedded-nul",
		"ünïcödé-påsswörd",
	} {
		pkt := buildRequest(t, testSecret, "alice", pw, true)
		p, err := Decode(pkt)
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		got, err := p.DecodePassword([]byte(testSecret))
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		// Trailing NULs are padding and are trimmed; an embedded one is the
		// user's byte and must survive.
		want := strings.TrimRight(pw, "\x00")
		if got != want {
			t.Errorf("round trip of %q gave %q", pw, got)
		}
	}
}

// TestMalformedPacketsDoNotHang. A zero-length attribute would not advance the
// parse cursor: the loop would spin forever on a packet an attacker sends once.
func TestMalformedPacketsDoNotHang(t *testing.T) {
	cases := [][]byte{
		{},
		{1, 2, 3},
		append([]byte{1, 1, 0, 22}, make([]byte, 18)...),      // attribute length 0
		append([]byte{1, 1, 0, 21}, make([]byte, 17)...),      // attribute length 1
		append([]byte{1, 1, 0xFF, 0xFF}, make([]byte, 16)...), // declared far beyond arrival
	}
	for i, c := range cases {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = Decode(c)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("case %d did not terminate", i)
		}
	}
}

// TestShortSecretIsRefusedAtConfiguration.
func TestShortSecretIsRefusedAtConfiguration(t *testing.T) {
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	_, err := New(Config{Clients: []Client{{Net: n, Secret: "short"}}}, &fakeAuth{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("a five-character shared secret was accepted")
	}
}

// TestNoClientsIsRefused. A server that trusts everybody is an authentication
// oracle for the whole network.
func TestNoClientsIsRefused(t *testing.T) {
	if _, err := New(Config{}, &fakeAuth{},
		slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("a server with no configured clients was accepted")
	}
}

// TestReplaceClientsRevokesADevice covers the reload that makes revocation mean
// something.
//
// The client list was read once at startup, so disabling a device did nothing
// until a restart: the listener carried on answering an access point whose
// access had been revoked.
func TestReplaceClientsRevokesADevice(t *testing.T) {
	_, netA, _ := net.ParseCIDR("10.0.0.0/8")
	_, netB, _ := net.ParseCIDR("192.168.0.0/16")
	srv, err := New(Config{Clients: []Client{
		{Net: netA, Secret: "a-secret-of-sufficient-length", Name: "ap-a"},
		{Net: netB, Secret: "another-secret-long-enough", Name: "ap-b"},
	}}, &fakeAuth{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	from := func(ip string) (Client, bool) {
		return srv.clientFor(&net.UDPAddr{IP: net.ParseIP(ip), Port: 5000})
	}

	if _, ok := from("10.1.2.3"); !ok {
		t.Fatal("ap-a should be recognised to begin with")
	}

	// ap-a is revoked; ap-b stays.
	if err := srv.ReplaceClients([]Client{
		{Net: netB, Secret: "another-secret-long-enough", Name: "ap-b"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := from("10.1.2.3"); ok {
		t.Fatal("a revoked device is still recognised; disabling it did nothing")
	}
	if _, ok := from("192.168.1.5"); !ok {
		t.Fatal("revoking one device removed another")
	}
}

// TestReplaceClientsAcceptsEmpty is a correction to a guard that blocked the
// feature it shipped with.
//
// The first version refused an empty list, reasoning that an empty result was
// more likely a failed read than a deliberate removal. That is true of a
// PAGINATED fetch and untrue of a single SQL query, which either succeeds or
// errors -- so the guard rejected the reload that would have applied the
// revocation of the last device, and revoking it did nothing.
func TestReplaceClientsAcceptsEmpty(t *testing.T) {
	_, netA, _ := net.ParseCIDR("10.0.0.0/8")
	srv, err := New(Config{Clients: []Client{
		{Net: netA, Secret: "a-secret-of-sufficient-length", Name: "ap-a"},
	}}, &fakeAuth{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ReplaceClients(nil); err != nil {
		t.Fatalf("disabling every device was refused: %v\n"+
			"An operator who revokes the last access point means it.", err)
	}
	if _, ok := srv.clientFor(&net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5000}); ok {
		t.Fatal("a device is still recognised after every one was disabled")
	}
}

// TestReplaceClientsRefusesAnUnusableSecret keeps the startup rule at runtime.
func TestReplaceClientsRefusesAnUnusableSecret(t *testing.T) {
	_, netA, _ := net.ParseCIDR("10.0.0.0/8")
	srv, err := New(Config{Clients: []Client{
		{Net: netA, Secret: "a-secret-of-sufficient-length", Name: "ap-a"},
	}}, &fakeAuth{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ReplaceClients([]Client{
		{Net: netA, Secret: "short", Name: "ap-a"},
	}); err == nil {
		t.Fatal("a secret too short to resist an offline grind was accepted at " +
			"reload, though it is refused at startup")
	}
	// And the working list is still in force.
	if _, ok := srv.clientFor(&net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5000}); !ok {
		t.Fatal("a refused reload lost the working configuration")
	}
}

func TestTwoMessageAuthenticatorsAreRefusedEvenWhenBothVerify(t *testing.T) {
	s, a := newServer(t)
	pkt := buildRequest(t, testSecret, "alice", "correct-horse-battery", true)

	// Append a second, zero-valued Message-Authenticator and fix the length.
	dup := append(append([]byte(nil), pkt...), AttrMessageAuthenticator, 18)
	dup = append(dup, make([]byte, 16)...)
	binary.BigEndian.PutUint16(dup[2:4], uint16(len(dup)))

	// Zero the first one too, then compute the HMAC over the whole packet — the
	// same bytes the verifier will construct.
	zeroed := append([]byte(nil), dup...)
	for i := headerLen; i+2 <= len(zeroed); {
		l := int(zeroed[i+1])
		if l < 2 || i+l > len(zeroed) {
			break
		}
		if zeroed[i] == AttrMessageAuthenticator {
			for j := i + 2; j < i+l; j++ {
				zeroed[j] = 0
			}
		}
		i += l
	}
	mac := hmac.New(md5.New, []byte(testSecret))
	mac.Write(zeroed)
	sum := mac.Sum(nil)

	// Write that HMAC into BOTH attributes, so each is individually correct.
	for i := headerLen; i+2 <= len(dup); {
		l := int(dup[i+1])
		if l < 2 || i+l > len(dup) {
			break
		}
		if dup[i] == AttrMessageAuthenticator && l == 18 {
			copy(dup[i+2:i+18], sum)
		}
		i += l
	}

	if reply := exchange(t, s, dup); reply != nil {
		t.Fatalf("a request carrying two individually-valid Message-Authenticators "+
			"got a reply (code %d); which one was verified is then up to the parser",
			reply.Code)
	}
	if a.calls != 0 {
		t.Errorf("the authenticator ran %d time(s) for a packet that could not be "+
			"unambiguously authenticated", a.calls)
	}
}

// A truncated Message-Authenticator must be refused rather than compared.
//
// RFC 2869 §5.14 fixes the value at 16 bytes. A shorter one cannot be a valid
// HMAC-MD5, and comparing it is how an implementation ends up doing a
// prefix-length comparison instead of a full one.
func TestShortMessageAuthenticatorIsRefused(t *testing.T) {
	s, _ := newServer(t)
	pkt := buildRequest(t, testSecret, "alice", "correct-horse-battery", true)

	out := append([]byte(nil), pkt[:headerLen]...)
	for i := headerLen; i+2 <= len(pkt); {
		l := int(pkt[i+1])
		if l < 2 || i+l > len(pkt) {
			break
		}
		if pkt[i] == AttrMessageAuthenticator {
			// 8 bytes of value instead of 16.
			out = append(out, AttrMessageAuthenticator, 10)
			out = append(out, pkt[i+2:i+10]...)
		} else {
			out = append(out, pkt[i:i+l]...)
		}
		i += l
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))

	if reply := exchange(t, s, out); reply != nil {
		t.Fatalf("a request with an 8-byte Message-Authenticator got a reply (code %d)",
			reply.Code)
	}
}
