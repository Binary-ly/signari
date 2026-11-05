package radius

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// EAP-TTLS with PAP inside (7.08), end to end: a real crypto/tls client makes the
// tunnel through EAP-TTLS framing, RADIUS and the challenge cycle, then sends a
// name and a password as AVPs inside it, and the access point is handed the key
// the client derives from RFC 5281 §8 itself.

type ttlsAuth struct{ calls int }

func (a *ttlsAuth) Authenticate(_ context.Context, u, p string) error {
	a.calls++
	switch {
	case u == "ada" && p == "correct-horse-battery":
		return nil
	case u == "grace" && p == "a-password-and-a-code":
		return ErrSecondFactor
	}
	return errors.New("invalid credentials")
}

func ttlsTestServer(t *testing.T, pki *testPKI, withTLS bool) (*Server, *ttlsAuth) {
	t.Helper()
	_, netw, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := Config{
		Clients: []Client{{Net: netw, Secret: "a-secret-of-sufficient-length", Name: "ap"}},
		EAPTTLS: &EAPTunnelConfig{Certificate: pki.issue(t, "radius.test", false, 0)},
	}
	if withTLS {
		cfg.EAPTLS = &EAPTLSConfig{Certificate: cfg.EAPTTLS.Certificate, ClientCAs: pki.pool,
			Auth: &certAuth{}}
	}
	auth := &ttlsAuth{}
	srv, err := New(cfg, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return srv, auth
}

// avp encodes one AVP (RFC 5281 §10.1), padded to four octets (§10.2).
func avp(code uint32, flags byte, data []byte) []byte {
	length := 8 + len(data)
	b := make([]byte, 8, (length+3)&^3)
	binary.BigEndian.PutUint32(b[0:4], code)
	b[4] = flags
	b[5], b[6], b[7] = byte(length>>16), byte(length>>8), byte(length)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// papAVPs are User-Name and User-Password, the password null-padded to sixteen
// octets as §11.2.5 has a client do.
func papAVPs(user, password string) []byte {
	pw := []byte(password)
	for len(pw)%16 != 0 {
		pw = append(pw, 0)
	}
	return append(avp(avpUserName, avpFlagMust, []byte(user)), avp(avpUserPassword, avpFlagMust, pw)...)
}

type ttlsRun struct {
	code      byte
	accept    *Packet
	sentWith  []byte
	tlsConn   *tls.Conn
	resumed   bool
	startType byte
}

// ttlsConversation runs one conversation: phase2 is what goes inside the tunnel,
// version the V bits every response carries, nak whether to refuse a first offer
// of EAP-TLS by naming TTLS.
func ttlsConversation(t *testing.T, srv *Server, pki *testPKI, phase2 []byte, version byte, nak bool,
	cache tls.ClientSessionCache) ttlsRun {
	t.Helper()
	secret := []byte("a-secret-of-sufficient-length")
	conn := newFakePacketConn()
	var run ttlsRun
	exchange := func(eap, state []byte) *Packet {
		t.Helper()
		attrs := EAPAttributes(eap)
		if state != nil {
			attrs = append(attrs, Attribute{Type: AttrState, Value: state})
		}
		attrs = append(attrs, Attribute{Type: AttrUserName, Value: []byte("anonymous")})
		req, err := buildTestRequest(secret, attrs)
		if err != nil {
			t.Fatal(err)
		}
		run.sentWith = req[4:20]
		srv.handle(context.Background(), conn, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}, req)
		raw, err := conn.take(5 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	pipe := newEAPConn()
	run.tlsConn = tls.Client(pipe, &tls.Config{RootCAs: pki.pool, ServerName: "radius.test",
		MinVersion: tls.VersionTLS12, ClientSessionCache: cache})
	done := make(chan struct{})
	go func() { _ = run.tlsConn.Handshake(); close(done) }()

	reply := exchange((&EAPPacket{Code: EAPResponse, Identifier: 1, Type: EAPTypeIdentity,
		Data: []byte("anonymous")}).Encode(), nil)
	sentPhase2 := false
	for round := 0; round < 40; round++ {
		if reply.Code != CodeAccessChallenge {
			run.code, run.accept = reply.Code, reply
			// Closed first: a handshake the server refused partway is still
			// waiting to read, and holds the lock ConnectionState takes.
			pipe.closeBoth()
			<-done
			run.resumed = run.tlsConn.ConnectionState().DidResume
			return run
		}
		state, _ := reply.Attr(AttrState)
		raw, _ := reply.EAPMessage()
		eap, err := DecodeEAP(raw)
		if err != nil {
			t.Fatal(err)
		}
		if round == 0 {
			run.startType = eap.Type
		}
		if eap.Type == EAPTypeTLS && nak {
			reply = exchange((&EAPPacket{Code: EAPResponse, Identifier: eap.Identifier, Type: EAPTypeNak,
				Data: []byte{EAPTypeTTLS}}).Encode(), state)
			continue
		}
		if eap.Type != EAPTypeTTLS {
			t.Fatalf("the server offered EAP type %d", eap.Type)
		}
		frame, err := DecodeEAPTLS(eap.Data)
		if err != nil {
			t.Fatal(err)
		}
		if len(frame.Data) > 0 {
			pipe.feed(frame.Data)
		}
		var out []byte
		if !frame.More {
			// What the client's TLS makes of what arrived. When that was the
			// server's Finished, the handshake ends with nothing to send, and the
			// client goes first in phase 2 (RFC 5281 §7.6).
			out = pipe.waitOut(done, 2*time.Second)
			if len(out) == 0 && isClosed(done) && !sentPhase2 {
				if _, err := run.tlsConn.Write(phase2); err != nil {
					t.Fatal(err)
				}
				out = pipe.take()
				sentPhase2 = true
			}
		}
		resp := (&EAPTLSFrame{Data: out, Version: version}).Encode()
		reply = exchange((&EAPPacket{Code: EAPResponse, Identifier: eap.Identifier, Type: EAPTypeTTLS,
			Data: resp}).Encode(), state)
	}
	t.Fatal("the conversation did not finish in 40 round trips")
	return run
}

func TestEAPTTLSCarriesAPasswordAndHandsTheAccessPointTheTunnelsKey(t *testing.T) {
	pki := newTestPKI(t)
	srv, auth := ttlsTestServer(t, pki, false)
	run := ttlsConversation(t, srv, pki, papAVPs("ada", "correct-horse-battery"), 0, false, nil)
	if run.startType != EAPTypeTTLS || run.code != CodeAccessAccept {
		t.Fatalf("offered type %d, answered %d; want EAP-TTLS and an accept", run.startType, run.code)
	}
	if got := run.tlsConn.ConnectionState().Version; got != tls.VersionTLS12 {
		t.Errorf("the tunnel ran TLS %x; its keys are defined over TLS 1.2's PRF", got)
	}
	if name, _ := run.accept.Attr(AttrUserName); string(name) != "ada" {
		t.Errorf("the accept names %q, want the person the tunnel proved", name)
	}
	// RFC 5281 §8, from the client's own TLS: PRF-128 with "ttls keying material";
	// the MSK is the first 64 octets, MPPE-Recv-Key the first 32 of it.
	cs := run.tlsConn.ConnectionState()
	km, err := cs.ExportKeyingMaterial("ttls keying material", nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("a-secret-of-sufficient-length")
	if recv := mppeKey(t, run.accept, vendorTypeRecvKey, secret, run.sentWith); !bytes.Equal(recv, km[:32]) {
		t.Error("MPPE-Recv-Key is not the first 32 octets of the client's TTLS keying material")
	}
	if send := mppeKey(t, run.accept, vendorTypeSendKey, secret, run.sentWith); !bytes.Equal(send, km[32:64]) {
		t.Error("MPPE-Send-Key is not the second 32 octets of the client's TTLS keying material")
	}

	// Again, with a client keeping sessions: nothing is resumed, so the password is
	// asked again (RFC 5281 §7.5).
	cache := tls.NewLRUClientSessionCache(4)
	for i := range 2 {
		run := ttlsConversation(t, srv, pki, papAVPs("ada", "correct-horse-battery"), 0, false, cache)
		if run.code != CodeAccessAccept || run.resumed {
			t.Errorf("conversation %d: %d, resumed %v", i+1, run.code, run.resumed)
		}
	}
	if auth.calls != 3 {
		t.Errorf("the password was checked %d times in three conversations", auth.calls)
	}
}

func TestEAPTTLSRefusesWhatItCannotAccept(t *testing.T) {
	pki := newTestPKI(t)
	srv, _ := ttlsTestServer(t, pki, false)
	unknown := append(papAVPs("ada", "correct-horse-battery"), avp(9999, avpFlagMust, []byte("x"))...)
	ignorable := append(papAVPs("ada", "correct-horse-battery"), avp(9999, 0, []byte("x"))...)
	for name, c := range map[string]struct {
		phase2  []byte
		version byte
		want    byte
	}{
		"a wrong password":                   {papAVPs("ada", "wrong"), 0, CodeAccessReject},
		"a right password that needs a code": {papAVPs("grace", "a-password-and-a-code"), 0, CodeAccessReject},
		"no password":                        {avp(avpUserName, avpFlagMust, []byte("ada")), 0, CodeAccessReject},
		"an AVP that must be understood":     {unknown, 0, CodeAccessReject},
		"an AVP that may be ignored":         {ignorable, 0, CodeAccessAccept},
		"a version the server did not offer": {papAVPs("ada", "correct-horse-battery"), 1, CodeAccessReject},
		"an AVP sequence cut short":          {papAVPs("ada", "correct-horse-battery")[:10], 0, CodeAccessReject},
	} {
		if run := ttlsConversation(t, srv, pki, c.phase2, c.version, false, nil); run.code != c.want {
			t.Errorf("%s: answered %d, want %d", name, run.code, c.want)
		}
	}
}

// With EAP-TLS on as well, the certificate method is offered first, and a
// supplicant without a certificate names EAP-TTLS in its Nak.
func TestASupplicantThatNaksEAPTLSIsOfferedEAPTTLS(t *testing.T) {
	pki := newTestPKI(t)
	srv, _ := ttlsTestServer(t, pki, true)
	run := ttlsConversation(t, srv, pki, papAVPs("ada", "correct-horse-battery"), 0, true, nil)
	if run.startType != EAPTypeTLS || run.code != CodeAccessAccept {
		t.Errorf("first offered %d, answered %d; want EAP-TLS offered, then EAP-TTLS accepted", run.startType,
			run.code)
	}
	if name, _ := run.accept.Attr(AttrUserName); string(name) != "ada" {
		t.Errorf("the accept names %q", name)
	}
}

func TestParseAVPs(t *testing.T) {
	seq := append(avp(1, avpFlagMust, []byte("ada")), avp(2, 0, []byte("12345"))...)
	got, err := parseAVPs(seq)
	if err != nil || len(got) != 2 || string(got[0].data) != "ada" || string(got[1].data) != "12345" {
		t.Fatalf("%+v, %v", got, err)
	}
	vendor := []byte{0, 0, 0, 7, avpFlagVendor, 0, 0, 13, 0, 0, 0x01, 0x37, 'x', 0, 0, 0}
	if got, err := parseAVPs(vendor); err != nil || got[0].vendor != 311 || string(got[0].data) != "x" {
		t.Errorf("a vendor AVP: %+v, %v", got, err)
	}
	for name, b := range map[string][]byte{
		"shorter than its header": {0, 0, 0, 1, 0, 0, 0, 4},
		"a vendor AVP of 8":       {0, 0, 0, 1, avpFlagVendor, 0, 0, 8},
	} {
		if _, err := parseAVPs(b); err == nil || errors.Is(err, errAVPShort) {
			t.Errorf("%s: %v, want it refused", name, err)
		}
	}
	if _, err := parseAVPs(seq[:9]); !errors.Is(err, errAVPShort) {
		t.Errorf("a sequence cut short: %v", err)
	}
}
