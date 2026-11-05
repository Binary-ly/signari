package radius

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// PEAPv0 with EAP-GTC inside (7.08), end to end against a real crypto/tls client:
// the server asks for an identity and a password inside the tunnel, says the result
// in a Result TLV, and on the peer's own Result answers EAP-Success with the keys of
// MS-PEAP §3.1.5.7 for a conversation without cryptobinding.

type peapRun struct {
	code      byte
	accept    *Packet
	sentWith  []byte
	tlsConn   *tls.Conn
	startType byte
	prompts   []string // the GTC prompts the server sent
	result    uint16   // the Result TLV the server sent
}

// peapConversation answers the server as a PEAP peer does: identity inside the
// tunnel, then each GTC prompt with the next of answers, then the Result TLV with
// echo, or with its own result when echo is 0.
func peapConversation(t *testing.T, srv *Server, pki *testPKI, identity string, answers []string, echo uint16,
	nak bool) peapRun {
	t.Helper()
	secret := []byte("a-secret-of-sufficient-length")
	conn := newFakePacketConn()
	var run peapRun
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
	run.tlsConn = tls.Client(pipe, &tls.Config{RootCAs: pki.pool, ServerName: "radius.test", MinVersion: tls.VersionTLS12})
	done := make(chan struct{})
	go func() { _ = run.tlsConn.Handshake(); close(done) }()
	inner := make(chan []byte, 8)
	go func() {
		<-done
		buf := make([]byte, 4096)
		for {
			n, err := run.tlsConn.Read(buf)
			if n > 0 {
				inner <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				close(inner)
				return
			}
		}
	}()

	reply := exchange((&EAPPacket{Code: EAPResponse, Identifier: 1, Type: EAPTypeIdentity,
		Data: []byte("anonymous")}).Encode(), nil)
	for round := 0; round < 40; round++ {
		if reply.Code != CodeAccessChallenge {
			run.code, run.accept = reply.Code, reply
			pipe.closeBoth()
			<-done
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
				Data: []byte{EAPTypeTTLS, EAPTypePEAP}}).Encode(), state)
			continue
		}
		if eap.Type != EAPTypePEAP {
			t.Fatalf("the server offered EAP type %d", eap.Type)
		}
		frame, err := DecodeEAPTLS(eap.Data)
		if err != nil {
			t.Fatal(err)
		}
		handshakeOver := isClosed(done)
		if len(frame.Data) > 0 {
			pipe.feed(frame.Data)
		}
		var out []byte
		switch {
		case frame.More:
		case !handshakeOver:
			// Still the handshake, or its last flight, which the peer acknowledges.
			out = pipe.waitOut(done, 2*time.Second)
		default:
			// Inside the tunnel: what the server asked.
			var asked []byte
			select {
			case asked = <-inner:
			case <-time.After(2 * time.Second):
				t.Fatal("the server sent nothing inside the tunnel")
			}
			var answer []byte
			switch {
			case len(asked) == 1 && asked[0] == EAPTypeIdentity:
				answer = append([]byte{EAPTypeIdentity}, identity...)
			case len(asked) > 0 && asked[0] == EAPTypeGTC:
				run.prompts = append(run.prompts, string(asked[1:]))
				next := ""
				if len(answers) > 0 {
					next, answers = answers[0], answers[1:]
				}
				answer = append([]byte{EAPTypeGTC}, next...)
			default:
				p, err := DecodeEAP(asked)
				if err != nil || p.Type != EAPTypeTLVExtensions || len(p.Data) != 6 {
					t.Fatalf("inside the tunnel the server sent %x", asked)
				}
				run.result = binary.BigEndian.Uint16(p.Data[4:6])
				value := echo
				if value == 0 {
					value = run.result
				}
				tlv := make([]byte, 6)
				binary.BigEndian.PutUint16(tlv[0:2], tlvMandatory|tlvTypeResult)
				binary.BigEndian.PutUint16(tlv[2:4], 2)
				binary.BigEndian.PutUint16(tlv[4:6], value)
				answer = (&EAPPacket{Code: EAPResponse, Identifier: p.Identifier, Type: EAPTypeTLVExtensions,
					Data: tlv}).Encode()
			}
			if _, err := run.tlsConn.Write(answer); err != nil {
				t.Fatal(err)
			}
			out = pipe.take()
		}
		reply = exchange((&EAPPacket{Code: EAPResponse, Identifier: eap.Identifier, Type: EAPTypePEAP,
			Data: (&EAPTLSFrame{Data: out}).Encode()}).Encode(), state)
	}
	t.Fatal("the conversation did not finish in 40 round trips")
	return run
}

func TestPEAPCarriesAPasswordInGTCAndHandsTheAccessPointEAPTLSKeys(t *testing.T) {
	pki := newTestPKI(t)
	srv, auth := tunnelTestServer(t, pki, false, EAPTunnelConfig{TTLS: true, PEAP: true})
	run := peapConversation(t, srv, pki, "ada", []string{"correct-horse-battery"}, 0, false)
	if run.startType != EAPTypePEAP || run.code != CodeAccessAccept || run.result != tlvSuccess {
		t.Fatalf("offered %d, result TLV %d, answered %d; want PEAP, success and an accept", run.startType,
			run.result, run.code)
	}
	if len(run.prompts) != 1 || run.prompts[0] != gtcPrompt {
		t.Errorf("the GTC prompts were %q", run.prompts)
	}
	if name, _ := run.accept.Attr(AttrUserName); string(name) != "ada" {
		t.Errorf("the accept names %q, want the identity given inside the tunnel", name)
	}
	if got := run.tlsConn.ConnectionState().Version; got != tls.VersionTLS12 {
		t.Errorf("the tunnel ran TLS %x", got)
	}
	// MS-PEAP §3.1.5.7, no cryptobinding: the first 64 octets of RFC 5216's keying
	// material, the server's Recv-Key the first 32.
	cs := run.tlsConn.ConnectionState()
	km, err := cs.ExportKeyingMaterial("client EAP encryption", nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("a-secret-of-sufficient-length")
	if recv := mppeKey(t, run.accept, vendorTypeRecvKey, secret, run.sentWith); !bytes.Equal(recv, km[:32]) {
		t.Error("MPPE-Recv-Key is not the first 32 octets of the keying material")
	}
	if send := mppeKey(t, run.accept, vendorTypeSendKey, secret, run.sentWith); !bytes.Equal(send, km[32:64]) {
		t.Error("MPPE-Send-Key is not the second 32 octets of the keying material")
	}
	if auth.calls != 1 {
		t.Errorf("the password was checked %d times", auth.calls)
	}
}

// A password right for somebody who also gives a code is asked for the code in a
// second GTC prompt, the use GTC was made for.
func TestPEAPAsksForACodeInASecondPrompt(t *testing.T) {
	pki := newTestPKI(t)
	srv, _ := tunnelTestServer(t, pki, false, EAPTunnelConfig{PEAP: true})
	srv.auth = &peapCodeAuth{ttlsAuth: &ttlsAuth{}}
	run := peapConversation(t, srv, pki, "grace", []string{"a-password-and-a-code", "123456"}, 0, false)
	if run.code != CodeAccessAccept || len(run.prompts) != 2 || run.prompts[1] != codePrompt {
		t.Errorf("answered %d after prompts %q; want an accept after the password and a code", run.code, run.prompts)
	}
	run = peapConversation(t, srv, pki, "grace", []string{"a-password-and-a-code", "000000"}, 0, false)
	if run.code != CodeAccessReject || run.result != tlvFailure {
		t.Errorf("a wrong code: answered %d, result TLV %d", run.code, run.result)
	}
}

type peapCodeAuth struct{ *ttlsAuth }

func (a *peapCodeAuth) VerifyCode(_ context.Context, u, code string) error {
	if u == "grace" && code == "123456" {
		return nil
	}
	return ErrSecondFactor
}

func TestPEAPRefusesWhatItCannotAccept(t *testing.T) {
	pki := newTestPKI(t)
	srv, _ := tunnelTestServer(t, pki, false, EAPTunnelConfig{PEAP: true})
	if run := peapConversation(t, srv, pki, "ada", []string{"wrong"}, 0, false); run.code != CodeAccessReject ||
		run.result != tlvFailure {
		t.Errorf("a wrong password: answered %d, result TLV %d; want the failure said inside the tunnel too",
			run.code, run.result)
	}
	if run := peapConversation(t, srv, pki, "grace", []string{"a-password-and-a-code"}, 0, false); run.code !=
		CodeAccessReject {
		t.Errorf("a right password needing a code, with no code verifier: answered %d", run.code)
	}
	// The peer saying failure to the server's success is not an accept.
	if run := peapConversation(t, srv, pki, "ada", []string{"correct-horse-battery"}, tlvFailure, false); run.code !=
		CodeAccessReject {
		t.Errorf("a peer answering the success with failure: answered %d", run.code)
	}
}

// With EAP-TLS on, a peer without a certificate Naks it naming what it would rather,
// in its order; the first that is on is begun.
func TestAPeerNakingEAPTLSIsGivenTheFirstTunnelItNamesThatIsOn(t *testing.T) {
	pki := newTestPKI(t)
	srv, _ := tunnelTestServer(t, pki, true, EAPTunnelConfig{PEAP: true})
	run := peapConversation(t, srv, pki, "ada", []string{"correct-horse-battery"}, 0, true)
	if run.startType != EAPTypeTLS || run.code != CodeAccessAccept {
		t.Errorf("first offered %d, answered %d; want EAP-TLS, then PEAP, the Nak's TTLS being off", run.startType,
			run.code)
	}
}

func TestPEAPPeerResult(t *testing.T) {
	result := func(head uint16, value []byte) []byte {
		tlv := make([]byte, 4, 4+len(value))
		binary.BigEndian.PutUint16(tlv[0:2], head)
		binary.BigEndian.PutUint16(tlv[2:4], uint16(len(value)))
		return append(tlv, value...)
	}
	pkt := func(tlvs ...[]byte) []byte {
		return (&EAPPacket{Code: EAPResponse, Identifier: 7, Type: EAPTypeTLVExtensions,
			Data: bytes.Join(tlvs, nil)}).Encode()
	}
	for name, c := range map[string]struct {
		in   []byte
		want uint16
		ok   bool
	}{
		"success":                        {pkt(result(tlvMandatory|tlvTypeResult, []byte{0, 1})), tlvSuccess, true},
		"failure":                        {pkt(result(tlvMandatory|tlvTypeResult, []byte{0, 2})), tlvFailure, true},
		"an optional TLV it ignores":     {pkt(result(99, []byte{1}), result(tlvMandatory|tlvTypeResult, []byte{0, 1})), tlvSuccess, true},
		"a mandatory TLV it cannot read": {pkt(result(tlvMandatory|99, []byte{1}), result(tlvMandatory|tlvTypeResult, []byte{0, 1})), 0, false},
		"no Result":                      {pkt(result(99, []byte{1})), 0, false},
		"a Result of three bytes":        {pkt(result(tlvMandatory|tlvTypeResult, []byte{0, 0, 1})), 0, false},
		"a TLV cut short":                {pkt([]byte{0x80, 3, 0, 2, 0}), 0, false},
	} {
		got, ok := peapPeerResult(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: %d, %v; want %d, %v", name, got, ok, c.want, c.ok)
		}
	}
}
