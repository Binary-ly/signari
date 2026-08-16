package radius

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A real EAP-TLS conversation, end to end.
//
// The supplicant here is an actual crypto/tls client, not a recording. It
// performs a genuine handshake -- client certificate and all -- with every byte
// travelling through EAP fragmentation, RADIUS attribute splitting, and the
// UDP request/challenge cycle. If any layer mangles a byte the handshake fails,
// which is the only test of this that is worth anything.

// testPKI is a CA that can issue a server and client certificate.
type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Signari EAP Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testPKI{caCert: cert, caKey: key, pool: pool}
}

// issue mints a leaf certificate. extraDER pads it so the handshake is forced
// to fragment, which is the case that hides bugs.
func (p *testPKI) issue(t *testing.T, cn string, client bool, pad int) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{cn},
	}
	if pad > 0 {
		// A large extension makes the certificate big enough that the handshake
		// must be fragmented across several EAP round trips.
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: make([]byte, pad),
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// certAuth maps a certificate to a username for the test.
type certAuth struct {
	refuse bool
}

func (c *certAuth) AuthenticateCertificate(cert *x509.Certificate) (string, error) {
	if c.refuse {
		return "", errors.New("this certificate is not permitted")
	}
	return cert.Subject.CommonName, nil
}

// supplicant is a crypto/tls client speaking EAP-TLS over a RADIUS server.
//
// It drives the conversation the way a laptop does: send an identity, then
// answer each Access-Challenge until the server accepts or rejects.
type supplicant struct {
	t      *testing.T
	server *Server
	conn   *fakePacketConn
	secret []byte
	cert   tls.Certificate
	pool   *x509.CertPool

	tlsConn  *tls.Conn
	pipe     *eapConn
	identity string

	// serverFragments counts challenges that carried the More flag, and
	// clientFragments our own. A fragmentation test that never fragmented would
	// otherwise pass silently.
	serverFragments int
	clientFragments int

	// pending is our own TLS output still to be sent, fragment by fragment.
	pending []byte
	// declared records that the total length has already been sent, so it goes
	// on the first fragment only.
	declared bool
}

// nextFragment takes the next piece of our outbound flight.
func (s *supplicant) nextFragment() []byte {
	frame := &EAPTLSFrame{}
	if len(s.pending) > eapTLSMaxFragment {
		s.clientFragments++
		if !s.declared {
			frame.LengthIncluded = true
			frame.TotalLength = uint32(len(s.pending))
			s.declared = true
		}
		frame.More = true
		frame.Data = s.pending[:eapTLSMaxFragment]
		s.pending = s.pending[eapTLSMaxFragment:]
	} else {
		frame.Data = s.pending
		s.pending = nil
		s.declared = false
	}
	return frame.Encode()
}

// fakePacketConn is the UDP socket, in memory.
type fakePacketConn struct {
	mu   sync.Mutex
	cond *sync.Cond
	sent [][]byte
}

func newFakePacketConn() *fakePacketConn {
	c := &fakePacketConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	c.cond.Broadcast()
	return len(b), nil
}

// take waits for the next packet the server sent.
func (c *fakePacketConn) take(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.sent) == 0 {
		if time.Now().After(deadline) {
			return nil, errors.New("the server sent nothing")
		}
		c.mu.Unlock()
		time.Sleep(time.Millisecond)
		c.mu.Lock()
	}
	out := c.sent[0]
	c.sent = c.sent[1:]
	return out, nil
}

func (c *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *fakePacketConn) Close() error                           { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                    { return eapAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error            { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error       { return nil }

// run performs the whole conversation and reports the final RADIUS code.
func (s *supplicant) run() (byte, *Packet, error) {
	// The client's TLS runs against an in-memory conn, exactly as the server's
	// does; the test moves bytes between them through EAP.
	s.pipe = newEAPConn()
	s.tlsConn = tls.Client(s.pipe, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		RootCAs:      s.pool,
		ServerName:   "radius.test",
		MinVersion:   tls.VersionTLS12,
	})
	handshakeDone := make(chan struct{})
	var handshakeErr error
	go func() {
		handshakeErr = s.tlsConn.Handshake()
		close(handshakeDone)
	}()

	// 1. EAP-Response/Identity.
	identity := (&EAPPacket{Code: EAPResponse, Identifier: 1, Type: EAPTypeIdentity,
		Data: []byte(s.identity)}).Encode()
	reply, err := s.exchange(identity, nil)
	if err != nil {
		return 0, nil, err
	}

	// 2. Loop until the server stops challenging.
	for round := 0; round < 40; round++ {
		if reply.Code != CodeAccessChallenge {
			select {
			case <-handshakeDone:
			case <-time.After(time.Second):
			}
			_ = handshakeErr
			return reply.Code, reply, nil
		}

		state, _ := reply.Attr(AttrState)
		raw, ok := reply.EAPMessage()
		if !ok {
			return 0, nil, errors.New("a challenge carried no EAP-Message")
		}
		eap, err := DecodeEAP(raw)
		if err != nil {
			return 0, nil, fmt.Errorf("decoding the server's EAP: %w", err)
		}
		if eap.Type != EAPTypeTLS {
			return 0, nil, fmt.Errorf("server offered EAP type %d", eap.Type)
		}
		frame, err := DecodeEAPTLS(eap.Data)
		if err != nil {
			return 0, nil, err
		}

		// Feed whatever TLS data arrived to our client.
		if len(frame.Data) > 0 {
			s.pipe.feed(frame.Data)
		}

		var payload []byte
		switch {
		case frame.More:
			// Acknowledge the fragment with an empty EAP-TLS packet, as a real
			// supplicant does.
			s.serverFragments++
			payload = (&EAPTLSFrame{}).Encode()

		case len(s.pending) > 0:
			// Still sending our own flight: the server just acknowledged a
			// fragment, so send the next one.
			payload = s.nextFragment()

		default:
			// Take whatever our TLS client has produced and send it, fragmented
			// if it is large.
			//
			// A real supplicant MUST do this: a client certificate chain is
			// several kilobytes and a RADIUS packet holds 4096 bytes in total.
			// The first version of this test sent the whole flight in one frame,
			// the packet exceeded the limit, and the server silently dropped it
			// -- which is exactly what a real access point would do.
			s.pending = s.pipe.waitOut(handshakeDone, 2*time.Second)
			payload = s.nextFragment()
		}

		resp := (&EAPPacket{Code: EAPResponse, Identifier: eap.Identifier,
			Type: EAPTypeTLS, Data: payload}).Encode()
		reply, err = s.exchange(resp, state)
		if err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, errors.New("the conversation did not finish in 40 round trips")
}

// exchange sends one Access-Request and returns the server's reply.
func (s *supplicant) exchange(eap, state []byte) (*Packet, error) {
	attrs := EAPAttributes(eap)
	if state != nil {
		attrs = append(attrs, Attribute{Type: AttrState, Value: state})
	}
	attrs = append(attrs, Attribute{Type: AttrUserName, Value: []byte(s.identity)})

	req, err := buildTestRequest(s.secret, attrs)
	if err != nil {
		return nil, err
	}
	s.server.handle(context.Background(), s.conn,
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}, req)

	raw, err := s.conn.take(5 * time.Second)
	if err != nil {
		return nil, err
	}
	return Decode(raw)
}

func eapTestServer(t *testing.T, pki *testPKI, auth CertificateAuthenticator) *Server {
	return eapTestServerWithPad(t, pki, auth, 0)
}

// eapTestServerWithPad gives the server a large certificate, so ITS flight has
// to be fragmented too.
func eapTestServerWithPad(t *testing.T, pki *testPKI, auth CertificateAuthenticator,
	pad int) *Server {

	t.Helper()
	_, netw, _ := net.ParseCIDR("10.0.0.0/8")
	srv, err := New(Config{
		Clients: []Client{{Net: netw, Secret: "a-secret-of-sufficient-length", Name: "ap"}},
		EAPTLS: &EAPTLSConfig{
			Certificate: pki.issue(t, "radius.test", false, pad),
			ClientCAs:   pki.pool,
			Auth:        auth,
		},
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// TestEAPTLSFullHandshake is the test that matters: a real TLS handshake,
// carried entirely over EAP and RADIUS.
func TestEAPTLSFullHandshake(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})

	sup := &supplicant{
		t: t, server: srv, conn: newFakePacketConn(),
		secret:   []byte("a-secret-of-sufficient-length"),
		cert:     pki.issue(t, "alice@corp.test", true, 0),
		pool:     pki.pool,
		identity: "anonymous",
	}

	code, reply, err := sup.run()
	if err != nil {
		t.Fatalf("the conversation failed: %v", err)
	}
	if code != CodeAccessAccept {
		t.Fatalf("got code %d, want Access-Accept", code)
	}

	// The name must come from the CERTIFICATE, not from the identity the
	// supplicant announced -- which was "anonymous".
	name, ok := reply.Attr(AttrUserName)
	if !ok {
		t.Fatal("the accept carried no User-Name")
	}
	if string(name) != "alice@corp.test" {
		t.Fatalf("User-Name is %q; it must come from the certificate, not from the "+
			"unauthenticated identity the supplicant sent", name)
	}

	// And the keys, without which the laptop associates and passes no traffic.
	var vendorCount int
	for _, a := range reply.Attributes {
		if a.Type == AttrVendorSpecific {
			vendorCount++
		}
	}
	if vendorCount != 2 {
		t.Fatalf("got %d vendor-specific attributes, want 2 (MPPE send and recv keys)",
			vendorCount)
	}

	// EAP-Success, so the supplicant stops rather than retrying.
	raw, _ := reply.EAPMessage()
	eap, err := DecodeEAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if eap.Code != EAPSuccess {
		t.Fatalf("the accept carried EAP code %d, want Success", eap.Code)
	}
}

// TestEAPTLSFragmentation forces the handshake across many EAP round trips.
//
// A certificate small enough to fit in one fragment hides every fragmentation
// bug there is, which is why this pads one to several kilobytes.
func TestEAPTLSFragmentation(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})

	sup := &supplicant{
		t: t, server: srv, conn: newFakePacketConn(),
		secret: []byte("a-secret-of-sufficient-length"),
		// 6 KB of padding: several fragments in each direction.
		cert:     pki.issue(t, "bob@corp.test", true, 6000),
		pool:     pki.pool,
		identity: "anonymous",
	}

	code, reply, err := sup.run()
	if err != nil {
		t.Fatalf("a fragmented handshake failed: %v", err)
	}
	if code != CodeAccessAccept {
		t.Fatalf("got code %d, want Access-Accept", code)
	}
	name, _ := reply.Attr(AttrUserName)
	if string(name) != "bob@corp.test" {
		t.Fatalf("User-Name %q", name)
	}
	if sup.clientFragments == 0 {
		t.Fatal("the supplicant never fragmented, so this test proved nothing " +
			"about reassembly")
	}
	t.Logf("client sent %d fragments", sup.clientFragments)
}

// TestEAPTLSRefusesAnUnknownCA: a certificate from another CA is not a login.
func TestEAPTLSRefusesAnUnknownCA(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})

	sup := &supplicant{
		t: t, server: srv, conn: newFakePacketConn(),
		secret:   []byte("a-secret-of-sufficient-length"),
		cert:     other.issue(t, "attacker@corp.test", true, 0),
		pool:     pki.pool,
		identity: "anonymous",
	}

	code, _, err := sup.run()
	if err != nil {
		// A handshake failure part-way is an acceptable outcome here: the
		// server refused before the conversation could complete.
		return
	}
	if code == CodeAccessAccept {
		t.Fatal("a certificate from an unknown CA was accepted")
	}
}

// TestEAPTLSRefusesWhenTheAuthenticatorSaysNo separates "valid certificate"
// from "permitted person".
func TestEAPTLSRefusesWhenTheAuthenticatorSaysNo(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{refuse: true})

	sup := &supplicant{
		t: t, server: srv, conn: newFakePacketConn(),
		secret:   []byte("a-secret-of-sufficient-length"),
		cert:     pki.issue(t, "leaver@corp.test", true, 0),
		pool:     pki.pool,
		identity: "anonymous",
	}

	code, reply, err := sup.run()
	if err != nil {
		t.Fatalf("the conversation failed: %v", err)
	}
	if code != CodeAccessReject {
		t.Fatalf("got code %d, want Access-Reject: a cryptographically valid "+
			"certificate belonging to somebody who has left is not a login", code)
	}
	// EAP-Failure, so the supplicant gives up rather than retrying.
	raw, ok := reply.EAPMessage()
	if !ok {
		t.Fatal("the reject carried no EAP-Message, so a supplicant would retry")
	}
	eap, _ := DecodeEAP(raw)
	if eap.Code != EAPFailure {
		t.Fatalf("the reject carried EAP code %d, want Failure", eap.Code)
	}
}

// TestEAPWithoutEAPTLSConfigured must refuse rather than downgrade.
func TestEAPWithoutEAPTLSConfigured(t *testing.T) {
	_, netw, _ := net.ParseCIDR("10.0.0.0/8")
	srv, err := New(Config{
		Clients: []Client{{Net: netw, Secret: "a-secret-of-sufficient-length", Name: "ap"}},
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	conn := newFakePacketConn()
	attrs := EAPAttributes((&EAPPacket{Code: EAPResponse, Identifier: 1,
		Type: EAPTypeIdentity, Data: []byte("alice")}).Encode())
	req, err := buildTestRequest([]byte("a-secret-of-sufficient-length"), attrs)
	if err != nil {
		t.Fatal(err)
	}
	srv.handle(context.Background(), conn,
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}, req)

	raw, err := conn.take(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != CodeAccessReject {
		t.Fatalf("got code %d, want Access-Reject", reply.Code)
	}
}

// TestEAPSessionsAreBounded: an attacker starting handshakes must not grow the
// table without limit.
func TestEAPSessionsAreBounded(t *testing.T) {
	s := newEAPSessions()
	for i := 0; i < eapMaxSessions+50; i++ {
		s.put(&eapSession{
			state:    fmt.Sprintf("state-%d", i),
			conn:     newEAPConn(),
			lastSeen: time.Now(),
		})
	}
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	if n > eapMaxSessions {
		t.Fatalf("%d sessions held, cap is %d: an attacker who never finishes a "+
			"handshake would exhaust memory", n, eapMaxSessions)
	}
}

// TestEAPMessageReassembly covers the RADIUS half of the two fragmentations.
func TestEAPMessageReassembly(t *testing.T) {
	// An EAP packet larger than one attribute can hold.
	big := &EAPPacket{Code: EAPRequest, Identifier: 7, Type: EAPTypeTLS,
		Data: make([]byte, 700)}
	for i := range big.Data {
		big.Data[i] = byte(i % 251)
	}
	encoded := big.Encode()

	attrs := EAPAttributes(encoded)
	if len(attrs) < 3 {
		t.Fatalf("a %d byte packet became %d attributes; it must be split at 253",
			len(encoded), len(attrs))
	}
	for i, a := range attrs {
		if len(a.Value) > maxEAPMessageChunk {
			t.Fatalf("attribute %d is %d bytes, over the 253 limit", i, len(a.Value))
		}
	}

	p := &Packet{Attributes: attrs}
	back, ok := p.EAPMessage()
	if !ok {
		t.Fatal("reassembly found nothing")
	}
	if len(back) != len(encoded) {
		t.Fatalf("reassembled %d bytes from %d", len(back), len(encoded))
	}
	for i := range back {
		if back[i] != encoded[i] {
			t.Fatalf("byte %d differs after a round trip through attributes", i)
		}
	}
}

// TestDecodeEAPRefusesALyingLength: the length field must not reach past the
// buffer.
func TestDecodeEAPRefusesALyingLength(t *testing.T) {
	b := []byte{EAPRequest, 1, 0xFF, 0xFF, EAPTypeTLS}
	if _, err := DecodeEAP(b); err == nil {
		t.Fatal("an EAP packet claiming 65535 bytes was accepted")
	}
	if _, err := DecodeEAP([]byte{EAPSuccess, 1, 0, 8, 1, 2, 3, 4}); err == nil {
		t.Fatal("an EAP Success longer than 4 bytes was accepted")
	}
}

// TestMPPEKeysAreDistinctAndSalted checks the two keys do not collide.
func TestMPPEKeysAreDistinctAndSalted(t *testing.T) {
	msk := make([]byte, 64)
	for i := range msk {
		msk[i] = byte(i)
	}
	secret := []byte("a-secret-of-sufficient-length")
	auth := make([]byte, 16)

	attrs, err := mppeKeyAttributes(msk, secret, auth)
	if err != nil {
		t.Fatal(err)
	}
	if len(attrs) != 2 {
		t.Fatalf("got %d attributes, want 2", len(attrs))
	}
	if string(attrs[0].Value) == string(attrs[1].Value) {
		t.Fatal("the send and recv keys encoded identically")
	}
	// The salts must differ, or the two ciphertexts leak their relationship.
	s0, s1 := attrs[0].Value[6:8], attrs[1].Value[6:8]
	if string(s0) == string(s1) {
		t.Fatal("both keys used the same salt")
	}
	if s0[0]&0x80 == 0 || s1[0]&0x80 == 0 {
		t.Fatal("the salt's top bit must be set (RFC 2548)")
	}
	// And the vendor id must be Microsoft's, or no access point understands it.
	for i, a := range attrs {
		if a.Value[0] != 0 || a.Value[1] != 0 || a.Value[2] != 1 || a.Value[3] != 0x37 {
			t.Fatalf("attribute %d has vendor id %v, want 311", i, a.Value[:4])
		}
	}
}

func TestEAPTLSConfigIsChecked(t *testing.T) {
	pki := newTestPKI(t)
	_, netw, _ := net.ParseCIDR("10.0.0.0/8")
	base := Config{
		Clients: []Client{{Net: netw, Secret: "a-secret-of-sufficient-length", Name: "ap"}},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name string
		cfg  *EAPTLSConfig
		want string
	}{
		{"no client CAs", &EAPTLSConfig{
			Certificate: pki.issue(t, "radius.test", false, 0), Auth: &certAuth{}},
			"client CAs"},
		{"no authenticator", &EAPTLSConfig{
			Certificate: pki.issue(t, "radius.test", false, 0), ClientCAs: pki.pool},
			"certificate authenticator"},
		{"no server certificate", &EAPTLSConfig{
			ClientCAs: pki.pool, Auth: &certAuth{}},
			"server certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.EAPTLS = tc.cfg
			_, err := New(cfg, nil, log)
			if err == nil {
				t.Fatal("accepted an incomplete EAP-TLS configuration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// buildTestRequest builds an Access-Request carrying arbitrary attributes.
//
// A Message-Authenticator is always included and always correct: RFC 3579 §3.2
// requires one on every packet carrying EAP, and this server refuses a packet
// without it, so a test helper that omitted it would only ever exercise the
// rejection path.
func buildTestRequest(secret []byte, attrs []Attribute) ([]byte, error) {
	var auth [16]byte
	if _, err := io.ReadFull(rand.Reader, auth[:]); err != nil {
		return nil, err
	}

	body := []byte{}
	add := func(typ byte, v []byte) {
		body = append(body, typ, byte(len(v)+2))
		body = append(body, v...)
	}
	for _, a := range attrs {
		add(a.Type, a.Value)
	}
	add(AttrMessageAuthenticator, make([]byte, 16))

	length := headerLen + len(body)
	pkt := make([]byte, headerLen)
	pkt[0], pkt[1] = CodeAccessRequest, 42
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	copy(pkt[4:20], auth[:])
	pkt = append(pkt, body...)

	mac := hmac.New(md5.New, secret)
	mac.Write(pkt)
	sum := mac.Sum(nil)
	for i := headerLen; i+2 <= len(pkt); {
		l := int(pkt[i+1])
		if pkt[i] == AttrMessageAuthenticator {
			copy(pkt[i+2:i+2+16], sum)
			break
		}
		if l <= 0 {
			break
		}
		i += l
	}
	return pkt, nil
}

// TestEAPTLSServerFragmentation exercises the OTHER direction.
//
// The test above fragments what the supplicant sends; this fragments what the
// server sends, by giving the server a certificate several kilobytes long. Both
// directions have their own code and their own ways to be wrong: one reassembles
// with the More flag, the other splits and declares a total length on the first
// fragment only.
func TestEAPTLSServerFragmentation(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServerWithPad(t, pki, &certAuth{}, 7000)

	sup := &supplicant{
		t: t, server: srv, conn: newFakePacketConn(),
		secret:   []byte("a-secret-of-sufficient-length"),
		cert:     pki.issue(t, "carol@corp.test", true, 0),
		pool:     pki.pool,
		identity: "anonymous",
	}

	code, reply, err := sup.run()
	if err != nil {
		t.Fatalf("a handshake with a large SERVER certificate failed: %v", err)
	}
	if code != CodeAccessAccept {
		t.Fatalf("got code %d, want Access-Accept", code)
	}
	name, _ := reply.Attr(AttrUserName)
	if string(name) != "carol@corp.test" {
		t.Fatalf("User-Name %q", name)
	}
	if sup.serverFragments == 0 {
		t.Fatal("the server never fragmented, so this test proved nothing about " +
			"its outbound splitting")
	}
	t.Logf("server sent %d fragments", sup.serverFragments)
}

// TestEAPTLSBothDirectionsFragment is the case a real deployment hits: a real
// certificate chain at each end.
func TestEAPTLSBothDirectionsFragment(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServerWithPad(t, pki, &certAuth{}, 5000)

	sup := &supplicant{
		t: t, server: srv, conn: newFakePacketConn(),
		secret:   []byte("a-secret-of-sufficient-length"),
		cert:     pki.issue(t, "dave@corp.test", true, 5000),
		pool:     pki.pool,
		identity: "anonymous",
	}

	code, reply, err := sup.run()
	if err != nil {
		t.Fatalf("a handshake fragmented in both directions failed: %v", err)
	}
	if code != CodeAccessAccept {
		t.Fatalf("got code %d, want Access-Accept", code)
	}
	name, _ := reply.Attr(AttrUserName)
	if string(name) != "dave@corp.test" {
		t.Fatalf("User-Name %q", name)
	}
	if sup.serverFragments == 0 || sup.clientFragments == 0 {
		t.Fatalf("expected fragmentation in both directions, got server=%d client=%d",
			sup.serverFragments, sup.clientFragments)
	}
	t.Logf("server %d fragments, client %d fragments",
		sup.serverFragments, sup.clientFragments)
}
