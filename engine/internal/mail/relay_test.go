package mail

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

// relayed is what a relay was handed.
type relayed struct {
	mailFrom, rcptTo string
	data             string
}

// fakeRelay is as much of an SMTP server as a message needs: STARTTLS, one
// message, and what it was told. Sending is what has to work, and building a
// message proves nothing about the envelope around it.
func fakeRelay(t *testing.T) (*SMTPSender, <-chan relayed) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	got := make(chan relayed, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var m relayed
		tc := textproto.NewConn(conn)
		_ = tc.PrintfLine("220 relay")
		secure := false
		for {
			line, err := tc.ReadLine()
			if err != nil {
				return
			}
			verb, _, _ := strings.Cut(line, " ")
			switch strings.ToUpper(verb) {
			case "EHLO":
				if secure {
					_ = tc.PrintfLine("250 relay")
				} else {
					_ = tc.PrintfLine("250-relay")
					_ = tc.PrintfLine("250 STARTTLS")
				}
			case "STARTTLS":
				_ = tc.PrintfLine("220 go ahead")
				secured := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12,
					Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
				conn, tc, secure = secured, textproto.NewConn(secured), true
			case "MAIL":
				m.mailFrom = line
				_ = tc.PrintfLine("250 ok")
			case "RCPT":
				m.rcptTo = line
				_ = tc.PrintfLine("250 ok")
			case "DATA":
				_ = tc.PrintfLine("354 go ahead")
				data, err := tc.ReadDotBytes()
				if err != nil {
					return
				}
				m.data = string(data)
				_ = tc.PrintfLine("250 ok")
			case "QUIT":
				_ = tc.PrintfLine("221 bye")
				got <- m
				return
			default:
				_ = tc.PrintfLine("500 no")
			}
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return &SMTPSender{Host: "127.0.0.1", Port: addr.Port, FromAddr: "noreply@example.com",
		FromName: "Example Identity", RootCAs: roots}, got
}

// The envelope is the domain receivers check SPF against, so an organisation's
// address belongs there as well as in the From line, and the two agreeing is what
// DMARC reads. The deployment's stays for everybody else.
func TestTheEnvelopeCarriesTheSenderItsMessageShows(t *testing.T) {
	for _, c := range []struct {
		name     string
		m        Message
		envelope string
	}{
		{"the deployment's", Message{}, "noreply@example.com"},
		{"an organisation's", Message{From: "id@acme.example", FromName: "Acme"}, "id@acme.example"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, got := fakeRelay(t)
			// A line that starts with a dot is what SMTP's framing eats if nothing
			// stuffs it, and a code on the last line must arrive whole.
			c.m.To, c.m.Subject, c.m.Body = "u@example.com", "s", "Hello.\n\n.starts with a dot\n\n123456"
			if err := s.Send(t.Context(), c.m); err != nil {
				t.Fatal(err)
			}
			m := <-got
			if !strings.Contains(m.mailFrom, "<"+c.envelope+">") {
				t.Errorf("the envelope says %q", m.mailFrom)
			}
			if !strings.Contains(m.rcptTo, "<u@example.com>") {
				t.Errorf("the recipient is %q", m.rcptTo)
			}
			plain, page := parts(t, m.data)
			if want := c.m.Body; strings.ReplaceAll(plain, "\r\n", "\n") != want {
				t.Errorf("the text part arrived as %q", plain)
			}
			for _, want := range []string{".starts with a dot", "123456"} {
				if !strings.Contains(page, want) {
					t.Errorf("the page arrived without %q:\n%s", want, page)
				}
			}
		})
	}
}

// An organisation's sender changes who a message is from, not how it travels: a
// relay that offers no STARTTLS is refused for it too.
func TestARelayThatWillNotEncryptIsRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		tc := textproto.NewConn(conn)
		_ = tc.PrintfLine("220 relay")
		if _, err := tc.ReadLine(); err == nil {
			_ = tc.PrintfLine("250 relay")
		}
		_, _ = tc.ReadLine()
	}()
	s := &SMTPSender{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, FromAddr: "noreply@example.com"}
	err = s.Send(t.Context(), Message{To: "u@example.com", Subject: "s", Body: "b", From: "id@acme.example"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("sending over a relay with no STARTTLS answered %v", err)
	}
}
