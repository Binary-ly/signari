// Package ldaptest is a directory for tests: LDAPS on loopback that answers a
// simple bind. Shared by the delegated verifier's tests and the sign-in tests
// that migrate a person through it.
package ldaptest

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Directory serves LDAPS on loopback until the test ends, and answers a simple
// bind with success for dn and password, invalidCredentials (49) otherwise.
// It returns the ldaps:// URL, the PEM of the certificate to trust (httptest's,
// valid for 127.0.0.1), a function returning the DNs binds named, and one that
// stops the directory, as an outage would.
func Directory(t *testing.T, dn, password string) (url, caPEM string, binds func() []string, stop func()) {
	t.Helper()
	tlsSrv := httptest.NewTLSServer(nil)
	cert := tlsSrv.TLS.Certificates[0]
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}))
	tlsSrv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() { once.Do(func() { _ = ln.Close() }) }
	t.Cleanup(stop)
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, dn, password, func(name string) {
				mu.Lock()
				seen = append(seen, name)
				mu.Unlock()
			})
		}
	}()
	binds = func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
	return "ldaps://" + ln.Addr().String(), caPEM, binds, stop
}

func serve(c net.Conn, dn, password string, record func(string)) {
	defer func() { _ = c.Close() }()
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		if op.Tag != 0 || len(op.Children) < 3 { // not a BindRequest: an unbind
			return
		}
		name, _ := op.Children[1].Value.(string)
		record(name)
		code := int64(49)
		if name == dn && op.Children[2].Data.String() == password {
			code = 0
		}
		resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		br := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "")
		br.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
		br.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		br.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		resp.AppendChild(br)
		if _, err := c.Write(resp.Bytes()); err != nil {
			return
		}
	}
}
