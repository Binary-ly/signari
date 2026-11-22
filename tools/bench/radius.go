package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- RADIUS specifies MD5 for the password and the message authenticator
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// RADIUS codes and attributes used here, as engine/internal/radius/packet.go
// numbers them.
const (
	radiusAccessRequest = 1
	radiusAccessAccept  = 2
	attrUserName        = 1
	attrUserPassword    = 2
	attrMessageAuth     = 80
)

// accessRequest builds an Access-Request for a PAP password. The password is
// hidden as the engine's own decoder reverses it (engine/internal/radius,
// DecodePassword), and the Message-Authenticator is the HMAC-MD5 of the packet
// with that attribute zeroed, which a server defending against BlastRADIUS
// requires.
func accessRequest(secret, username, password string, id byte, auth [16]byte) []byte {
	pw := []byte(password)
	for len(pw) == 0 || len(pw)%16 != 0 {
		pw = append(pw, 0)
	}
	hidden := make([]byte, 0, len(pw))
	prev := auth[:]
	for i := 0; i < len(pw); i += 16 {
		h := md5.New() // #nosec G401 -- RFC 2865 §5.2
		h.Write([]byte(secret))
		h.Write(prev)
		key := h.Sum(nil)
		block := make([]byte, 16)
		for j := range block {
			block[j] = pw[i+j] ^ key[j]
		}
		hidden = append(hidden, block...)
		prev = block
	}

	var attrs []byte
	add := func(typ byte, v []byte) {
		attrs = append(attrs, typ, byte(len(v)+2))
		attrs = append(attrs, v...)
	}
	add(attrMessageAuth, make([]byte, 16))
	add(attrUserName, []byte(username))
	add(attrUserPassword, hidden)

	pkt := make([]byte, 20, 20+len(attrs))
	pkt[0], pkt[1] = radiusAccessRequest, id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(attrs)))
	copy(pkt[4:20], auth[:])
	pkt = append(pkt, attrs...)

	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(pkt)
	copy(pkt[22:38], mac.Sum(nil)) // the Message-Authenticator is the first attribute
	return pkt
}

// radiusPAP sends one Access-Request and waits for Access-Accept.
func radiusPAP(ctx context.Context, addr, secret, username, password string) error {
	var auth [16]byte
	if _, err := rand.Read(auth[:]); err != nil {
		return err
	}
	var id [1]byte
	_, _ = rand.Read(id[:])
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(accessRequest(secret, username, password, id[0], auth)); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 20 || buf[1] != id[0] {
		return fmt.Errorf("an answer that is not to this request")
	}
	if buf[0] != radiusAccessAccept {
		return fmt.Errorf("answered code %d, not Access-Accept", buf[0])
	}
	return nil
}
