package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// serveDirectory answers as a directory of people people would, for a directory sync:
// a bind, and a paged search (RFC 4511 §4.5, with RFC 2696's control) over all of them.
// It holds no entries, and writes each as it is asked for, so what a sync is measured
// doing is its own work and not this.
func serveDirectory(l net.Listener, people int) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer func() { _ = conn.Close() }()
			// A client that goes away is how every session ends.
			_ = directorySession(conn, people)
		}()
	}
}

func directorySession(conn io.ReadWriter, people int) error {
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			return err
		}
		if len(packet.Children) < 2 {
			return fmt.Errorf("an LDAP message with %d parts", len(packet.Children))
		}
		id, ok := packet.Children[0].Value.(int64)
		if !ok {
			return fmt.Errorf("an LDAP message with no id")
		}
		switch packet.Children[1].Tag {
		case ldap.ApplicationBindRequest:
			if _, err := conn.Write(ldapResult(id, ldap.ApplicationBindResponse, nil)); err != nil {
				return err
			}
		case ldap.ApplicationSearchRequest:
			if err := answerSearch(conn, packet, id, people); err != nil {
				return err
			}
		case ldap.ApplicationUnbindRequest:
			return nil
		default:
			return fmt.Errorf("an operation this directory does not do: %d", packet.Children[1].Tag)
		}
	}
}

// answerSearch sends the page the request's control asks for, or everybody without one.
func answerSearch(w io.Writer, packet *ber.Packet, id int64, people int) error {
	size, after := people, 0
	if len(packet.Children) > 2 {
		for _, control := range packet.Children[2].Children {
			if len(control.Children) < 2 || control.Children[0].Value != ldap.ControlTypePaging {
				continue
			}
			value := control.Children[len(control.Children)-1]
			inner := ber.DecodePacket(value.Data.Bytes())
			if len(inner.Children) == 2 {
				if n, ok := inner.Children[0].Value.(int64); ok && n > 0 {
					size = int(n)
				}
				// The cookie is the last person sent, which a client only hands back.
				if cookie := inner.Children[1].Data.String(); cookie != "" {
					after, _ = strconv.Atoi(cookie)
				}
			}
		}
	}
	last := min(after+size, people)
	for n := after + 1; n <= last; n++ {
		if _, err := w.Write(directoryEntry(id, n)); err != nil {
			return err
		}
	}
	cookie := ""
	if last < people {
		cookie = strconv.Itoa(last)
	}
	_, err := w.Write(ldapResult(id, ldap.ApplicationSearchResultDone, pagingControl(size, cookie)))
	return err
}

func directoryEntry(id int64, n int) []byte {
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "entry")
	name := "dir-" + strconv.Itoa(n)
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid="+name+",dc=load,dc=test", "dn"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, attr := range [][2]string{
		{"entryUUID", fmt.Sprintf("00000000-0000-4000-8000-%012d", n)},
		{"uid", name}, {"cn", "Person " + name}, {"mail", name + "@" + benchDomain},
	} {
		one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr[0], "type"))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr[1], "value"))
		one.AppendChild(values)
		attrs.AppendChild(one)
	}
	entry.AppendChild(attrs)
	return ldapMessage(id, entry, nil)
}

// ldapResult is an LDAPResult of success (RFC 4511 §4.1.9).
func ldapResult(id int64, op ber.Tag, controls *ber.Packet) []byte {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, op, nil, "result")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldap.LDAPResultSuccess), "code"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "message"))
	return ldapMessage(id, result, controls)
}

func ldapMessage(id int64, op, controls *ber.Packet) []byte {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "message")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	msg.AppendChild(op)
	if controls != nil {
		msg.AppendChild(controls)
	}
	return msg.Bytes()
}

// pagingControl is the control a page ends with: an empty cookie says it was the last.
func pagingControl(size int, cookie string) *ber.Packet {
	control := ldap.NewControlPaging(uint32(size))
	control.SetCookie([]byte(cookie))
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	wrapper.AppendChild(control.Encode())
	return wrapper
}
