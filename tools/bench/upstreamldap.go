package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

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
// A search of one entry (scope baseObject) is a client reading the root DSE or a schema
// before it syncs, as some do on connecting (E.21): the root DSE says what this directory
// supports, and any other single entry is not here.
func answerSearch(w io.Writer, packet *ber.Packet, id int64, people int) error {
	if req := packet.Children[1]; len(req.Children) > 1 {
		if scope, ok := req.Children[1].Value.(int64); ok && scope == ldap.ScopeBaseObject {
			if req.Children[0].Data.String() == "" {
				if _, err := w.Write(rootDSE(id)); err != nil {
					return err
				}
			}
			_, err := w.Write(ldapResult(id, ldap.ApplicationSearchResultDone, nil))
			return err
		}
	}
	// A search for particular people (a client looking one up by name, as one does listing or
	// signing in through a federated directory) finds those people, and a search for anything
	// but people finds nobody; only a search for everybody walks the directory.
	req := packet.Children[1]
	if len(req.Children) > 6 {
		if filter, err := ldap.DecompileFilter(req.Children[6]); err == nil {
			if found, particular := whoMatches(filter, people); particular {
				for _, n := range found {
					if _, err := w.Write(directoryEntry(id, n)); err != nil {
						return err
					}
				}
				_, err := w.Write(ldapResult(id, ldap.ApplicationSearchResultDone, nil))
				return err
			}
		}
	}
	size, after, paged := people, 0, false
	if os.Getenv("BENCH_TRACE") != "" {
		filter, _ := ldap.DecompileFilter(req.Children[6])
		limit, _ := req.Children[3].Value.(int64)
		fmt.Fprintf(os.Stderr, "ldap search base=%q filter=%s sizeLimit=%d controls=%d\n",
			req.Children[0].Data.String(), filter, limit, len(packet.Children)-2)
	}
	if len(packet.Children) > 2 {
		for _, control := range packet.Children[2].Children {
			if len(control.Children) < 2 || control.Children[0].Value != ldap.ControlTypePaging {
				continue
			}
			value := control.Children[len(control.Children)-1]
			inner := ber.DecodePacket(value.Data.Bytes())
			paged = true
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
	// Unpaged, the request's size limit holds, and a search it cuts short ends in
	// sizeLimitExceeded (RFC 4511 §4.5.1.4) rather than with everybody.
	if limit, ok := req.Children[3].Value.(int64); ok && limit > 0 && !paged && int(limit) < people {
		for n := 1; n <= int(limit); n++ {
			if _, err := w.Write(directoryEntry(id, n)); err != nil {
				return err
			}
		}
		_, err := w.Write(ldapResultCode(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultSizeLimitExceeded, nil))
		return err
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

// rootDSE is the directory's description of itself (RFC 4512 §5.1): LDAPv3, its one naming
// context, and the paged results control it answers (RFC 2696).
func rootDSE(id int64) []byte {
	return searchEntry(id, "", [][2]string{
		{"supportedLDAPVersion", "3"}, {"namingContexts", "dc=load,dc=test"},
		{"supportedControl", ldap.ControlTypePaging}, {"vendorName", "bench"},
	})
}

func searchEntry(id int64, dn string, attributes [][2]string) []byte {
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "dn"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, attr := range attributes {
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

func directoryEntry(id int64, n int) []byte {
	name := "dir-" + strconv.Itoa(n)
	return searchEntry(id, "uid="+name+",dc=load,dc=test", [][2]string{
		{"objectClass", "inetOrgPerson"},
		{"entryUUID", fmt.Sprintf("00000000-0000-4000-8000-%012d", n)},
		{"uid", name}, {"cn", "Person " + name}, {"mail", name + "@" + benchDomain},
	})
}

// identityTerm is an equality term on an attribute that names one person, and personClass
// an object class people have; the directory's people are dir-N, so a term names N.
var (
	identityTerm = regexp.MustCompile(`\((?i:(uid|entryUUID|mail|cn))=([^()]*)\)`)
	classTerm    = regexp.MustCompile(`\((?i:objectClass)=([^()*]+)\)`)
	personNumber = regexp.MustCompile(`(?:dir-|-4000-8000-)0*([0-9]+)`)
)

func personClass(c string) bool {
	switch strings.ToLower(c) {
	case "inetorgperson", "person", "organizationalperson", "top":
		return true
	}
	return false
}

// whoMatches reads a search filter for the people it names. particular is false for a
// search for everybody, which the caller pages through; otherwise found is who matched.
func whoMatches(filter string, people int) (found []int, particular bool) {
	classes := classTerm.FindAllStringSubmatch(filter, -1)
	if len(classes) > 0 {
		anyPerson := false
		for _, c := range classes {
			anyPerson = anyPerson || personClass(c[1])
		}
		if !anyPerson {
			return nil, true
		}
	}
	// (uid=*) is everybody with a name, and (uid=dir-1*) a prefix: neither names one person.
	var terms [][]string
	for _, t := range identityTerm.FindAllStringSubmatch(filter, -1) {
		if !strings.Contains(t[2], "*") {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		return nil, false
	}
	seen := map[int]bool{}
	for _, t := range terms {
		if m := personNumber.FindStringSubmatch(t[2]); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n >= 1 && n <= people && !seen[n] {
				seen[n] = true
				found = append(found, n)
			}
		}
	}
	return found, true
}

// ldapResult is an LDAPResult of success (RFC 4511 §4.1.9).
func ldapResult(id int64, op ber.Tag, controls *ber.Packet) []byte {
	return ldapResultCode(id, op, ldap.LDAPResultSuccess, controls)
}

// ldapResultCode is an LDAPResult with the result code given.
func ldapResultCode(id int64, op ber.Tag, code uint16, controls *ber.Packet) []byte {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, op, nil, "result")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "code"))
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
