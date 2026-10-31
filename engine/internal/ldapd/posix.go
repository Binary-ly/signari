package ldapd

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// POSIX accounts (7.03): what a host reading its users from a directory needs. RFC
// 2307 is not in specs/, so the attributes and classes in subschema.go were checked
// against OpenLDAP's nis.schema, lines 38-67, 97-100 and 165-183, with one difference:
// posixGroup is auxiliary here where that file has it structural, because a group's
// structural class is groupOfNames and an entry has one.
//
// A person's gidNumber is their own number, the group private to them. The directory
// publishes no such group, so a host shows the number where it would show a name.
// Everything a person is in beyond that comes through memberUid.

const (
	posixAccountClass = "posixAccount"
	posixGroupClass   = "posixGroup"
)

// personClasses is what a person here is. objectClasses is the set an Add may claim,
// and posixAccount is not in it: the numbers are allocated, not written.
func (s *Server) personClasses() []string {
	if !s.cfg.POSIX {
		return objectClasses
	}
	return append(slices.Clone(objectClasses), posixAccountClass)
}

func (s *Server) groupClasses() []string {
	if !s.cfg.POSIX {
		return groupClasses
	}
	return append(slices.Clone(groupClasses), posixGroupClass)
}

// addPosixAccount completes a person's attributes. Somebody with no number comes from
// a core that predates them, and claiming the class without one would publish an
// account a host refuses or, worse, reads as uid 0.
func (s *Server) addPosixAccount(attrs map[string][]string, id *Identity) {
	if !s.cfg.POSIX || id.UIDNumber <= 0 {
		attrs["objectClass"] = objectClasses
		return
	}
	number := strconv.Itoa(id.UIDNumber)
	attrs["uid"] = []string{id.Username}
	attrs["uidNumber"] = []string{number}
	attrs["gidNumber"] = []string{number}
	attrs["homeDirectory"] = []string{s.homeDirectory(id.Username)}
	attrs["loginShell"] = []string{s.cfg.LoginShell}
	// gecos is IA5 (nis.schema:53), so a name in any other script stays in cn.
	if gecos := firstNonEmpty(id.DisplayName, id.Username); isASCII(gecos) {
		attrs["gecos"] = []string{gecos}
	}
}

func isASCII(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r > unicode.MaxASCII }) < 0
}

// homeDirectory fills the template. A name is whatever was registered, so it is held
// to one path segment: a person named `..` must not be given the parent of /home.
func (s *Server) homeDirectory(username string) string {
	segment := strings.NewReplacer("/", "_", "\x00", "_").Replace(username)
	if strings.Trim(segment, ".") == "" {
		segment = "_"
	}
	return strings.ReplaceAll(s.cfg.HomeTemplate, "{username}", segment)
}

// isIntegerAttr is an attribute that orders as a number. As text, 9 sorts after 10,
// so a range over uidNumber finds the wrong people.
func isIntegerAttr(name string) bool {
	return equalFold(name, "uidNumber") || equalFold(name, "gidNumber")
}

// numberCondition says who an equality on a number could be. A value that is not one
// matches nobody.
func numberCondition(op, value string) *Condition {
	if _, err := strconv.Atoi(value); err != nil {
		return &Condition{Op: CondNone}
	}
	return &Condition{Op: op, Value: value}
}
