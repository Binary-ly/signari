package ldapd

import (
	"fmt"
	"strings"
)

// The directory schema, as much of one as a writable shim needs.
//
// # Why this file exists at all
//
// Reading is forgiving: a client asks for attributes and gets what we have.
// Writing is not. A client sends `sn: Smith` and expects to read `sn: Smith`
// back; it sends `objectClass: inetOrgPerson` and expects the MUST attributes of
// that class to be enforced; it sends two values for a single-valued attribute
// and expects to be told. None of that can be answered by a directory with no
// schema -- it can only be guessed at, and the guesses are silent.
//
// So the writable surface is an explicit table. Every attribute a client may
// write is named here with its rules, and anything not named is
// undefinedAttributeType(17) rather than quietly accepted and dropped.
//
// # What this is not
//
// It is not RFC 4512. There is no subschema subentry, no attribute type
// definitions published at the root DSE, no matching rules beyond
// case-insensitive equality, no DIT content or structure rules. Applications
// that need those need a directory; this is a shim that can now be written to.

// attrDef is one attribute this directory understands.
type attrDef struct {
	// Name is the canonical spelling. Comparison is case-insensitive, as LDAP
	// attribute descriptions are, but this is what gets returned.
	Name string
	// Single is true for an attribute this directory holds one value of.
	//
	// # This is usually NARROWER than the standard, and that is a decision
	//
	// Checked against RFC 4519 rather than assumed: `uid`, `cn`, `sn`,
	// `givenName` and `userPassword` are all MULTI-VALUED there, and `mail`
	// (RFC 4524 §2.16) is too. Only `displayName` (RFC 2798 §2.3) is genuinely
	// SINGLE-VALUE in its own definition.
	//
	// They are single here because the backing store holds one column each, and
	// the honest thing to do about that is to say so and refuse the second value
	// -- not to accept it and keep the first, which is how a client comes to
	// believe it stored something it did not. An application that needs a person
	// with three mail addresses needs a directory, and this is not one.
	Single bool
	// Writable is false for an attribute a client may read and not change.
	//
	// RFC 4511 §4.7 calls these NO-USER-MODIFICATION: "Clients MUST NOT supply
	// NO-USER-MODIFICATION attributes ... since the server maintains these
	// automatically." memberOf is the important one here -- it is DERIVED from
	// group membership, and a client that could write it would be writing a
	// cache of a fact stored somewhere else.
	Writable bool
	// RequiredForAdd is a MUST attribute of the object classes this directory
	// publishes.
	//
	// RFC 4519 §3.9 defines `person` as:
	//
	//	( 2.5.6.6 NAME 'person' SUP top STRUCTURAL
	//	  MUST ( sn $ cn )
	//	  MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )
	//
	// Every entry here claims that class, so both are required. `uid` is
	// required for a different reason -- it is the naming attribute, so an entry
	// without one has no DN.
	RequiredForAdd bool
	// Secret is never returned by a search, whatever was asked for.
	Secret bool
}

// schema is the complete writable surface.
//
// Ordered for reading; lookup is by name, case-insensitively.
var schema = []attrDef{
	// The naming attribute. Writable is FALSE: RFC 4511 §4.6 says the Modify
	// operation "cannot be used to remove from an entry any of its distinguished
	// values", and changing it is what Modify DN is for (§4.9). A client that
	// tries gets notAllowedOnRDN(67), which names the operation it should have
	// used.
	{Name: "uid", Single: true, Writable: false, RequiredForAdd: true},

	// RFC 4519 §3.9: `cn` and `sn` are the MUST attributes of `person`, and every
	// entry this directory returns claims that class. Neither was stored before
	// writes existed, so the read side was publishing entries that violated a
	// class it declared -- see entryFor for how existing rows are handled.
	{Name: "cn", Single: true, Writable: true, RequiredForAdd: true},
	{Name: "sn", Single: true, Writable: true, RequiredForAdd: true},

	{Name: "givenName", Single: true, Writable: true},   // RFC 4519 §2.12
	{Name: "displayName", Single: true, Writable: true}, // RFC 2798 §2.3
	{Name: "mail", Single: true, Writable: true},        // RFC 4524 §2.16

	// Write-only, in both directions. A search never returns it at any value --
	// not a hash, not a placeholder -- because either teaches an application to
	// compare passwords itself, which is how a credential ends up compared with
	// == in somebody else's code.
	{Name: "userPassword", Single: true, Writable: true, Secret: true},

	// Derived, and not a standard attribute at all: `memberOf` comes from Active
	// Directory and is provided as an overlay by OpenLDAP. It is published here
	// because applications that bind to a directory almost always gate on it,
	// and it is unwritable because it is a VIEW of group membership -- the
	// writable side of that relationship is a group's `member`, and there is no
	// group subtree here to write.
	{Name: "memberOf", Writable: false},

	// Structural, and fixed. A client may send it on Add and it must name the
	// classes this directory implements; it may not be changed afterwards, which
	// RFC 4511 gives its own result code for (objectClassModsProhibited, 69).
	{Name: "objectClass", Writable: false, RequiredForAdd: false},
}

// objectClasses is what every entry here is, and the only set an Add may claim.
//
// `top`, `person` and `organizationalPerson` are RFC 4519 §3; `inetOrgPerson` is
// RFC 2798 and is NOT in 4519, which is worth writing down because the MUST
// attributes enforced above come from 4519's `person` and it is easy to cite the
// wrong document for a class that only appears in the other one.
//
// Published in this order because clients display the last one and expect the
// most specific.
var objectClasses = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}

// lookupAttr finds an attribute definition, case-insensitively.
func lookupAttr(name string) (attrDef, bool) {
	for _, a := range schema {
		if equalFold(a.Name, name) {
			return a, true
		}
	}
	return attrDef{}, false
}

// canonicalAttr returns the schema's spelling of an attribute name.
func canonicalAttr(name string) string {
	if a, ok := lookupAttr(name); ok {
		return a.Name
	}
	return name
}

// NewEntry is a user an Add request is asking for.
//
// Deliberately the same shape as Identity plus the two things Identity does not
// carry: a password, and the surname a person entry MUST have.
type NewEntry struct {
	Username    string
	Email       string
	DisplayName string
	CommonName  string
	Surname     string
	GivenName   string
	// Password is empty when the client supplied none. That is legitimate: an
	// account that signs in through a federated provider has no local password,
	// and refusing to create one would make this directory unable to represent
	// half the accounts it can already read.
	Password string
}

// ChangeOp is RFC 4511 §4.6's modification type.
type ChangeOp int

const (
	ChangeAdd     ChangeOp = 0
	ChangeDelete  ChangeOp = 1
	ChangeReplace ChangeOp = 2
)

// Change is one entry in a ModifyRequest's `changes`.
type Change struct {
	Op   ChangeOp
	Attr string
	// Values may be empty, which is meaningful for both delete and replace --
	// see §4.6: "delete: ... If no values are listed, or if all current values
	// of the attribute are listed, the entire attribute is removed" and
	// "replace: ... A replace with no value will delete the entire attribute".
	Values []string
}

// Update is the resolved effect of a whole ModifyRequest.
//
// RFC 4511 §4.6: "The entire list of modifications MUST be performed in the
// order they are listed as a single atomic operation." So the changes are
// folded into a final state HERE, against the entry as it stands, and the store
// applies that state in one transaction. Applying them one at a time against the
// database would make a failure halfway through a partial write, which is the
// one outcome §4.6 promises cannot happen.
type Update struct {
	// Each field is nil when the request does not touch it, and non-nil holding
	// the new value when it does -- including the empty string, which is how an
	// attribute gets removed.
	Email       *string
	DisplayName *string
	CommonName  *string
	Surname     *string
	GivenName   *string
	Password    *string
}

// Empty reports whether this update would change nothing.
func (u *Update) Empty() bool {
	return u.Email == nil && u.DisplayName == nil && u.CommonName == nil &&
		u.Surname == nil && u.GivenName == nil && u.Password == nil
}

// modifyError carries an LDAP result code alongside its explanation.
type modifyError struct {
	code int64
	msg  string
}

func (e *modifyError) Error() string { return e.msg }

func schemaErr(code int64, format string, args ...any) *modifyError {
	return &modifyError{code: code, msg: fmt.Sprintf(format, args...)}
}

// ApplyChanges folds a ModifyRequest onto the entry as it currently stands.
//
// The current entry is needed because §4.6's `add` and `delete` operate on the
// existing value set, not on nothing: deleting a value that is not present is
// noSuchAttribute(16), and adding one that is already there is
// attributeOrValueExists(20). A server that skipped those would report success
// for a change it did not make.
func ApplyChanges(current *entry, changes []Change) (*Update, error) {
	if len(changes) == 0 {
		// A Modify with no changes. Not an error in the specification, and
		// refused here because it is always a client bug: nothing was asked for,
		// and answering success teaches the client that its request worked.
		return nil, schemaErr(resultProtocolError,
			"the modify request lists no changes")
	}

	// A working copy of the attribute values, so `add` and `delete` see the
	// effect of earlier changes in the same request -- which §4.6's "in the
	// order they are listed" requires.
	working := map[string][]string{}
	for k, v := range current.Attrs {
		working[strings.ToLower(k)] = append([]string(nil), v...)
	}

	touched := map[string]bool{}
	for i, ch := range changes {
		def, known := lookupAttr(ch.Attr)
		if !known {
			return nil, schemaErr(resultUndefinedAttributeType,
				"change %d names %q, which this directory does not define", i, ch.Attr)
		}
		if equalFold(def.Name, "objectClass") {
			// §4.6 has its own code for this, and it is more useful than a generic
			// refusal: a client trying to turn a person into something else needs
			// to know that the structural class is fixed, not that it lacked
			// permission.
			return nil, schemaErr(resultObjectClassModsProhibited,
				"the structural object class of an entry cannot be changed")
		}
		if !def.Writable {
			if equalFold(def.Name, "uid") {
				return nil, schemaErr(resultNotAllowedOnRDN,
					"%s forms this entry's RDN and cannot be changed by a modify; "+
						"use modify DN (RFC 4511 section 4.9)", def.Name)
			}
			return nil, schemaErr(resultConstraintViolation,
				"%s is maintained by this server and cannot be written; it is derived "+
					"from group membership", def.Name)
		}

		key := strings.ToLower(def.Name)
		have := working[key]

		switch ch.Op {
		case ChangeAdd:
			if len(ch.Values) == 0 {
				return nil, schemaErr(resultProtocolError,
					"change %d adds no values to %s", i, def.Name)
			}
			for _, v := range ch.Values {
				if containsFold(have, v) {
					return nil, schemaErr(resultAttributeOrValueExists,
						"%s already has the value %q", def.Name, v)
				}
				have = append(have, v)
			}
			if def.Single && len(have) > 1 {
				return nil, schemaErr(resultConstraintViolation,
					"%s is single-valued and this change would give it %d values",
					def.Name, len(have))
			}

		case ChangeDelete:
			if len(ch.Values) == 0 {
				// §4.6: "If no values are listed ... the entire attribute is
				// removed."
				have = nil
				break
			}
			for _, v := range ch.Values {
				idx := indexFold(have, v)
				if idx < 0 {
					return nil, schemaErr(resultNoSuchAttribute,
						"%s does not have the value %q", def.Name, v)
				}
				have = append(have[:idx], have[idx+1:]...)
			}

		case ChangeReplace:
			if def.Single && len(ch.Values) > 1 {
				return nil, schemaErr(resultConstraintViolation,
					"%s is single-valued and the replacement lists %d values",
					def.Name, len(ch.Values))
			}
			// §4.6: "A replace with no value will delete the entire attribute if
			// it exists, and it is ignored if the attribute does not exist." Both
			// land on the same empty set here.
			have = append([]string(nil), ch.Values...)

		default:
			return nil, schemaErr(resultProtocolError,
				"change %d uses operation %d, which is not add, delete or replace",
				i, ch.Op)
		}

		working[key] = have
		touched[key] = true
	}

	// §4.6: "the resulting entry after the entire list of modifications is
	// performed MUST conform to the requirements of the directory model and
	// controlling schema". So the MUST attributes are checked at the END, on the
	// result -- a request that deletes `sn` and adds it back in the next change
	// is legal, and one that only deletes it is not.
	for _, def := range schema {
		if !def.RequiredForAdd || def.Secret {
			continue
		}
		if len(working[strings.ToLower(def.Name)]) == 0 {
			return nil, schemaErr(resultObjectClassViolation,
				"the entry would be left with no %s, which `person` makes a MUST "+
					"attribute (RFC 4519 section 3.9)", def.Name)
		}
	}

	u := &Update{}
	first := func(key string) string {
		if v := working[key]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	for key := range touched {
		v := first(key)
		switch key {
		case "mail":
			u.Email = &v
		case "displayname":
			u.DisplayName = &v
		case "cn":
			u.CommonName = &v
		case "sn":
			u.Surname = &v
		case "givenname":
			u.GivenName = &v
		case "userpassword":
			// An empty password is a REMOVAL of the credential, not a password of
			// zero length. The store distinguishes them; nothing here should
			// silently turn "delete userPassword" into "set the password to the
			// empty string", which would be an account anybody can bind to.
			u.Password = &v
		}
	}
	return u, nil
}

// ValidateNewEntry applies the Add-time schema rules.
//
// RFC 4511 §4.7: "Servers MUST ensure that entries conform to user and system
// schema rules or other data model constraints."
func ValidateNewEntry(e *NewEntry, suppliedClasses []string) error {
	if e.Username == "" {
		return schemaErr(resultNamingViolation,
			"the entry has no uid, which is this directory's naming attribute")
	}
	// §4.7: "Clients MAY or MAY NOT include the RDN attribute(s) in this list."
	// So an Add whose attributes carry a `uid` different from the one in the DN
	// is contradictory, and the caller resolves that before getting here.
	if e.CommonName == "" {
		return schemaErr(resultObjectClassViolation,
			"cn is required: `person` makes it a MUST attribute (RFC 4519 section 3.9)")
	}
	if e.Surname == "" {
		return schemaErr(resultObjectClassViolation,
			"sn is required: `person` makes it a MUST attribute (RFC 4519 section 3.9)")
	}
	if len(suppliedClasses) > 0 && !classesAcceptable(suppliedClasses) {
		return schemaErr(resultObjectClassViolation,
			"this directory stores `person` entries; the object classes it "+
				"implements are %s", strings.Join(objectClasses, ", "))
	}
	return nil
}

// classesAcceptable checks that every class a client asked for is one we
// actually implement.
//
// A subset is fine -- a client sending only `inetOrgPerson` gets an entry that
// is also `top`, `person` and `organizationalPerson`, because it must be. A
// class we do not implement is refused rather than ignored: an entry stored as
// something other than what the client asked for is one they will read back and
// not recognise.
func classesAcceptable(supplied []string) bool {
	for _, s := range supplied {
		found := false
		for _, ours := range objectClasses {
			if equalFold(s, ours) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsFold(list []string, v string) bool { return indexFold(list, v) >= 0 }

func indexFold(list []string, v string) int {
	for i, s := range list {
		if equalFold(s, v) {
			return i
		}
	}
	return -1
}
