package ldapd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// The write half: Add, Modify, Delete and Modify DN, RFC 4511 §4.6 to §4.9.
//
// # Off unless a Writer is supplied
//
// A nil Writer refuses every one of them with unwillingToPerform(53), which is
// exactly what this shim did before writes existed. That is not a transitional
// state: the LDAP outpost has no write path back to the engine, most
// deployments want a bind shim and nothing more, and a directory that can be
// written to is a much larger attack surface than one that cannot.
//
// # And off unless a write group is configured
//
// Even with a Writer, a bound identity may write only if it is in
// Config.WriteGroup. Empty means nobody, so turning writes on is two decisions
// rather than one -- and the second one names the people, in the group machinery
// an operator already uses, visible in the `memberOf` of anybody who has it.

// Writer is the optional write half of a directory.
//
// Every method takes the bound identity's username as `actor`, so the
// implementation can audit who did it. The protocol layer has already checked
// that the actor is permitted; the implementation is free to check again.
type Writer interface {
	// Create adds a user. It must return ErrEntryExists when the name is taken.
	Create(ctx context.Context, actor string, e *NewEntry) error
	// Update applies the resolved effect of a Modify request, atomically.
	Update(ctx context.Context, actor, username string, u *Update) error
	// Remove deletes a user. It must return ErrNoSuchEntry when there is none.
	Remove(ctx context.Context, actor, username string) error
	// Rename changes a user's naming attribute value.
	Rename(ctx context.Context, actor, from, to string) error
}

// Errors a Writer returns, mapped to result codes by the handlers.
var (
	ErrEntryExists = errors.New("entry already exists")
	ErrNoSuchEntry = errors.New("no such entry")
	// ErrConstraint is for a rule the store enforces and the schema here cannot
	// -- a password the policy refuses, an email already used by somebody else.
	ErrConstraint = errors.New("constraint violation")
)

// writesConfigured reports whether this deployment offers writes at all.
//
// Two things, deliberately: a Writer must be attached AND a group must name who
// may use it. The first is a deployment decision, the second names people.
//
// Fail-closed on both. An unconfigured group permits nobody, which is the
// opposite of the reading an empty list gets in one place elsewhere in this
// codebase -- and the right one here, because this list decides who may rewrite
// the directory and then bind as anybody in it.
//
// ONE method rather than the same condition written twice. mayWrite and
// refuseWrite both need it, and they need it to agree: if they drifted, a
// connection could be permitted to write by one and told the directory is
// read-only by the other.
func (s *Server) writesConfigured() bool {
	return s.writer != nil && s.cfg.WriteGroup != ""
}

// mayWrite reports whether the bound identity is permitted to change anything.
func (s *Server) mayWrite(sess *session) bool {
	if !s.writesConfigured() {
		return false
	}
	if !sess.bound || sess.identity == nil {
		return false
	}
	for _, g := range sess.identity.Groups {
		if g == s.cfg.WriteGroup {
			return true
		}
	}
	return false
}

// refuseWrite answers a write this connection may not perform.
//
// The two reasons are DISTINGUISHED, and that is a deliberate disclosure. "This
// directory is read-only" and "you are not permitted to write here" send an
// administrator to completely different places, and neither tells an attacker
// anything they could not learn by trying with any account: whether the server
// has writes on at all is a property of the deployment, not of a credential.
func (s *Server) refuseWrite(c net.Conn, messageID int64, respTag ber.Tag, sess *session) bool {
	if !s.writesConfigured() {
		s.log.Info("ldap write refused: this directory is read-only",
			"remote", c.RemoteAddr().String(), "bound_dn", sess.dn)
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultUnwillingToPerform, "", "this directory is read-only")))
	}
	s.log.Warn("ldap write refused: the bound identity is not in the write group",
		"remote", c.RemoteAddr().String(), "bound_dn", sess.dn,
		"write_group", s.cfg.WriteGroup)
	// insufficientAccessRights(50), not unwillingToPerform. §4.7's own vocabulary
	// distinguishes "the server will not" from "you may not", and an
	// administrator whose service account silently cannot write needs the second.
	return s.write(c, newMessage(messageID, newResult(respTag,
		resultInsufficientAccess, "",
		"the bound identity is not permitted to write to this directory")))
}

// --- Add, §4.7 --------------------------------------------------------------

// addRequest is a decoded AddRequest.
type addRequest struct {
	DN    string
	Attrs map[string][]string
	// Classes is objectClass as supplied, kept apart because it is validated
	// rather than stored.
	Classes []string
}

func decodeAdd(op *ber.Packet) (*addRequest, error) {
	if len(op.Children) < 2 {
		return nil, fmt.Errorf("add request has %d fields, expected 2", len(op.Children))
	}
	dn, ok := op.Children[0].Value.(string)
	if !ok {
		dn = string(op.Children[0].Data.Bytes())
	}
	req := &addRequest{DN: dn, Attrs: map[string][]string{}}

	// AttributeList ::= SEQUENCE OF attribute Attribute
	// Attribute ::= PartialAttribute (type, vals SET OF value)
	for _, a := range op.Children[1].Children {
		if len(a.Children) < 2 {
			return nil, fmt.Errorf("an attribute in the add request has %d fields",
				len(a.Children))
		}
		name := string(a.Children[0].Data.Bytes())
		var vals []string
		for _, v := range a.Children[1].Children {
			vals = append(vals, string(v.Data.Bytes()))
		}
		if equalFold(name, "objectClass") {
			req.Classes = append(req.Classes, vals...)
			continue
		}
		key := strings.ToLower(name)
		req.Attrs[key] = append(req.Attrs[key], vals...)
	}
	return req, nil
}

func (s *Server) handleAdd(ctx context.Context, c net.Conn, sess *session,
	messageID int64, op *ber.Packet) bool {

	const respTag = appAddRequest + 1
	if !s.mayWrite(sess) {
		return s.refuseWrite(c, messageID, respTag, sess)
	}
	req, err := decodeAdd(op)
	if err != nil {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultProtocolError, "", "malformed add request")))
	}

	username, derr := s.usernameFromDN(req.DN)
	if derr != nil {
		return s.writeDNError(c, messageID, respTag, req.DN, derr)
	}

	e := &NewEntry{Username: username}
	single := func(key string) (string, bool, *modifyError) {
		v := req.Attrs[key]
		switch {
		case len(v) == 0:
			return "", false, nil
		case len(v) > 1:
			return "", false, schemaErr(resultConstraintViolation,
				"%s is single-valued and %d values were supplied",
				canonicalAttr(key), len(v))
		}
		return v[0], true, nil
	}
	for key := range req.Attrs {
		def, known := lookupAttr(key)
		if !known {
			return s.write(c, newMessage(messageID, newResult(respTag,
				resultUndefinedAttributeType, "",
				"this directory does not define the attribute "+key)))
		}
		// §4.7: "Clients MUST NOT supply NO-USER-MODIFICATION attributes". uid is
		// permitted here despite being unwritable, because it is the RDN and §4.7
		// explicitly allows a client to repeat it -- see the check below.
		if !def.Writable && !equalFold(def.Name, "uid") {
			return s.write(c, newMessage(messageID, newResult(respTag,
				resultConstraintViolation, "",
				canonicalAttr(key)+" is maintained by this server and cannot be supplied")))
		}
	}
	// §4.7: "the list of attributes that, along with those from the RDN, make up
	// the content of the entry... Clients MAY or MAY NOT include the RDN
	// attribute(s) in this list." Included is fine; CONTRADICTING the DN is not,
	// and silently preferring one of the two would store an entry under a name
	// the client did not ask for.
	if uid, present, merr := single("uid"); merr != nil {
		return s.writeSchemaError(c, messageID, respTag, merr)
	} else if present && !equalFold(uid, username) {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNamingViolation, "",
			"the uid attribute says "+uid+" and the entry DN says "+username)))
	}

	for key, into := range map[string]*string{
		"cn": &e.CommonName, "sn": &e.Surname, "givenname": &e.GivenName,
		"displayname": &e.DisplayName, "mail": &e.Email, "userpassword": &e.Password,
	} {
		v, _, merr := single(key)
		if merr != nil {
			return s.writeSchemaError(c, messageID, respTag, merr)
		}
		*into = v
	}

	if err := ValidateNewEntry(e, req.Classes); err != nil {
		return s.writeSchemaError(c, messageID, respTag, err)
	}

	switch err := s.writer.Create(ctx, sess.identity.Username, e); {
	case err == nil:
		s.log.Info("ldap add", "uid", username, "by", sess.dn,
			"remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(respTag, resultSuccess, "", "")))
	case errors.Is(err, ErrEntryExists):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultEntryAlreadyExists, "", "an entry with that name already exists")))
	case errors.Is(err, ErrConstraint):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultConstraintViolation, "", err.Error())))
	default:
		s.log.Error("ldap add", "err", err, "uid", username)
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultOther, "", "the entry could not be added")))
	}
}

// --- Modify, §4.6 -----------------------------------------------------------

func decodeModify(op *ber.Packet) (string, []Change, error) {
	if len(op.Children) < 2 {
		return "", nil, fmt.Errorf("modify request has %d fields, expected 2",
			len(op.Children))
	}
	dn, ok := op.Children[0].Value.(string)
	if !ok {
		dn = string(op.Children[0].Data.Bytes())
	}

	var out []Change
	for _, ch := range op.Children[1].Children {
		if len(ch.Children) < 2 {
			return "", nil, fmt.Errorf("a change has %d fields, expected 2",
				len(ch.Children))
		}
		opnum, ok := ch.Children[0].Value.(int64)
		if !ok {
			return "", nil, fmt.Errorf("a change operation is not an integer")
		}
		mod := ch.Children[1]
		if len(mod.Children) < 1 {
			return "", nil, fmt.Errorf("a modification carries no attribute type")
		}
		c := Change{Op: ChangeOp(opnum), Attr: string(mod.Children[0].Data.Bytes())}
		if len(mod.Children) > 1 {
			for _, v := range mod.Children[1].Children {
				c.Values = append(c.Values, string(v.Data.Bytes()))
			}
		}
		out = append(out, c)
	}
	return dn, out, nil
}

func (s *Server) handleModify(ctx context.Context, c net.Conn, sess *session,
	messageID int64, op *ber.Packet) bool {

	const respTag = appModifyRequest + 1
	if !s.mayWrite(sess) {
		return s.refuseWrite(c, messageID, respTag, sess)
	}
	dn, changes, err := decodeModify(op)
	if err != nil {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultProtocolError, "", "malformed modify request")))
	}
	username, derr := s.usernameFromDN(dn)
	if derr != nil {
		return s.writeDNError(c, messageID, respTag, dn, derr)
	}

	// The entry as it stands. §4.6's add and delete operate on the existing
	// value set, so the modification cannot be resolved without it -- and a
	// server that resolved them against nothing would report success for
	// deleting a value that was never there.
	id, err := s.auth.Lookup(ctx, username)
	if err != nil || id == nil {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNoSuchObject, s.cfg.BaseDN, "no such object")))
	}

	update, merr := ApplyChanges(s.entryFor(id), changes)
	if merr != nil {
		return s.writeSchemaError(c, messageID, respTag, merr)
	}
	if update.Empty() {
		// Every change resolved to the value already there. Success, because the
		// entry does conform to what was asked for -- §4.6 promises atomicity and
		// a final state, not that something changed.
		return s.write(c, newMessage(messageID, newResult(respTag, resultSuccess, "", "")))
	}

	switch err := s.writer.Update(ctx, sess.identity.Username, username, update); {
	case err == nil:
		s.log.Info("ldap modify", "uid", username, "by", sess.dn,
			"remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(respTag, resultSuccess, "", "")))
	case errors.Is(err, ErrNoSuchEntry):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNoSuchObject, s.cfg.BaseDN, "no such object")))
	case errors.Is(err, ErrConstraint):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultConstraintViolation, "", err.Error())))
	default:
		s.log.Error("ldap modify", "err", err, "uid", username)
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultOther, "", "the entry could not be modified")))
	}
}

// --- Delete, §4.8 -----------------------------------------------------------

func (s *Server) handleDelete(ctx context.Context, c net.Conn, sess *session,
	messageID int64, op *ber.Packet) bool {

	const respTag = appDelRequest + 1
	if !s.mayWrite(sess) {
		return s.refuseWrite(c, messageID, respTag, sess)
	}
	// DelRequest ::= [APPLICATION 10] LDAPDN -- the DN is the whole request, not
	// a sequence, so it is read from the packet's own data.
	dn := string(op.Data.Bytes())

	// §4.8: "Only leaf entries (those with no subordinate entries) can be
	// deleted." The base itself is not a leaf, and neither is anything that is
	// not a user entry. Both land in usernameFromDN's refusal, and the base gets
	// its own code because notAllowedOnNonLeaf is what a client needs to see.
	if equalFold(strings.TrimSpace(dn), s.cfg.BaseDN) {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNotAllowedOnNonLeaf, s.cfg.BaseDN,
			"the naming context itself cannot be deleted")))
	}
	username, derr := s.usernameFromDN(dn)
	if derr != nil {
		return s.writeDNError(c, messageID, respTag, dn, derr)
	}

	switch err := s.writer.Remove(ctx, sess.identity.Username, username); {
	case err == nil:
		s.log.Warn("ldap delete", "uid", username, "by", sess.dn,
			"remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(respTag, resultSuccess, "", "")))
	case errors.Is(err, ErrNoSuchEntry):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNoSuchObject, s.cfg.BaseDN, "no such object")))
	case errors.Is(err, ErrConstraint):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultConstraintViolation, "", err.Error())))
	default:
		s.log.Error("ldap delete", "err", err, "uid", username)
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultOther, "", "the entry could not be deleted")))
	}
}

// --- Modify DN, §4.9 --------------------------------------------------------

type modifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
	HasSuperior  bool
}

func decodeModifyDN(op *ber.Packet) (*modifyDNRequest, error) {
	if len(op.Children) < 3 {
		return nil, fmt.Errorf("modify DN request has %d fields, expected at least 3",
			len(op.Children))
	}
	req := &modifyDNRequest{
		DN:     string(op.Children[0].Data.Bytes()),
		NewRDN: string(op.Children[1].Data.Bytes()),
	}
	// deleteoldrdn is a BOOLEAN. Read from Value when the parser gave one and
	// from the raw byte otherwise: a context-tagged boolean does not always
	// decode to bool, and defaulting the wrong way here silently changes whether
	// the old name survives.
	switch v := op.Children[2].Value.(type) {
	case bool:
		req.DeleteOldRDN = v
	default:
		b := op.Children[2].Data.Bytes()
		req.DeleteOldRDN = len(b) > 0 && b[0] != 0
	}
	if len(op.Children) > 3 {
		req.NewSuperior = string(op.Children[3].Data.Bytes())
		req.HasSuperior = true
	}
	return req, nil
}

func (s *Server) handleModifyDN(ctx context.Context, c net.Conn, sess *session,
	messageID int64, op *ber.Packet) bool {

	const respTag = appModifyDNRequest + 1
	if !s.mayWrite(sess) {
		return s.refuseWrite(c, messageID, respTag, sess)
	}
	req, err := decodeModifyDN(op)
	if err != nil {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultProtocolError, "", "malformed modify DN request")))
	}
	from, derr := s.usernameFromDN(req.DN)
	if derr != nil {
		return s.writeDNError(c, messageID, respTag, req.DN, derr)
	}

	// §4.9's newSuperior moves an entry to a different parent. This directory is
	// flat -- every entry sits directly under the naming context -- so the only
	// superior that exists is the base itself. Anything else is noSuchObject with
	// matchedDN naming what does exist, which is what §4.9 specifies for exactly
	// this case.
	if req.HasSuperior && !equalFold(strings.TrimSpace(req.NewSuperior), s.cfg.BaseDN) {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNoSuchObject, s.cfg.BaseDN,
			"this directory has no subordinate structure; the only superior is "+
				s.cfg.BaseDN)))
	}

	// The new RDN, which must use the naming attribute and nothing else.
	attr, value, ok := strings.Cut(req.NewRDN, "=")
	if !ok {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultInvalidDNSyntax, "", "the new RDN is not attribute=value")))
	}
	if !equalFold(strings.TrimSpace(attr), s.cfg.UserAttr) {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNamingViolation, "",
			"entries here are named by "+s.cfg.UserAttr+", not by "+attr)))
	}
	to := strings.TrimSpace(value)
	if to == "" {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultInvalidDNSyntax, "", "the new RDN has an empty value")))
	}

	// §4.9: "If the deleteoldrdn field is FALSE, the attribute values forming
	// the old RDN will be retained as non-distinguished attribute values of the
	// entry."
	//
	// Cannot be honoured here and is refused rather than ignored. uid is
	// single-valued in this directory, so retaining the old value alongside the
	// new one is not a thing the store can represent -- and a server that
	// accepted FALSE and dropped the old value anyway would have done the one
	// thing the flag exists to prevent.
	if !req.DeleteOldRDN {
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultConstraintViolation, "",
			s.cfg.UserAttr+" is single-valued here, so the old value cannot be "+
				"retained as a non-distinguished value; send deleteoldrdn TRUE")))
	}

	if equalFold(from, to) {
		// A rename to the same name. Success and no write: the entry already has
		// the name that was asked for.
		return s.write(c, newMessage(messageID, newResult(respTag, resultSuccess, "", "")))
	}

	switch err := s.writer.Rename(ctx, sess.identity.Username, from, to); {
	case err == nil:
		s.log.Info("ldap modify dn", "from", from, "to", to, "by", sess.dn,
			"remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(respTag, resultSuccess, "", "")))
	case errors.Is(err, ErrEntryExists):
		// §4.9: "If there was already an entry with that name, the operation
		// would fail with the entryAlreadyExists result code."
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultEntryAlreadyExists, "", "an entry with that name already exists")))
	case errors.Is(err, ErrNoSuchEntry):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultNoSuchObject, s.cfg.BaseDN, "no such object")))
	case errors.Is(err, ErrConstraint):
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultConstraintViolation, "", err.Error())))
	default:
		s.log.Error("ldap modify dn", "err", err, "from", from, "to", to)
		return s.write(c, newMessage(messageID, newResult(respTag,
			resultOther, "", "the entry could not be renamed")))
	}
}

// --- shared error paths -----------------------------------------------------

// writeDNError answers a DN this directory cannot address.
//
// Unlike bind, where every failure returns invalidCredentials so nothing can be
// enumerated, a write is performed by an authenticated administrator who needs
// to know what is wrong with the name they sent. There is nothing to protect
// here: they can already read the tree.
func (s *Server) writeDNError(c net.Conn, messageID int64, respTag ber.Tag,
	dn string, cause error) bool {

	code := int64(resultInvalidDNSyntax)
	if strings.Contains(cause.Error(), "not under") {
		// A syntactically fine DN that is outside our naming context. §4.7 says
		// to answer noSuchObject with matchedDN naming the deepest ancestor that
		// does exist, which for a flat directory is the base or nothing.
		code = resultNoSuchObject
	}
	matched := ""
	if code == resultNoSuchObject {
		matched = s.cfg.BaseDN
	}
	s.log.Info("ldap write with an unusable DN", "dn", dn, "err", cause,
		"remote", c.RemoteAddr().String())
	return s.write(c, newMessage(messageID, newResult(respTag, code, matched,
		cause.Error())))
}

// writeSchemaError answers a schema violation with the code the schema chose.
func (s *Server) writeSchemaError(c net.Conn, messageID int64, respTag ber.Tag,
	err error) bool {

	var me *modifyError
	if errors.As(err, &me) {
		return s.write(c, newMessage(messageID, newResult(respTag, me.code, "", me.msg)))
	}
	return s.write(c, newMessage(messageID, newResult(respTag,
		resultConstraintViolation, "", err.Error())))
}
