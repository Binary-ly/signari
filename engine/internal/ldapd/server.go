package ldapd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Authenticator resolves and verifies a person.
//
// An interface so the protocol layer can be tested without a database, and so
// the credential path stays in one place -- the same Argon2 parameters, the same
// throttling, the same audit trail as every other way of signing in.
type Authenticator interface {
	// Authenticate verifies a username and password. It must return the same
	// error for "no such user" and "wrong password".
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
	// Lookup finds a user without verifying a credential, for search.
	Lookup(ctx context.Context, username string) (*Identity, error)
	// List returns users for a subtree search.
	List(ctx context.Context, limit int) ([]*Identity, error)
}

// Identity is what the directory exposes about a person.
//
// Deliberately thin. This is a bind shim, and every additional attribute is
// something readable by any application that can bind.
type Identity struct {
	Username    string
	Email       string
	DisplayName string
	Active      bool
	// Groups is published as memberOf. Applications that bind to a directory
	// almost always gate on it, and one that cannot read groups falls back to
	// giving everybody the same access.
	Groups []string

	// Surname and GivenName exist because RFC 4519 makes `sn` a MUST attribute
	// of `person`, and every entry this directory returns claims that class.
	//
	// They were not stored before writes existed, so the read side was
	// publishing entries that violated a class it declared -- a real defect
	// found by working out what an Add would have to accept. See entryFor for
	// what happens to rows that predate the column.
	Surname   string
	GivenName string
}

// Config is one LDAP listener.
type Config struct {
	// BaseDN is the suffix every DN sits under, e.g. dc=example,dc=com.
	BaseDN string
	// UserAttr is the naming attribute in a user DN: uid=alice,ou=users,...
	UserAttr string
	// AllowAnonymousSearch permits searching without binding. OFF by default:
	// an anonymous search endpoint is a user directory published to anyone who
	// can reach the port, which is how internal address books end up in breach
	// dumps.
	AllowAnonymousSearch bool
	// MaxResults caps a single search.
	MaxResults  int
	ReadTimeout time.Duration

	// WriteGroup names the group whose members may perform Add, Modify, Delete
	// and Modify DN.
	//
	// EMPTY MEANS NOBODY. That is the fail-closed reading, and it is the right
	// one here for the same reason the SSF stream `Allows` field takes it:
	// reading an unset list as "everybody" is how a half-made configuration
	// becomes a live grant, and this particular grant is the ability to rewrite
	// the directory and then bind as anybody in it.
	//
	// A group rather than a list of DNs, so the people who hold it are visible in
	// their own `memberOf` and are managed with `signari group member` like every
	// other privilege.
	WriteGroup string
}

func (c *Config) withDefaults() {
	if c.UserAttr == "" {
		c.UserAttr = "uid"
	}
	if c.MaxResults == 0 {
		c.MaxResults = 500
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 30 * time.Second
	}
}

// Server answers LDAP on a listener.
type Server struct {
	cfg  Config
	auth Authenticator
	// writer is nil for a read-only directory, which is the default and what
	// every deployment got before writes existed. See write.go.
	writer Writer
	log    *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func New(cfg Config, auth Authenticator, log *slog.Logger) *Server {
	cfg.withDefaults()
	return &Server{cfg: cfg, auth: auth, log: log, conns: map[net.Conn]struct{}{}}
}

// WithWriter returns a server that can be written to.
//
// A separate constructor rather than a field on Config, so that turning writes
// on is a call somebody made rather than a struct literal somebody copied. The
// write group still has to name people; a Writer with no group permits nobody.
func (s *Server) WithWriter(w Writer) *Server {
	s.writer = w
	return s
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

// session is the per-connection state.
//
// The bound identity lives HERE and nowhere else: it is established by a bind
// on this connection and is not derivable from anything the client sends later.
type session struct {
	bound    bool
	identity *Identity
	dn       string
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()

	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()

	sess := &session{}
	for {
		if err := c.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout)); err != nil {
			return
		}
		packet, err := ber.ReadPacket(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log.Debug("ldap read", "err", err, "remote", c.RemoteAddr().String())
			}
			return
		}
		// Bound AFTER read because the length is inside the packet: a client can
		// announce a huge message, and a decoder that allocates first is a
		// one-packet denial of service. ber.ReadPacket streams, so this catches
		// the oversized case without having pre-allocated for it.
		if len(packet.Bytes()) > maxMessageSize {
			s.log.Info("ldap message over the size limit", "bytes", len(packet.Bytes()),
				"remote", c.RemoteAddr().String())
			return
		}
		if len(packet.Children) < 2 {
			return
		}

		messageID, ok := packet.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := packet.Children[1]

		if !s.dispatch(ctx, c, sess, messageID, op) {
			return
		}
	}
}

// dispatch handles one operation. It returns false to close the connection.
func (s *Server) dispatch(ctx context.Context, c net.Conn, sess *session, messageID int64, op *ber.Packet) bool {
	switch op.Tag {
	case appBindRequest:
		return s.handleBind(ctx, c, sess, messageID, op)

	case appSearchRequest:
		return s.handleSearch(ctx, c, sess, messageID, op)

	case appUnbindRequest:
		// No response is defined for unbind; the client expects the connection
		// to close.
		return false

	case appAbandonRequest:
		// No response is defined. Nothing here is long-running enough to abandon.
		return true

	case appExtendedRequest:
		return s.handleExtended(c, sess, messageID, op)

	// The four write operations, RFC 4511 §4.6 to §4.9.
	//
	// Each handler refuses first -- no Writer, or a bound identity outside the
	// write group -- so a read-only deployment behaves exactly as it did before
	// writes existed, down to the result code. See write.go.
	case appAddRequest:
		return s.handleAdd(ctx, c, sess, messageID, op)
	case appModifyRequest:
		return s.handleModify(ctx, c, sess, messageID, op)
	case appDelRequest:
		return s.handleDelete(ctx, c, sess, messageID, op)
	case appModifyDNRequest:
		return s.handleModifyDN(ctx, c, sess, messageID, op)

	case appCompareRequest:
		// Compare can be used as an oracle: ask whether userPassword equals X and
		// learn a credential one guess at a time, with no failed-login counter
		// anywhere. Refused.
		return s.write(c, newMessage(messageID, newResult(15,
			resultUnwillingToPerform, "", "compare is not supported")))

	default:
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultProtocolError, "", "unsupported operation")))
	}
}

// Extended operation OIDs.
const (
	oidWhoAmI   = "1.3.6.1.4.1.4203.1.11.3"
	oidStartTLS = "1.3.6.1.4.1.1466.20037"
)

// handleExtended answers the two extended operations that matter, and refuses
// the rest.
//
// Dispatching on the OID rather than refusing the whole class, because "Who am
// I?" is how every operator checks that a bind worked -- `ldapwhoami` sends
// nothing else -- and a directory that cannot answer it looks broken during the
// first five minutes of every integration.
//
// StartTLS stays refused, and that is the important half. A server that answers
// success to StartTLS without actually upgrading the connection has told the
// client the channel is protected, and the client then sends a password over
// it in the clear. Refusing is the honest answer: run a TLS listener instead.
func (s *Server) handleExtended(c net.Conn, sess *session, messageID int64, op *ber.Packet) bool {
	var oid string
	if len(op.Children) > 0 {
		oid = string(op.Children[0].Data.Bytes())
	}

	switch oid {
	case oidWhoAmI:
		resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedResponse, nil, "ExtendedResponse")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
			int64(resultSuccess), "resultCode"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

		// The authzId. Empty for an unbound connection, which is what RFC 4532
		// specifies for anonymous -- and is the honest answer rather than
		// inventing an identity for somebody who never proved one.
		authz := ""
		if sess.bound {
			authz = "dn:" + sess.dn
		}
		// Context tag 11 is responseValue in an ExtendedResponse.
		resp.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, authz, "responseValue"))
		return s.write(c, newMessage(messageID, resp))

	case oidStartTLS:
		s.log.Info("ldap StartTLS refused", "remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(appExtendedResponse,
			resultProtocolError, "", "StartTLS is not supported; connect to the LDAPS "+
				"listener instead. Answering success here without upgrading the "+
				"connection would have you send credentials in the clear.")))

	default:
		return s.write(c, newMessage(messageID, newResult(appExtendedResponse,
			resultProtocolError, "", "unsupported extended operation")))
	}
}

// handleBind authenticates a connection.
func (s *Server) handleBind(ctx context.Context, c net.Conn, sess *session, messageID int64, op *ber.Packet) bool {
	req, err := decodeBind(op)
	if err != nil {
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultProtocolError, "", "malformed bind request")))
	}

	// Every bind RESETS the connection's identity, including a failed one. A
	// connection that stays bound as its previous identity after a failed
	// re-bind lets a client authenticate once and then keep the session while
	// pretending to be somebody else.
	sess.bound, sess.identity, sess.dn = false, nil, ""

	if req.Version != 3 {
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultProtocolError, "", "only LDAPv3 is supported")))
	}
	if !req.Simple {
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultAuthMethodNotSupported, "", "only simple authentication is supported")))
	}

	// Anonymous bind: no DN and no password. Permitted, and it authenticates
	// nobody -- the session stays unbound, so anything requiring an identity
	// still refuses.
	if req.DN == "" && req.Password == "" {
		s.log.Debug("ldap anonymous bind", "remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultSuccess, "", "")))
	}

	// # The unauthenticated bind, and why it is refused
	//
	// A DN with an EMPTY password. RFC 4513 §5.1.2 calls this an unauthenticated
	// bind, and it is what CVE-2017-14623 was about: applications ask "did the
	// bind return an error" and read a nil answer as "this person proved who
	// they are". They did not. They supplied a name.
	//
	// There is no option to permit it.
	//
	// The result code is the one §5.1.2 names: "Servers SHOULD by default fail
	// Unauthenticated Bind requests with a resultCode of unwillingToPerform."
	//
	// This returned invalidCredentials(49), which is a worse answer for the
	// person who actually hits it. An administrator whose client sends an empty
	// password reads "invalid credentials" and goes looking for a password
	// problem; the real fault is that the client is requesting a mode this
	// server refuses. unwillingToPerform(53) says so.
	//
	// It costs nothing to be specific here. The code is returned for every empty
	// password whether or not the DN exists, so it distinguishes nothing an
	// attacker could use -- and "this server refuses unauthenticated binds" is
	// something worth advertising anyway.
	if req.Password == "" {
		s.log.Warn("ldap unauthenticated bind refused (empty password)",
			"dn", req.DN, "remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultUnwillingToPerform, "",
			"a bind with an empty password authenticates nobody (RFC 4513 section 5.1.2)")))
	}

	username, err := s.usernameFromDN(req.DN)
	if err != nil {
		// Reported as invalid credentials, not as a bad DN. A distinguishable
		// error here tells an attacker which DNs exist in what shape, and the
		// application cannot do anything different with the answer anyway.
		s.log.Info("ldap bind with an unusable DN", "dn", req.DN, "err", err,
			"remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultInvalidCredentials, "", "invalid credentials")))
	}

	id, err := s.auth.Authenticate(ctx, username, req.Password)
	if err != nil || id == nil {
		s.log.Info("ldap bind failed", "username", username,
			"remote", c.RemoteAddr().String())
		// One message for every failure: no such user, wrong password,
		// deactivated account. Anything else is a user-enumeration oracle
		// reachable by anyone who can open the port.
		return s.write(c, newMessage(messageID, newResult(appBindResponse,
			resultInvalidCredentials, "", "invalid credentials")))
	}

	sess.bound, sess.identity, sess.dn = true, id, req.DN
	s.log.Info("ldap bind succeeded", "username", username, "remote", c.RemoteAddr().String())
	return s.write(c, newMessage(messageID, newResult(appBindResponse, resultSuccess, "", "")))
}

// handleSearch answers a search.
func (s *Server) handleSearch(ctx context.Context, c net.Conn, sess *session, messageID int64, op *ber.Packet) bool {
	req, err := decodeSearch(op)
	if err != nil {
		return s.write(c, newMessage(messageID, newResult(appSearchResultDone,
			resultProtocolError, "", "malformed search request")))
	}

	// The root DSE probe: base "", scope base. Clients send it before binding to
	// discover what the server supports, and answering it discloses nothing.
	if req.BaseDN == "" && req.Scope == scopeBaseObject {
		return s.writeRootDSE(c, messageID, req)
	}

	if !sess.bound && !s.cfg.AllowAnonymousSearch {
		s.log.Info("ldap anonymous search refused", "base", req.BaseDN,
			"remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(appSearchResultDone,
			resultInsufficientAccess, "",
			"bind before searching; anonymous search is disabled")))
	}

	if !s.underBase(req.BaseDN) {
		return s.write(c, newMessage(messageID, newResult(appSearchResultDone,
			resultNoSuchObject, s.cfg.BaseDN, "no such object")))
	}

	limit := s.cfg.MaxResults
	if req.SizeLimit > 0 && req.SizeLimit < limit {
		limit = req.SizeLimit
	}

	// §4.5.1.5's client-requested time limit. Zero means none, and the server's
	// own read deadline still applies on top -- "Servers may also enforce a
	// maximum time limit for the Search." Honoured because a client that asks
	// for two seconds has usually told its own caller the same thing, and a
	// directory that overruns it turns one slow query into a stalled request
	// somewhere the operator cannot see.
	if req.TimeLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeLimit)*time.Second)
		defer cancel()
	}

	entries, err := s.entriesFor(ctx, req, limit)
	// `ctx.Err()` rather than `errors.Is(err, context.DeadlineExceeded)` alone:
	// a backing store is free to report cancellation as its own error type, and
	// several do -- pgx wraps, some drivers substitute. Asking the context
	// whether the deadline passed is a question about our own state, and does not
	// depend on a stranger's error-wrapping discipline.
	if err != nil && ctx.Err() != nil && req.TimeLimit > 0 {
		// §4.5.1.5's own result code, rather than `other`: a client that asked
		// for a time limit and hit it should be told which limit it hit.
		s.log.Info("ldap search exceeded the client's time limit",
			"seconds", req.TimeLimit, "remote", c.RemoteAddr().String())
		return s.write(c, newMessage(messageID, newResult(appSearchResultDone,
			resultTimeLimitExceeded, "", "the search exceeded the requested timeLimit")))
	}
	if err != nil {
		s.log.Error("ldap search", "err", err)
		return s.write(c, newMessage(messageID, newResult(appSearchResultDone,
			resultOther, "", "search failed")))
	}

	for _, e := range entries {
		if !s.write(c, newMessage(messageID, newSearchEntry(e, req.Attrs, req.TypesOnly))) {
			return false
		}
	}
	return s.write(c, newMessage(messageID, newResult(appSearchResultDone, resultSuccess, "", "")))
}

// entriesFor resolves a search to entries.
func (s *Server) entriesFor(ctx context.Context, req *searchRequest, limit int) ([]*entry, error) {
	// A base-object search on a specific user DN is the common shape: an
	// application binds as a service account and reads one person.
	if req.Scope == scopeBaseObject {
		username, err := s.usernameFromDN(req.BaseDN)
		if err != nil {
			return nil, nil
		}
		id, err := s.auth.Lookup(ctx, username)
		if err != nil || id == nil {
			return nil, nil
		}
		e := s.entryFor(id)
		if req.Filter.Matches(e) {
			return []*entry{e}, nil
		}
		return nil, nil
	}

	users, err := s.auth.List(ctx, limit)
	if err != nil {
		return nil, err
	}
	var out []*entry
	for _, id := range users {
		e := s.entryFor(id)
		if req.Filter.Matches(e) {
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// entryFor renders one identity.
//
// There is no userPassword attribute, at any value. Some directories return a
// hash; some return a placeholder. Both teach applications to compare passwords
// themselves, which is how a credential ends up compared with == in somebody
// else's code.
func (s *Server) entryFor(id *Identity) *entry {
	attrs := map[string][]string{
		"objectClass":  objectClasses,
		s.cfg.UserAttr: {id.Username},
		"cn":           {firstNonEmpty(id.DisplayName, id.Username)},
		// `sn` is a MUST attribute of `person` (RFC 4519), and this entry claims
		// that class four lines up. It was simply absent before writes existed,
		// which made every entry here schema-invalid against a class it declared
		// -- found by working out what an Add would have to require.
		//
		// The fallback matters as much as the column. Rows that predate the
		// column have no surname, and returning no `sn` for them would leave the
		// original defect in place for every existing account. A directory whose
		// `cn` is a whole name and whose `sn` is derived from it is ordinary; an
		// entry missing a MUST attribute is not.
		"sn": {firstNonEmpty(id.Surname, surnameFrom(id.DisplayName), id.Username)},
	}
	if id.Email != "" {
		attrs["mail"] = []string{id.Email}
	}
	if id.DisplayName != "" {
		attrs["displayName"] = []string{id.DisplayName}
	}
	if id.GivenName != "" {
		attrs["givenName"] = []string{id.GivenName}
	}
	if len(id.Groups) > 0 {
		// Full DNs, which is what directory-aware software expects to match on --
		// a bare name here works with some clients and silently matches nothing
		// in others.
		dns := make([]string, 0, len(id.Groups))
		for _, g := range id.Groups {
			dns = append(dns, fmt.Sprintf("cn=%s,ou=groups,%s", g, s.cfg.BaseDN))
		}
		attrs["memberOf"] = dns
	}
	return &entry{DN: s.dnFor(id.Username), Attrs: attrs}
}

func (s *Server) dnFor(username string) string {
	return fmt.Sprintf("%s=%s,%s", s.cfg.UserAttr, username, s.cfg.BaseDN)
}

// usernameFromDN extracts the login name from a bind DN.
//
// Only the leading RDN is read, and only when it uses the configured naming
// attribute. Searching the whole DN for something that looks like a username is
// how `uid=admin,ou=uid=alice,...` becomes a way to bind as somebody else.
func (s *Server) usernameFromDN(dn string) (string, error) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return "", fmt.Errorf("empty DN")
	}
	first := dn
	if i := strings.IndexByte(dn, ','); i >= 0 {
		first = dn[:i]
	}
	attr, value, ok := strings.Cut(first, "=")
	if !ok {
		return "", fmt.Errorf("DN does not begin with attribute=value")
	}
	if !equalFold(strings.TrimSpace(attr), s.cfg.UserAttr) {
		return "", fmt.Errorf("DN begins with %q, expected %q", attr, s.cfg.UserAttr)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("DN has an empty %s", s.cfg.UserAttr)
	}
	// The suffix must match, ALWAYS.
	//
	// The first version only checked when there was something after the leading
	// RDN, so a bare `uid=alice` -- no suffix at all -- skipped the check and
	// bound. Validation you can bypass by omitting the thing being validated is
	// not validation. Caught by a test, not by reading it.
	rest := strings.TrimPrefix(strings.TrimPrefix(dn, first), ",")
	if !equalFold(strings.TrimSpace(rest), s.cfg.BaseDN) {
		return "", fmt.Errorf("DN is not under %s", s.cfg.BaseDN)
	}
	return value, nil
}

func (s *Server) underBase(dn string) bool {
	dn = strings.TrimSpace(dn)
	return equalFold(dn, s.cfg.BaseDN) || strings.HasSuffix(strings.ToLower(dn),
		","+strings.ToLower(s.cfg.BaseDN))
}

// writeRootDSE answers the pre-bind capability probe.
func (s *Server) writeRootDSE(c net.Conn, messageID int64, req *searchRequest) bool {
	e := &entry{DN: "", Attrs: map[string][]string{
		"objectClass":          {"top", "LDAProotDSE"},
		"namingContexts":       {s.cfg.BaseDN},
		"supportedLDAPVersion": {"3"},
		// No supportedExtension, and specifically no StartTLS: advertising an
		// extension that is refused is how a client decides to try it, fails,
		// and falls back to plaintext.
		"vendorName": {"Signari"},
	}}
	if !s.write(c, newMessage(messageID, newSearchEntry(e, req.Attrs, req.TypesOnly))) {
		return false
	}
	return s.write(c, newMessage(messageID, newResult(appSearchResultDone, resultSuccess, "", "")))
}

func (s *Server) write(c net.Conn, p *ber.Packet) bool {
	if err := c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return false
	}
	if _, err := c.Write(p.Bytes()); err != nil {
		return false
	}
	return true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// surnameFrom takes the last word of a display name.
//
// A guess, and labelled as one. It exists only for rows that predate the
// surname column: the alternative for those is publishing a `person` entry with
// no `sn`, which every schema-aware client is entitled to reject. A row written
// through this directory carries the surname the client actually sent, and this
// function is not consulted.
func surnameFrom(displayName string) string {
	fields := strings.Fields(displayName)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}
