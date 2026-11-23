package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/migrate"
)

// The PostgreSQL half of `signari setup`. A superuser's connection is used for
// three things -- the database, migration 0001 and the engine role's password
// -- and nothing else, and is never written anywhere. Everything after runs as
// signari_engine, the role the engine then serves as: the one role every
// organisation's row-level security policy exempts (migration 0018), and one
// that, unlike a superuser, the policies still bind wherever it does not.

// engineRole is the role migration 0001 makes for the engine.
const engineRole = "signari_engine"

// pgSuperuser is a way to reach PostgreSQL as a role that may create roles.
type pgSuperuser struct {
	cfg *pgx.ConnConfig
	// query is what a URL the operator gave asked of the connection (sslmode,
	// sslrootcert), which the engine's own connection keeps.
	query url.Values
	// desc names it in the plan and in errors, with no password, as a phrase
	// beginning "as" or "at"; as says it shortly, for the question that
	// confirms it.
	desc, as string
	// socket is a Unix socket on this machine, which the engine reaches over
	// TCP on loopback instead, as setup proves it can.
	socket bool
}

// superuserFromFlags is the connection -superuser-dsn or -superuser-dsn-file
// names, or nil when neither does.
func superuserFromFlags(f setupFlags) (*pgSuperuser, error) {
	raw := f.superuserDSN
	switch {
	case f.superuserDSN != "" && f.superuserDSNFile != "":
		return nil, usageError{errors.New("give -superuser-dsn or -superuser-dsn-file, not both")}
	case f.superuserDSNFile != "":
		b, err := os.ReadFile(f.superuserDSNFile) // #nosec G304 G703 -- the operator names the file
		if err != nil {
			return nil, err
		}
		raw = strings.TrimSpace(string(b))
	case raw == "":
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, usageError{errors.New("give -superuser-dsn as a URL, postgres://user@host:5432/postgres")}
	}
	_, inUser := u.User.Password()
	if (inUser || u.Query().Get("password") != "") && f.superuserDSN != "" {
		return nil, usageError{errors.New("-superuser-dsn carries a password, which anybody on this machine " +
			"can read in the process list and the shell keeps in its history: leave it out and set " +
			"PGPASSWORD, or put the URL in a file for -superuser-dsn-file")}
	}
	return superuserFromURL(u)
}

// superuserFromURL parses a superuser's URL, given or typed at the prompt.
func superuserFromURL(u *url.URL) (*pgSuperuser, error) {
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, fmt.Errorf("the superuser URL: %w", err)
	}
	q := u.Query()
	// Named without its password, wherever the URL carried one.
	shown := *u
	if shown.User != nil {
		shown.User = url.User(shown.User.Username())
	}
	sq := shown.Query()
	sq.Del("password")
	shown.RawQuery = sq.Encode()
	return &pgSuperuser{cfg: cfg, query: q, desc: "at " + shown.String(), socket: strings.HasPrefix(cfg.Host, "/")}, nil
}

// validSuperuserURL is the prompt's check of a typed URL.
func validSuperuserURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Host == "" && u.Query().Get("host") == "") {
		return errors.New("type a URL such as postgres://postgres@db.example.com:5432/postgres")
	}
	if _, err := pgx.ParseConfig(s); err != nil {
		return err
	}
	return nil
}

// localPostgres is the PostgreSQL this machine runs, if any: a Unix socket in
// one of h.socketDirs, reached as the postgres system user when root can be
// that user, else as the user running setup; or failing that a server on
// 127.0.0.1:5432, as postgres with whatever password PGPASSWORD or ~/.pgpass
// holds.
func localPostgres(h setupHost) *pgSuperuser {
	for _, dir := range h.socketDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, ".s.PGSQL.*"))
		sort.Strings(matches)
		port := 0
		for _, m := range matches {
			n, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(m), ".s.PGSQL."))
			if err != nil || n < 1 || n > 65535 {
				continue // the .lock beside a socket, or not a socket of PostgreSQL's
			}
			if port == 0 || n == 5432 {
				port = n
			}
		}
		if port == 0 {
			continue
		}
		cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=postgres sslmode=disable", dir, port))
		if err != nil {
			continue
		}
		su := &pgSuperuser{cfg: cfg, socket: true}
		if h.postgresUID >= 0 {
			cfg.User = "postgres"
			cfg.DialFunc = peerDial(h.postgresUID)
			su.desc = "as postgres over the socket in " + dir + ", by peer authentication as the postgres system user"
		} else {
			su.desc = "as " + cfg.User + " over the socket in " + dir
		}
		su.as = "as " + cfg.User + " over the local socket"
		return su
	}
	if h.tcpOpen("127.0.0.1:5432") {
		cfg, err := pgx.ParseConfig("postgres://postgres@127.0.0.1:5432/postgres")
		if err == nil {
			return &pgSuperuser{cfg: cfg, desc: "as postgres at 127.0.0.1:5432", as: "as postgres at 127.0.0.1:5432"}
		}
	}
	return nil
}

// connectAs opens one connection with cfg, to database db when it is given.
func connectAs(ctx context.Context, cfg *pgx.ConnConfig, db string) (*pgx.Conn, error) {
	c := cfg.Copy()
	if db != "" {
		c.Database = db
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return pgx.ConnectConfig(cctx, c)
}

// pgCode is the SQLSTATE of err, or "".
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// authRefused says whether PostgreSQL turned the connection away for who it
// was: a wrong password, or no pg_hba.conf line letting it in.
func authRefused(err error) bool {
	switch pgCode(err) {
	case "28P01", "28000":
		return true
	}
	return false
}

// pgFacts is what setup reads of a server through the superuser before it
// writes anything.
type pgFacts struct {
	versionNum int
	version    string
	user       string
	superuser  bool
	port       int
	hbaFile    string
	dbExists   bool
	roleExists bool
	roleSuper  bool
	roleBypass bool
	// roleVerifier is signari_engine's stored password, "" for none.
	roleVerifier string
	// roleElsewhere are the other databases signari_engine owns or holds
	// something in, whose deployments its password belongs to as well.
	roleElsewhere []string
	hba           []hbaRule
}

func readPGFacts(ctx context.Context, su *pgx.Conn, database string) (pgFacts, error) {
	var p pgFacts
	if err := su.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::int, split_part(current_setting('server_version'), ' ', 1),
		       current_user, (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user),
		       current_setting('port')::int,
		       EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)`, database).
		Scan(&p.versionNum, &p.version, &p.user, &p.superuser, &p.port, &p.dbExists); err != nil {
		return p, fmt.Errorf("reading the server: %w", err)
	}
	// The rest is a superuser's to read, and pg_hba_file_rules has the
	// columns read below from PostgreSQL 16, the oldest the engine runs on:
	// either failing, the caller refuses the server before reading more.
	if !p.superuser || p.versionNum/10000 < migrate.MinServerMajor {
		return p, nil
	}
	if err := su.QueryRow(ctx, `SELECT current_setting('hba_file')`).Scan(&p.hbaFile); err != nil {
		return p, err
	}
	var verifier *string
	err := su.QueryRow(ctx, `SELECT rolsuper, rolbypassrls, rolpassword FROM pg_catalog.pg_authid WHERE rolname = $1`,
		engineRole).Scan(&p.roleSuper, &p.roleBypass, &verifier)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return p, err
	default:
		p.roleExists = true
		if verifier != nil {
			p.roleVerifier = *verifier
		}
		rows, err := su.Query(ctx, `
			SELECT DISTINCT d.datname FROM pg_catalog.pg_shdepend s
			  JOIN pg_catalog.pg_database d ON d.oid = s.dbid
			 WHERE s.refclassid = 'pg_catalog.pg_authid'::regclass
			   AND s.refobjid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)
			   AND d.datname <> $2
			 ORDER BY 1`, engineRole, database)
		if err != nil {
			return p, err
		}
		if p.roleElsewhere, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return p, err
		}
	}
	if p.hba, err = readHBA(ctx, su); err != nil {
		return p, err
	}
	return p, nil
}

// hbaRule is one line of pg_hba.conf, as pg_hba_file_rules shows it.
type hbaRule struct {
	file      string
	line      int
	kind      string
	databases []string
	users     []string
	address   string
	netmask   string
	method    string
	err       string
}

// readHBA reads pg_hba.conf as the server parses it: the file's current
// contents, which pg_hba_file_rules reports and only a superuser may read.
func readHBA(ctx context.Context, su *pgx.Conn) ([]hbaRule, error) {
	rows, err := su.Query(ctx, `
		SELECT coalesce(file_name, ''), coalesce(line_number, 0), coalesce(type, ''),
		       coalesce(database, '{}'), coalesce(user_name, '{}'), coalesce(address, ''),
		       coalesce(netmask, ''), coalesce(auth_method, ''), coalesce(error, '')
		  FROM pg_catalog.pg_hba_file_rules ORDER BY rule_number NULLS LAST, line_number`)
	if err != nil {
		return nil, fmt.Errorf("reading pg_hba.conf: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (hbaRule, error) {
		var h hbaRule
		err := r.Scan(&h.file, &h.line, &h.kind, &h.databases, &h.users, &h.address, &h.netmask, &h.method, &h.err)
		return h, err
	})
}

// hbaVerdict is what pg_hba.conf will do with the engine's connection.
type hbaVerdict int

const (
	hbaUnknown  hbaVerdict = iota // a rule setup cannot judge comes first
	hbaPassword                   // a line asks for the password, or trusts it
	hbaRefused                    // a line refuses it, or none matches
)

// judgeHBA is the first rule matching a connection over TCP without TLS from
// client to database as user, as the server would choose it. A rule whose
// match setup cannot work out -- a host name, a group, a regular expression, a
// line in error -- makes the answer unknown, and the real sign-in decides.
func judgeHBA(rules []hbaRule, database, user string, client netip.Addr) (hbaVerdict, hbaRule) {
	for _, r := range rules {
		if r.err != "" {
			return hbaUnknown, r
		}
		switch r.kind {
		case "host", "hostnossl", "hostnogssenc":
		default:
			continue // local, hostssl and hostgssenc never see a plain TCP connection
		}
		db, known := hbaNames(r.databases, database, user)
		if !known {
			return hbaUnknown, r
		}
		usr, known := hbaNames(r.users, user, "")
		if !known {
			return hbaUnknown, r
		}
		addr, known := hbaAddress(r.address, r.netmask, client)
		if !known {
			return hbaUnknown, r
		}
		if !db || !usr || !addr {
			continue
		}
		switch r.method {
		case "scram-sha-256", "md5", "password", "trust":
			return hbaPassword, r
		}
		return hbaRefused, r
	}
	return hbaRefused, hbaRule{}
}

// hbaNames says whether a rule's database or user list names want; user is
// the role, for sameuser.
func hbaNames(list []string, want, user string) (match, known bool) {
	for _, n := range list {
		switch {
		case n == "all", n == want:
			return true, true
		case n == "sameuser":
			if user != "" && user == want {
				return true, true
			}
		case n == "replication":
		case n == "samerole", n == "samegroup", strings.HasPrefix(n, "+"), strings.HasPrefix(n, "/"),
			strings.HasPrefix(n, "@"):
			return false, false
		}
	}
	return false, true
}

// hbaAddress says whether a rule's address covers client.
func hbaAddress(address, netmask string, client netip.Addr) (match, known bool) {
	switch address {
	case "all":
		return true, true
	case "samehost", "samenet":
		// The server's own addresses, and its own networks: loopback is both.
		return client.IsLoopback(), client.IsLoopback()
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false, false // a host name, which the server resolves itself
	}
	mask, err := netip.ParseAddr(netmask)
	if err != nil || ip.Is4() != client.Is4() {
		return false, err == nil
	}
	bits := 0
	for _, b := range mask.AsSlice() {
		for ; b&0x80 != 0; b <<= 1 {
			bits++
		}
	}
	prefix, err := ip.Prefix(bits)
	if err != nil {
		return false, false
	}
	return prefix.Contains(client), true
}

// hbaAdvice is what to put in pg_hba.conf so the engine may sign in.
func hbaAdvice(database, file string, rule hbaRule) string {
	line := fmt.Sprintf("host    %s    %s    127.0.0.1/32    scram-sha-256", database, engineRole)
	where := "to " + file
	if rule.line > 0 {
		f := rule.file
		if f == "" {
			f = file
		}
		where = fmt.Sprintf("to %s above line %d, which says %s for this connection", f, rule.line, rule.method)
	}
	return fmt.Sprintf("add this line %s:\n\n    %s\n\nthen reload PostgreSQL (SELECT pg_reload_conf(), or systemctl reload "+
		"postgresql) and run setup again", where, line)
}

// dbFacts is what setup reads of the database it sets up.
type dbFacts struct {
	applied int
	// issuers are the instances it holds; instanceID is the one setup's
	// issuer names, if any.
	issuers    []string
	instanceID string
	// signing counts the instance's active signing algorithms of the two
	// bootstrap makes; sealed says whether any signing key is stored at all.
	signing int
	sealed  bool
	orgID   string
	peopled bool
	// linkUntil is when the latest open one-time link expires, and linkEmail
	// whom it is for; lastEmail is whom the latest link was for, open or not.
	linkUntil time.Time
	linkEmail string
	lastEmail string
	// owners counts the organisation's org-owner bindings: the role that is
	// every administrative permission in it, which the console and the Admin
	// API read a person's rights from (adminapi.Roles).
	owners int
}

// ownerRole is the administrator's role: everything a stored token may do, in
// one organisation (internal/adminapi/roles.go).
const ownerRole = "org-owner"

// accountFor is the id of the person in orgID with the address email, or ""
// while they have none, which they get by setting a password with the link.
func accountFor(ctx context.Context, conn *pgx.Conn, orgID, email string) (string, error) {
	if orgID == "" || email == "" {
		return "", nil
	}
	var id string
	err := conn.QueryRow(ctx, `SELECT id::text FROM core.users WHERE org_id = $1::uuid AND email_fold = lower($2)`,
		orgID, email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// firstAdminDone says whether a person can sign in or has a link to.
func (d dbFacts) firstAdminDone(now time.Time) bool {
	return d.instanceID != "" && d.signing >= 2 && d.orgID != "" && (d.peopled || d.linkUntil.After(now))
}

// readDBFacts reads conn's database, as the engine or a superuser; a table a
// migration has not made yet is read as empty.
func readDBFacts(ctx context.Context, conn *pgx.Conn, issuer string) (dbFacts, error) {
	var d dbFacts
	var err error
	if d.applied, err = migrate.Applied(ctx, conn); err != nil {
		return d, err
	}
	var have struct{ instances, keys, orgs, users, invitations, roles bool }
	if err := conn.QueryRow(ctx, `SELECT to_regclass('core.instances') IS NOT NULL,
		to_regclass('core.signing_keys') IS NOT NULL, to_regclass('core.organizations') IS NOT NULL,
		to_regclass('core.users') IS NOT NULL, to_regclass('core.invitations') IS NOT NULL,
		to_regclass('core.admin_role_bindings') IS NOT NULL`).
		Scan(&have.instances, &have.keys, &have.orgs, &have.users, &have.invitations, &have.roles); err != nil {
		return d, err
	}
	if !have.instances {
		return d, nil
	}
	rows, err := conn.Query(ctx, `SELECT issuer FROM core.instances ORDER BY created_at, issuer`)
	if err != nil {
		return d, err
	}
	if d.issuers, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return d, err
	}
	err = conn.QueryRow(ctx, `SELECT id::text FROM core.instances WHERE issuer = $1`, issuer).Scan(&d.instanceID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	if have.keys {
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.signing_keys),
			(SELECT count(DISTINCT algorithm) FROM core.signing_keys
			  WHERE instance_id::text = $1 AND state = 'active' AND purpose = 'oidc'
			    AND algorithm IN ('ES256', 'RS256'))`, d.instanceID).Scan(&d.sealed, &d.signing); err != nil {
			return d, err
		}
	}
	if d.instanceID == "" || !have.orgs {
		return d, nil
	}
	err = conn.QueryRow(ctx, `SELECT id::text FROM core.organizations WHERE instance_id = $1::uuid
		ORDER BY created_at, id LIMIT 1`, d.instanceID).Scan(&d.orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, nil
	} else if err != nil {
		return d, err
	}
	if have.users {
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE org_id = $1::uuid)`,
			d.orgID).Scan(&d.peopled); err != nil {
			return d, err
		}
	}
	if have.invitations {
		err := conn.QueryRow(ctx, `SELECT expires_at, coalesce(email, '') FROM core.invitations
			WHERE org_id = $1::uuid AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
			ORDER BY expires_at DESC LIMIT 1`, d.orgID).Scan(&d.linkUntil, &d.linkEmail)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return d, err
		}
		err = conn.QueryRow(ctx, `SELECT coalesce(email, '') FROM core.invitations WHERE org_id = $1::uuid
			ORDER BY created_at DESC LIMIT 1`, d.orgID).Scan(&d.lastEmail)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return d, err
		}
	}
	if have.roles {
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM core.admin_role_bindings
			WHERE org_id = $1::uuid AND role = $2 AND group_id IS NULL`, d.orgID, ownerRole).Scan(&d.owners); err != nil {
			return d, err
		}
	}
	return d, nil
}

// rootKeyOpens says whether root unseals the instance's signing keys, which
// a root key made by a later run, after the first was lost, would not.
func rootKeyOpens(ctx context.Context, conn *pgx.Conn, instanceID string, root *keys.RootKey) error {
	if _, err := keys.LoadSet(ctx, conn, instanceID, root); err != nil {
		return err
	}
	return nil
}

// engineDSN is the engine's connection: the superuser's server, reached over
// TCP on loopback when the superuser came over a socket, as signari_engine
// with password, to database. TLS on loopback protects nothing a local
// attacker could not reach already and costs throughput, so it is off there
// unless the superuser's URL asked for it (docs/configuration.md, SIGNARI_DSN).
func engineDSN(su *pgSuperuser, port int, database, password string) string {
	host, p := su.cfg.Host, int(su.cfg.Port)
	q := url.Values{}
	for k, v := range su.query {
		if k != "host" && k != "port" && k != "user" && k != "password" && k != "dbname" {
			q[k] = v
		}
	}
	// Loopback by its address, so the connection is the one pg_hba.conf was
	// read for: "localhost" may be ::1 first, and a line for 127.0.0.1 then
	// says nothing about it.
	if su.socket {
		host, p = "127.0.0.1", port
	} else if host == "localhost" {
		host = "127.0.0.1"
	}
	if q.Get("sslmode") == "" && isLoopback(host) {
		q.Set("sslmode", "disable")
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword(engineRole, password),
		Host: net.JoinHostPort(host, strconv.Itoa(p)), Path: "/" + database, RawQuery: q.Encode()}
	return u.String()
}

// isLoopback says whether host is this machine's loopback.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// dsnParts reads an env file's SIGNARI_DSN: who it signs in as, with what,
// to which database, on which host.
func dsnParts(dsn string) (user, password, database, host string, err error) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", "", "", "", errors.New("SIGNARI_DSN is not a postgres:// URL")
	}
	password, _ = u.User.Password()
	return u.User.Username(), password, strings.TrimPrefix(u.Path, "/"), u.Hostname(), nil
}

// setEnginePassword gives signari_engine password, sent as its SCRAM verifier
// (scram.go). ALTER ROLE takes no parameters, so the statement is made by the
// server: format() with %L quotes the verifier as a literal.
func setEnginePassword(ctx context.Context, su *pgx.Conn, verifier string) error {
	var stmt string
	if verifier == "" {
		stmt = "ALTER ROLE " + engineRole + " PASSWORD NULL"
	} else if err := su.QueryRow(ctx, `SELECT format('ALTER ROLE `+engineRole+` PASSWORD %L', $1::text)`,
		verifier).Scan(&stmt); err != nil {
		return err
	}
	_, err := su.Exec(ctx, stmt)
	return err
}

// roleAttrs reads whether the role this connection signed in as, or acts as,
// is a superuser or may bypass row-level security.
func roleAttrs(ctx context.Context, conn *pgx.Conn) (session, current string, privileged bool, err error) {
	err = conn.QueryRow(ctx, `
		SELECT session_user, current_user,
		       (SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_catalog.pg_roles
		         WHERE rolname IN (session_user, current_user))`).Scan(&session, &current, &privileged)
	return
}
