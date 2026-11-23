package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/store"
)

// `signari setup` takes a machine with PostgreSQL to a deployment somebody can
// sign in to: a database, its schema, the engine's own role with a password,
// a root key, an instance with its signing keys, an organisation, a one-time
// link for its first administrator, and an env file `serve` starts from.
//
// It works out what it can -- the host's name, a PostgreSQL on this machine,
// what an earlier run did -- and asks only what it cannot, at a terminal; with
// none, or given -yes, it asks nothing and names the flag an answer it needs
// would come from. The defaults are the same either way (setupDefault).
//
// Every check runs before anything is written, and each step is skipped when
// what it makes is there, so a second run changes nothing and says so. When a
// step fails, what this run made is taken away again, except what may already
// hold something: the database, and the root key once anything is sealed
// under it, which are never deleted for anybody.

// setupFlags are what setup was given.
type setupFlags struct {
	issuer, email                  string
	superuserDSN, superuserDSNFile string
	database, addr                 string
	rootKeyFile, envFile           string
	yes, dryRun, check, json       bool
	printRootKey                   bool
	// given are the flags set on the command line.
	given map[string]bool
}

// prompts says whether setup may ask: at a terminal, and not told otherwise.
func (f setupFlags) prompts(h setupHost) bool {
	return h.interactive && !f.yes && !f.json && !f.dryRun && !f.check && !ciSet(h.getenv)
}

// setupHost is what setup reads of the machine it runs on, gathered in one
// place so a test can be another machine.
type setupHost struct {
	goos, goarch string
	euid         int
	getenv       func(string) string
	home         string
	// fqdn is the host's own name, from the operating system or `hostname
	// -f`; nothing outside this machine and its resolver is asked.
	fqdn     func() string
	resolves func(name string) bool
	// socketDirs are where a local PostgreSQL keeps its socket.
	socketDirs []string
	tcpOpen    func(addr string) bool
	// postgresUID is the postgres system user, which root can connect as
	// for peer authentication; -1 when that is not this machine's way in.
	postgresUID   int
	systemd       bool
	unitInstalled bool
	interactive   bool
	now           func() time.Time
}

// unitPath is where the installer writes signari's systemd unit.
const unitPath = "/etc/systemd/system/signari.service"

func thisHost() setupHost {
	home, _ := os.UserHomeDir()
	h := setupHost{goos: runtime.GOOS, goarch: runtime.GOARCH, euid: os.Geteuid(), getenv: os.Getenv,
		home: home, fqdn: hostFQDN, resolves: resolvesHere,
		socketDirs: []string{"/var/run/postgresql", "/tmp"}, postgresUID: -1,
		tcpOpen: func(addr string) bool {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				return false
			}
			_ = c.Close()
			return true
		},
		interactive: atTerminal(), now: time.Now}
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		h.systemd = true
	}
	if _, err := os.Stat(unitPath); err == nil {
		h.unitInstalled = true
	}
	if peerSupported && h.euid == 0 {
		if u, err := user.Lookup("postgres"); err == nil {
			if n, err := strconv.Atoi(u.Uid); err == nil && n > 0 {
				h.postgresUID = n
			}
		}
	}
	return h
}

// hostFQDN is this machine's name with its domain, as the operating system
// or `hostname -f` gives it.
func hostFQDN() string {
	name, _ := os.Hostname()
	if strings.Contains(name, ".") {
		return name
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "hostname", "-f").Output(); err == nil {
		if s := strings.TrimSpace(string(out)); strings.Contains(s, ".") {
			return s
		}
	}
	return name
}

// resolvesHere asks this machine's resolver whether name has an address.
func resolvesHere(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	return err == nil && len(addrs) > 0
}

// privateSuffixes end names nobody outside a network can reach.
var privateSuffixes = []string{".local", ".localdomain", ".lan", ".home", ".internal", ".intranet", ".corp",
	".localhost", ".home.arpa", ".test", ".example", ".invalid"}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// publicName says whether name looks like one people elsewhere could reach
// this machine by: a dotted DNS name, not an address, and not under a suffix
// kept for private networks.
func publicName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.Contains(name, ".") || strings.Contains(name, ".internal.") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, s := range privateSuffixes {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	_, err := strconv.Atoi(labels[len(labels)-1])
	return err != nil
}

// suggestIssuer is the issuer offered when none is given: https and the host's
// name when it has one people could reach and it resolves, else this machine
// alone, on the port setup has the engine listen on.
func suggestIssuer(h setupHost, addr string) string {
	if name := strings.TrimSuffix(strings.ToLower(h.fqdn()), "."); publicName(name) && h.resolves(name) {
		return "https://" + name
	}
	port := "8080"
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	return "http://localhost:" + port
}

// setupAnswers are what setup goes on: each from a flag, an earlier run's env
// file, the terminal, or the default, which from records.
type setupAnswers struct {
	issuer, email, database, addr, rootKeyFile, envFile string
	from                                                map[string]string
}

// setupDefault is the one table of defaults, read by the run that asks and the
// run that does not alike: an answer nobody gives is this either way. An
// installer whose quick defaults were set only where it asked would install
// one thing by hand and another from a script. The first administrator's email
// has none, as only the person running this can say whose it is.
func setupDefault(name string, h setupHost, a setupAnswers) string {
	switch name {
	case "database":
		return "signari"
	case "addr":
		return "127.0.0.1:8080"
	case "root-key-file":
		return filepath.Join(setupConfigDir(h.euid, h.getenv, h.home), rootKeyFileName)
	case "env-file":
		return filepath.Join(setupConfigDir(h.euid, h.getenv, h.home), envFileName)
	case "issuer":
		return suggestIssuer(h, a.addr)
	}
	return ""
}

// setupQuestion is an answer setup asks for at a terminal when it was not
// given, with the default offered.
type setupQuestion struct{ label, hint string }

var setupQuestions = map[string]setupQuestion{
	"issuer": {"The address people will use to reach Signari",
		"It becomes the issuer, in every token: choose the name you will keep."},
	"email": {"The first administrator's email",
		"They get a one-time link to set a password, which works for nobody else."},
}

// validIssuer holds an issuer to what `serve` publishes: https, or http on
// localhost alone, and nothing a relying party's exact comparison would trip
// on.
func validIssuer(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		return fmt.Errorf("%q is not an address such as https://login.example.com", s)
	case u.Scheme == "http" && u.Hostname() != "localhost":
		return fmt.Errorf("%s is plain HTTP on a name other than localhost, which puts every token on the "+
			"network readable: use https, with TLS ended here or by a proxy in front", s)
	case u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return fmt.Errorf("%s carries a user, a query or a fragment, which an issuer may not", s)
	case strings.HasSuffix(s, "/"):
		return fmt.Errorf("%s ends in a slash, and relying parties compare the issuer exactly: leave it off", s)
	case !envSafe(s):
		return fmt.Errorf("%q holds a quote or a line break", s)
	}
	return nil
}

func validEmail(s string) error {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || strings.ContainsAny(s, " \t\r\n'\"") {
		return fmt.Errorf("%q is not an email address", s)
	}
	return nil
}

var databaseName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func validDatabase(s string) error {
	if !databaseName.MatchString(s) {
		return fmt.Errorf("%q is not a database name setup makes: lowercase letters, digits and underscores, "+
			"not starting with a digit, at most 63", s)
	}
	return nil
}

func validAddr(s string) error {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%q is not a listen address such as 127.0.0.1:8080: %w", s, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q has no port from 1 to 65535", s)
	}
	if !envSafe(s) {
		return fmt.Errorf("%q holds a quote or a line break", s)
	}
	return nil
}

func validFilePath(s string) error {
	if !filepath.IsAbs(s) || !envSafe(s) {
		return fmt.Errorf("%q is not an absolute path setup can write to an env file", s)
	}
	if fi, err := os.Stat(s); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory", s)
	}
	return nil
}

var setupValid = map[string]func(string) error{
	"issuer": validIssuer, "email": validEmail, "database": validDatabase, "addr": validAddr,
	"root-key-file": validFilePath, "env-file": validFilePath,
}

// resolveAnswers settles every answer from, first to last: its flag, the env
// file an earlier run wrote, the person at the terminal when ask is given
// (offered the default), and the default. A flag that disagrees with the env
// file is refused, since setup never changes what an earlier run settled. The
// email is needed only when no earlier run has been here; allowMissing, for a
// dry run, lists it instead of refusing.
func resolveAnswers(f setupFlags, h setupHost, prior envFile, ask prompter, allowMissing bool) (setupAnswers, []string, error) {
	a := setupAnswers{envFile: prior.path, from: map[string]string{"env-file": "flag"}}
	if f.envFile == "" {
		a.from["env-file"] = "default"
	}
	_, _, priorDB, _, _ := dsnParts(prior.values["SIGNARI_DSN"])
	priors := map[string]string{
		"addr": prior.values["SIGNARI_ADDR"], "database": priorDB,
		"root-key-file": prior.values["SIGNARI_ROOT_KEY_FILE"], "issuer": prior.values["SIGNARI_ISSUER"],
	}
	flags := map[string]string{"addr": f.addr, "database": f.database, "root-key-file": f.rootKeyFile,
		"issuer": f.issuer, "email": strings.ToLower(strings.TrimSpace(f.email))}
	if p := flags["root-key-file"]; p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			flags["root-key-file"] = abs
		}
	}
	var missing []string
	set := map[string]*string{"addr": &a.addr, "database": &a.database, "root-key-file": &a.rootKeyFile,
		"issuer": &a.issuer, "email": &a.email}
	for _, name := range []string{"addr", "database", "root-key-file", "issuer", "email"} {
		valid := setupValid[name]
		given, before := flags[name], priors[name]
		switch {
		case given != "":
			if before != "" && before != given {
				return a, nil, usageError{fmt.Errorf("-%s is %s, and %s, which an earlier run wrote, says %s. "+
					"Setup never changes what it settled: edit that file yourself, or give -env-file for "+
					"another deployment", name, given, prior.path, before)}
			}
			if err := valid(given); err != nil {
				return a, nil, usageError{fmt.Errorf("-%s: %w", name, err)}
			}
			*set[name], a.from[name] = given, "flag"
		case before != "":
			if err := valid(before); err != nil {
				return a, nil, fmt.Errorf("%s: %w", prior.path, err)
			}
			*set[name], a.from[name] = before, "env file"
		default:
			def := setupDefault(name, h, a)
			q, asks := setupQuestions[name]
			switch {
			case asks && ask != nil && (name != "email" || !prior.exists):
				v, err := ask.ask(q.label, q.hint, def, valid)
				if err != nil {
					return a, nil, err
				}
				*set[name], a.from[name] = strings.TrimSpace(v), "asked"
				if name == "email" {
					a.email = strings.ToLower(a.email)
				}
			case def != "":
				*set[name], a.from[name] = def, "default"
			case name == "email" && prior.exists:
				// Needed only if the first administrator has no link yet,
				// which the database says (setupRun.inspect).
			case allowMissing:
				missing = append(missing, name)
			default:
				return a, nil, fmt.Errorf("give -%s, the first administrator's address, which setup cannot "+
					"work out for itself", name)
			}
		}
	}
	if a.rootKeyFile == a.envFile {
		return a, nil, usageError{fmt.Errorf("-root-key-file and -env-file are both %s", a.envFile)}
	}
	return a, missing, nil
}

// setupStep is one thing setup does, or found done.
type setupStep struct {
	name string // for a script: database, schema, root-key, env-file, engine-role, migrations, first-admin
	what string
	// skip, when set, is what was found that makes the step done already;
	// wait, what it needs that is not there yet, which a later run does.
	skip, wait string
	state      string // planned, skipped, waiting, done, failed
	run        func(context.Context) error
}

// errWaiting is a step finding that what it needs is not there yet.
var errWaiting = errors.New("not yet")

// setupRun is one run of setup: what it settled, found and made.
type setupRun struct {
	f   setupFlags
	h   setupHost
	out io.Writer
	ask prompter

	prior   envFile
	a       setupAnswers
	missing []string

	keyExists bool
	latest    int

	// The engine's connection, from an earlier run's env file or made here.
	engineDSN, password, engineHost string
	engineWorked                    bool
	eng                             *pgx.Conn

	su         *pgSuperuser
	suConn     *pgx.Conn
	suDB       *pgx.Conn
	suErr      error
	pg         pgFacts
	passwordOK bool // the role's stored verifier is the env file's password

	db dbFacts
	// adminID is the first administrator's account, once they have one.
	adminID string

	steps []setupStep

	// What this run made, for a failure to take back.
	createdDB, createdKey, createdEnv, rewroteEnv, passwordSet, bootstrapStarted bool
	envBefore                                                                    []byte
	madeDirs                                                                     []string
	rootKeyText                                                                  string

	link        string
	linkExpires time.Time
}

// setupCmd is `signari setup`. Its progress is for a person, on stdout, or on
// stderr with -json, which keeps stdout for the one line of JSON a script
// reads.
func setupCmd(ctx context.Context, stdout, stderr io.Writer, h setupHost, f setupFlags) error {
	if f.given["dsn"] {
		return usageError{errors.New("setup takes -superuser-dsn, a role that may create roles, once; -dsn " +
			"names the engine's own connection, which setup makes and writes to the env file")}
	}
	// -addr has serve's default when it is not given, which is not setup's.
	if !f.given["addr"] {
		f.addr = ""
	}
	out := stdout
	if f.json {
		out = stderr
	}
	if f.check {
		return setupCheck(ctx, stdout, out, h, f)
	}
	r := &setupRun{f: f, h: h, out: out}
	if f.prompts(h) {
		r.ask = newTermPrompter(out)
	}
	err := r.run(ctx)
	r.close()
	if f.json {
		line, jerr := json.Marshal(r.result(err))
		if jerr != nil {
			return jerr
		}
		fmt.Fprintln(stdout, string(line))
	}
	return err
}

func (r *setupRun) close() {
	for _, c := range []*pgx.Conn{r.eng, r.suDB, r.suConn} {
		if c != nil {
			_ = c.Close(context.Background())
		}
	}
}

func (r *setupRun) run(ctx context.Context) error {
	fmt.Fprintf(r.out, "\n  signari setup, on %s/%s as %s%s\n", r.h.goos, r.h.goarch, whoRuns(r.h.euid),
		map[bool]string{true: ", with systemd"}[r.h.systemd])
	if err := r.inspect(ctx); err != nil {
		return err
	}
	r.plan()
	r.printPlan()
	pending := slices.ContainsFunc(r.steps, func(s setupStep) bool { return s.skip == "" && s.wait == "" })
	if r.f.dryRun {
		if len(r.missing) > 0 {
			fmt.Fprintf(r.out, "\n  A real run also needs: -%s\n", strings.Join(r.missing, ", -"))
		}
		fmt.Fprintln(r.out, "\n  Dry run: nothing was changed.")
		return nil
	}
	if !pending {
		fmt.Fprintln(r.out)
		if err := r.execute(ctx); err != nil {
			return err
		}
		fmt.Fprintln(r.out, "\n  Nothing to do now: every step is done, or waits for what a later run needs.")
		r.printSummary()
		return nil
	}
	if r.ask != nil {
		ok, err := r.ask.confirm("Set up Signari as planned above?",
			"Nothing has changed yet, and every step is safe to run again.", true)
		if err != nil {
			return err
		}
		if !ok {
			return errCancelled
		}
	}
	fmt.Fprintln(r.out)
	// From here an interrupt ends the step under way, and what this run made
	// is taken back, rather than the process ending part way through a step.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := r.execute(ctx); err != nil {
		r.undo()
		return err
	}
	r.printSummary()
	return nil
}

func whoRuns(euid int) string {
	if euid == 0 {
		return "root"
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid " + strconv.Itoa(euid)
}

// inspect settles the answers and reads everything the plan depends on,
// writing nothing, and refuses what a step would fail on.
func (r *setupRun) inspect(ctx context.Context) error {
	envPath := r.f.envFile
	if envPath == "" {
		envPath = setupDefault("env-file", r.h, setupAnswers{})
	}
	envPath, err := filepath.Abs(envPath)
	if err != nil {
		return err
	}
	if err := validFilePath(envPath); err != nil {
		return usageError{fmt.Errorf("-env-file: %w", err)}
	}
	if r.prior, err = readEnvFile(envPath); err != nil {
		return err
	}
	if r.a, r.missing, err = resolveAnswers(r.f, r.h, r.prior, r.ask, r.f.dryRun); err != nil {
		return err
	}
	if r.keyExists, err = rootKeyFileState(r.a.rootKeyFile); err != nil {
		return err
	}
	all, err := migrate.Load()
	if err != nil {
		return err
	}
	r.latest = all[len(all)-1].Version

	// The engine's own connection first, when an earlier run wrote one: a run
	// that finds everything done needs no superuser at all.
	if dsn := r.prior.values["SIGNARI_DSN"]; dsn != "" {
		login, password, _, host, err := dsnParts(dsn)
		if err != nil {
			return fmt.Errorf("%s: %w", r.prior.path, err)
		}
		if login != engineRole {
			return fmt.Errorf("%s says SIGNARI_DSN signs in as %s, and setup has the engine serve as %s, the role "+
				"row-level security is written for: change it there, or give -env-file for a new file",
				r.prior.path, login, engineRole)
		}
		r.engineDSN, r.password, r.engineHost = dsn, password, host
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return fmt.Errorf("%s: SIGNARI_DSN: %w", r.prior.path, err)
		}
		if conn, err := connectAs(ctx, cfg, ""); err == nil {
			r.eng, r.engineWorked = conn, true
			if r.db, err = readDBFacts(ctx, conn, r.a.issuer); err != nil {
				return err
			}
		}
	}

	if !r.engineWorked || r.db.applied == 0 {
		if err := r.reachSuperuser(ctx); err != nil {
			if !r.f.dryRun {
				return err
			}
			r.suErr = err
		}
	}
	if r.suConn != nil {
		if err := r.inspectServer(ctx); err != nil {
			return err
		}
	}
	if r.engineDSN == "" && r.su == nil {
		// A dry run that reached no server: the plan as it would run on an
		// empty one, on this machine.
		r.engineHost = "127.0.0.1"
	}
	if err := r.settleFirstAdmin(ctx); err != nil {
		return err
	}
	return r.refuseWhatWouldFail(ctx)
}

// settleFirstAdmin finds whom the first administrator is, now the database
// has been read: the address given, else the one the earlier link was for,
// else the person at the terminal, and their account once they have one. It is
// needed only while nobody can sign in yet or nobody owns the organisation.
func (r *setupRun) settleFirstAdmin(ctx context.Context) error {
	d := r.db
	if d.firstAdminDone(r.h.now()) && d.owners > 0 {
		return nil
	}
	if r.a.email == "" && d.lastEmail != "" {
		r.a.email, r.a.from["email"] = d.lastEmail, "the earlier link"
	}
	if r.a.email == "" {
		switch q := setupQuestions["email"]; {
		case r.ask != nil:
			v, err := r.ask.ask(q.label, q.hint, "", validEmail)
			if err != nil {
				return err
			}
			r.a.email, r.a.from["email"] = strings.ToLower(v), "asked"
		case r.f.dryRun:
			if !slices.Contains(r.missing, "email") {
				r.missing = append(r.missing, "email")
			}
			return nil
		default:
			return errors.New("give -email, the first administrator's address: nobody can sign in here yet")
		}
	}
	conn := r.eng
	if conn == nil {
		conn = r.suDB
	}
	if conn == nil {
		return nil
	}
	var err error
	r.adminID, err = accountFor(ctx, conn, d.orgID, r.a.email)
	return err
}

// reachSuperuser settles the superuser's connection: the one given, else the
// PostgreSQL on this machine, confirmed at a terminal, else one typed there.
func (r *setupRun) reachSuperuser(ctx context.Context) error {
	given, err := superuserFromFlags(r.f)
	if err != nil {
		return err
	}
	if given != nil {
		return r.trySuperuser(ctx, given)
	}
	local := localPostgres(r.h)
	if local != nil {
		conn, err := connectAs(ctx, local.cfg, "")
		if err == nil {
			ok := true
			if r.ask != nil {
				ok, err = r.ask.confirm(fmt.Sprintf("Use the PostgreSQL %s on this machine?", serverVersion(ctx, conn)),
					"Used once, "+local.as+"; nothing of it is kept.", true)
				if err != nil {
					_ = conn.Close(ctx)
					return err
				}
			}
			if ok {
				r.su, r.suConn = local, conn
				return nil
			}
			_ = conn.Close(ctx)
		} else if r.ask == nil {
			return fmt.Errorf("give -superuser-dsn (or -superuser-dsn-file) for a role that may create roles: "+
				"the PostgreSQL on this machine did not let setup in %s: %w", local.desc, err)
		} else {
			fmt.Fprintf(r.out, "\n  The PostgreSQL on this machine did not let setup in %s:\n  %v\n", local.desc, err)
		}
	}
	if r.ask == nil {
		return errors.New("give -superuser-dsn (or -superuser-dsn-file) for a role that may create roles: " +
			"there is no PostgreSQL on this machine, no socket in /var/run/postgresql or /tmp and nothing on " +
			"127.0.0.1:5432. Install PostgreSQL 16 or newer, or name one elsewhere")
	}
	typed, err := r.ask.ask("A PostgreSQL URL for a role that may create roles",
		"Used once, never stored: e.g. postgres://postgres@db.example.com/postgres", "", validSuperuserURL)
	if err != nil {
		return err
	}
	u, err := url.Parse(typed)
	if err != nil {
		return err
	}
	su, err := superuserFromURL(u)
	if err != nil {
		return err
	}
	return r.trySuperuser(ctx, su)
}

// trySuperuser connects as su, asking at a terminal for a password the
// server wants and was not given.
func (r *setupRun) trySuperuser(ctx context.Context, su *pgSuperuser) error {
	// Its own database for the server-wide work, which is not the one being
	// set up: that may not exist yet.
	if su.cfg.Database == "" || su.cfg.Database == r.a.database {
		su.cfg.Database = "postgres"
	}
	for tries := 0; ; tries++ {
		conn, err := connectAs(ctx, su.cfg, "")
		if err == nil {
			r.su, r.suConn = su, conn
			return nil
		}
		if r.ask == nil || pgCode(err) != "28P01" || tries == 3 {
			return fmt.Errorf("connecting to PostgreSQL %s: %w", su.desc, err)
		}
		pw, perr := r.ask.secret("Password for "+su.cfg.User+" at "+su.cfg.Host,
			"Read without echo, used once and never stored. PGPASSWORD works too.")
		if perr != nil {
			return perr
		}
		su.cfg.Password = pw
	}
}

func serverVersion(ctx context.Context, conn *pgx.Conn) string {
	var v string
	_ = conn.QueryRow(ctx, `SELECT split_part(current_setting('server_version'), ' ', 1)`).Scan(&v)
	return v
}

// inspectServer reads the server through the superuser and refuses one setup
// cannot use.
func (r *setupRun) inspectServer(ctx context.Context) error {
	var err error
	if r.pg, err = readPGFacts(ctx, r.suConn, r.a.database); err != nil {
		return err
	}
	if major := r.pg.versionNum / 10000; major < migrate.MinServerMajor {
		return fmt.Errorf("PostgreSQL %s is older than %d, the oldest this release runs on: install %d or "+
			"newer (on Debian or Ubuntu before 24.04, from apt.postgresql.org), then run setup again",
			r.pg.version, migrate.MinServerMajor, migrate.MinServerMajor)
	}
	if !r.pg.superuser {
		return fmt.Errorf("%s is not a superuser. Migration 0001 creates signari_engine, signari_admin and "+
			"signari_maintenance, which bypasses row-level security, and hands schemas to them, all of which "+
			"PostgreSQL leaves to a superuser: give -superuser-dsn one, such as postgres", r.pg.user)
	}
	if r.pg.dbExists && !r.engineWorked {
		if r.suDB, err = connectAs(ctx, r.su.cfg, r.a.database); err != nil {
			return fmt.Errorf("connecting to %s as %s: %w", r.a.database, r.pg.user, err)
		}
		if r.db, err = readDBFacts(ctx, r.suDB, r.a.issuer); err != nil {
			return err
		}
	}
	if r.engineDSN == "" {
		r.password = rand.Text()
		r.engineDSN = engineDSN(r.su, r.pg.port, r.a.database, r.password)
		_, _, _, r.engineHost, _ = dsnParts(r.engineDSN)
	}
	r.passwordOK = r.pg.roleExists && scramVerifierHolds(r.pg.roleVerifier, r.password)
	return nil
}

// refuseWhatWouldFail is every check a step would otherwise fail on part way,
// run before any step.
func (r *setupRun) refuseWhatWouldFail(ctx context.Context) error {
	d := r.db
	if !r.keyExists && d.sealed {
		return fmt.Errorf("the database %s already holds signing keys sealed under a root key, and %s is not "+
			"there: a new key would open none of them. Put the original back at that path, or name it with "+
			"-root-key-file", r.a.database, r.a.rootKeyFile)
	}
	if d.instanceID == "" && len(d.issuers) > 0 {
		return fmt.Errorf("the database %s already holds %s, and setup sets up one deployment in a database: "+
			"give that issuer with -issuer, or another -database", r.a.database, strings.Join(d.issuers, ", "))
	}
	if r.keyExists && d.instanceID != "" && d.signing > 0 {
		root, err := loadRootKeyFile(r.a.rootKeyFile)
		if err != nil {
			return err
		}
		conn := r.eng
		if conn == nil {
			conn = r.suDB
		}
		if conn != nil {
			if err := rootKeyOpens(ctx, conn, d.instanceID, root); err != nil {
				return fmt.Errorf("the root key in %s does not open the signing keys of %s: %w. Name the key "+
					"they were sealed under with -root-key-file", r.a.rootKeyFile, r.a.issuer, err)
			}
		}
	}
	if r.suConn == nil || r.engineWorked {
		return nil
	}
	if r.pg.roleSuper || r.pg.roleBypass {
		return fmt.Errorf("%s is a superuser or may bypass row-level security, so the policies would bind nothing "+
			"it does: ALTER ROLE %s NOSUPERUSER NOBYPASSRLS, then run setup again", engineRole, engineRole)
	}
	if !r.passwordOK && r.pg.roleVerifier != "" && len(r.pg.roleElsewhere) > 0 {
		return fmt.Errorf("%s already has a password, and the database(s) %s use the role, so a new one would "+
			"lock that deployment out of its database. Copy SIGNARI_DSN from that deployment's env file into "+
			"%s, with the database changed to %s, and run setup again; or set this one up on another PostgreSQL",
			engineRole, strings.Join(r.pg.roleElsewhere, ", "), r.a.envFile, r.a.database)
	}
	if ip, err := netip.ParseAddr(r.engineHost); err == nil && ip.IsLoopback() {
		if v, rule := judgeHBA(r.pg.hba, r.a.database, engineRole, ip); v == hbaRefused {
			return fmt.Errorf("PostgreSQL would turn %s away over TCP, so serve could not sign in: %s",
				engineRole, hbaAdvice(r.a.database, r.pg.hbaFile, rule))
		}
	}
	return nil
}

// plan lays out the steps, each skipped when what it makes is there.
func (r *setupRun) plan() {
	d, a := r.db, r.a
	dbThere := r.pg.dbExists || r.engineWorked
	suName := r.pg.user
	if suName == "" {
		suName = "the superuser"
	}
	r.steps = []setupStep{
		{name: "database", what: "create the database " + a.database, run: r.createDatabase,
			skip: when(dbThere, "it is there")},
		{name: "schema", what: "apply migration 0001, roles, schemas and grants, as " + suName,
			run: r.applyBootstrapSchema, skip: when(d.applied >= 1, "applied")},
		{name: "root-key", what: "generate the root key into " + a.rootKeyFile, run: r.writeRootKey,
			skip: when(r.keyExists, "it is there")},
		{name: "env-file", what: "write the env file " + a.envFile, run: r.writeEnvFile,
			skip: when(r.envComplete(), "it holds every setting")},
		{name: "engine-role", what: "give " + engineRole + " the env file's password, and sign in with it over TCP",
			run: r.setPasswordAndProve, skip: when(r.engineWorked, "the env file's password signs in")},
		{name: "migrations", what: fmt.Sprintf("apply migrations %04d to %04d as %s", max(d.applied+1, 2),
			r.latest, engineRole), run: r.migrateCore,
			skip: when(d.applied >= r.latest, fmt.Sprintf("the schema is at %04d", d.applied))},
		{name: "first-admin", what: "create the instance, its organisation and the first admin's link",
			run: r.firstAdmin, skip: r.firstAdminSkip()},
		{name: "owner", what: "make " + r.adminName() + " the organisation's owner, " + ownerRole, run: r.grantOwner,
			skip: when(d.owners > 0, "the organisation has an owner"), wait: when(d.owners == 0 && r.adminID == "",
				ownerWait)},
	}
	for i := range r.steps {
		r.steps[i].state = "planned"
	}
}

// ownerWait is why the owner's step waits: a role is held by an account, and
// the first administrator has none until they use their link.
const ownerWait = "they have no account until they set a password with the link; run setup again then"

func (r *setupRun) adminName() string {
	if r.a.email == "" {
		return "the first administrator"
	}
	return r.a.email
}

func when(cond bool, why string) string {
	if cond {
		return why
	}
	return ""
}

// envComplete says whether the env file holds every setting setup writes.
func (r *setupRun) envComplete() bool {
	if !r.prior.exists {
		return false
	}
	for _, k := range envKeys {
		if _, ok := r.prior.values[k]; !ok {
			return false
		}
	}
	return true
}

func (r *setupRun) firstAdminSkip() string {
	d := r.db
	switch {
	case !d.firstAdminDone(r.h.now()):
		return ""
	case d.peopled:
		return "people are signing in here, so no link is needed"
	}
	return fmt.Sprintf("a link for %s is open until %s; it is stored hashed and cannot be shown again, and "+
		"signari bootstrap makes another", d.linkEmail, d.linkUntil.UTC().Format("2 Jan 2006 15:04 UTC"))
}

// envValues are the settings setup writes to the env file.
func (r *setupRun) envValues() map[string]string {
	return map[string]string{"SIGNARI_DSN": r.engineDSN, "SIGNARI_ROOT_KEY_FILE": r.a.rootKeyFile,
		"SIGNARI_ISSUER": r.a.issuer, "SIGNARI_ADDR": r.a.addr}
}

func (r *setupRun) printPlan() {
	w := r.out
	from := func(name string) string {
		switch r.a.from[name] {
		case "default":
			if name == "issuer" {
				return "   (worked out here; -issuer to choose)"
			}
			return "   (the default)"
		case "env file":
			return "   (from the env file)"
		}
		return ""
	}
	pgLine := "not reached"
	switch {
	case r.suConn != nil:
		pgLine = fmt.Sprintf("PostgreSQL %s, %s", r.pg.version, r.su.desc)
	case r.engineWorked:
		pgLine = fmt.Sprintf("PostgreSQL %s, as %s", serverVersion(context.Background(), r.eng), engineRole)
	case r.suErr != nil:
		pgLine = "not reached: " + r.suErr.Error()
	}
	email := r.a.email
	if email == "" {
		email = "-"
		if slices.Contains(r.missing, "email") {
			email = "(give -email)"
		}
	}
	fmt.Fprintf(w, "\n  Plan\n")
	fmt.Fprintf(w, "    %-16s %s%s\n", "address", r.a.issuer, from("issuer"))
	fmt.Fprintf(w, "    %-16s %s\n", "first admin", email)
	fmt.Fprintf(w, "    %-16s %s%s\n", "database", r.a.database, from("database"))
	fmt.Fprintf(w, "    %-16s %s\n", "PostgreSQL", pgLine)
	fmt.Fprintf(w, "    %-16s %s%s\n", "listens on", r.a.addr, from("addr"))
	fmt.Fprintf(w, "    %-16s %s%s\n", "root key", r.a.rootKeyFile, from("root-key-file"))
	fmt.Fprintf(w, "    %-16s %s%s\n", "env file", r.a.envFile, from("env-file"))
	fmt.Fprintf(w, "\n  Steps\n")
	n := 0
	for _, s := range r.steps {
		switch {
		case s.skip != "":
			fmt.Fprintf(w, "    -  %s: already done, %s\n", s.what, s.skip)
		case s.wait != "":
			fmt.Fprintf(w, "    -  %s: waits, as %s\n", s.what, s.wait)
		default:
			n++
			fmt.Fprintf(w, "    %d. %s\n", n, s.what)
		}
	}
}

func (r *setupRun) execute(ctx context.Context) error {
	for i := range r.steps {
		s := &r.steps[i]
		if s.skip != "" {
			s.state = "skipped"
			fmt.Fprintf(r.out, "  [skip] %s: %s\n", s.what, s.skip)
			continue
		}
		err := s.run(ctx)
		if errors.Is(err, errWaiting) {
			if s.wait == "" {
				s.wait = ownerWait
			}
			s.state = "waiting"
			fmt.Fprintf(r.out, "  [wait] %s: %s\n", s.what, s.wait)
			continue
		}
		if err != nil {
			s.state = "failed"
			fmt.Fprintf(r.out, "  [failed] %s\n", s.what)
			return fmt.Errorf("%s: %w", s.what, err)
		}
		s.state = "done"
		fmt.Fprintf(r.out, "  [done] %s\n", s.what)
	}
	if r.eng == nil {
		return nil
	}
	// The record every command that changed something leaves (migration 0140),
	// written only when this run wrote to the database.
	given := make([]string, 0, len(r.f.given))
	for name := range r.f.given {
		given = append(given, name)
	}
	slices.Sort(given)
	if _, err := store.RecordCLICommand(ctx, r.eng, "setup", given, r.db.orgID, cliOperator()); err != nil {
		return fmt.Errorf("setup finished and its audit record could not be written: %w", err)
	}
	return nil
}

// superuserDB is the superuser's connection to the database being set up.
func (r *setupRun) superuserDB(ctx context.Context) (*pgx.Conn, error) {
	if r.suDB != nil {
		return r.suDB, nil
	}
	if r.su == nil {
		return nil, errors.New("no superuser connection, and this step needs one")
	}
	conn, err := connectAs(ctx, r.su.cfg, r.a.database)
	if err != nil {
		return nil, err
	}
	r.suDB = conn
	return conn, nil
}

func (r *setupRun) createDatabase(ctx context.Context) error {
	if _, err := r.suConn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{r.a.database}.Sanitize()); err != nil {
		return err
	}
	r.createdDB = true
	return nil
}

func (r *setupRun) applyBootstrapSchema(ctx context.Context) error {
	conn, err := r.superuserDB(ctx)
	if err != nil {
		return err
	}
	_, err = migrate.Up(ctx, conn, migrate.TierBootstrap, 0, r.migrationOptions())
	return err
}

func (r *setupRun) migrationOptions() migrate.Options {
	return migrate.Options{LockTimeout: 10 * time.Second, Waiting: func() {
		fmt.Fprintln(r.out, "  another migrate is running against this database; waiting for it to finish")
	}}
}

func (r *setupRun) writeRootKey(_ context.Context) error {
	data, err := newRootKeyFile()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(r.a.rootKeyFile, data, true, r.h.euid, &r.madeDirs); err != nil {
		if errors.Is(err, errFileExists) {
			return fmt.Errorf("%s appeared while setup ran; run it again, and it uses that one", r.a.rootKeyFile)
		}
		return err
	}
	r.createdKey, r.rootKeyText = true, strings.TrimSpace(string(data))
	return nil
}

func (r *setupRun) writeEnvFile(_ context.Context) error {
	content, _, err := r.prior.render(r.envValues())
	if err != nil {
		return err
	}
	if r.prior.exists {
		before, err := os.ReadFile(r.prior.path) // #nosec G304 G703 -- the operator names the file
		if err != nil {
			return err
		}
		if err := writeFileAtomic(r.prior.path, []byte(content), false, r.h.euid, &r.madeDirs); err != nil {
			return err
		}
		r.rewroteEnv, r.envBefore = true, before
		return nil
	}
	if err := writeFileAtomic(r.a.envFile, []byte(content), true, r.h.euid, &r.madeDirs); err != nil {
		if errors.Is(err, errFileExists) {
			return fmt.Errorf("%s appeared while setup ran; run it again, and it reads that one", r.a.envFile)
		}
		return err
	}
	r.createdEnv = true
	return nil
}

func (r *setupRun) setPasswordAndProve(ctx context.Context) error {
	if !r.passwordOK {
		if r.suConn == nil {
			return errors.New("no superuser connection, and the env file's password does not sign in")
		}
		verifier, err := scramVerifier(r.password)
		if err != nil {
			return err
		}
		if err := setEnginePassword(ctx, r.suConn, verifier); err != nil {
			return err
		}
		r.passwordSet = true
	}
	cfg, err := pgx.ParseConfig(r.engineDSN)
	if err != nil {
		return err
	}
	conn, err := connectAs(ctx, cfg, "")
	switch {
	case err == nil:
	case authRefused(err):
		ip, _ := netip.ParseAddr(r.engineHost)
		_, rule := judgeHBA(r.pg.hba, r.a.database, engineRole, ip)
		return fmt.Errorf("PostgreSQL turned %s away over TCP (%v): %s", engineRole, err,
			hbaAdvice(r.a.database, r.pg.hbaFile, rule))
	case pgCode(err) == "":
		return fmt.Errorf("nothing let %s in at %s (%v): if PostgreSQL listens on no TCP address, set "+
			"listen_addresses = 'localhost' in postgresql.conf, restart it and run setup again",
			engineRole, r.engineHost, err)
	default:
		return err
	}
	if _, err := conn.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', false)`); err != nil {
		_ = conn.Close(ctx)
		return fmt.Errorf("marking this session as the operator CLI: %w", err)
	}
	if r.eng != nil {
		_ = r.eng.Close(ctx)
	}
	r.eng = conn
	return nil
}

// engine is the engine's connection, marked as the operator CLI's so its
// writes move the configuration version (migration 0139).
func (r *setupRun) engine(ctx context.Context) (*pgx.Conn, error) {
	if r.eng == nil {
		return nil, errors.New("the engine has no connection yet")
	}
	if _, err := r.eng.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', false)`); err != nil {
		return nil, fmt.Errorf("marking this session as the operator CLI: %w", err)
	}
	return r.eng, nil
}

func (r *setupRun) migrateCore(ctx context.Context) error {
	conn, err := r.engine(ctx)
	if err != nil {
		return err
	}
	_, err = migrate.Up(ctx, conn, migrate.TierCore, 0, r.migrationOptions())
	return err
}

func (r *setupRun) firstAdmin(ctx context.Context) error {
	if r.a.email == "" {
		return errors.New("give -email, the first administrator's address: they have no link yet")
	}
	conn, err := r.engine(ctx)
	if err != nil {
		return err
	}
	root, err := loadRootKeyFile(r.a.rootKeyFile)
	if err != nil {
		return err
	}
	r.bootstrapStarted = true
	out, err := bootstrapWith(ctx, conn, root, io.Discard, r.a.issuer, "Default", "default", r.a.email)
	if err != nil {
		return err
	}
	r.db.instanceID, r.db.orgID = out.InstanceID, out.OrgID
	r.link, r.linkExpires = out.Link, out.Expires
	if out.Link == "" {
		r.db.peopled = true
	}
	return nil
}

// grantOwner makes the first administrator the organisation's owner, as
// `signari role grant -role org-owner` does: the first owner is made from the
// command line, and later ones through the Admin API, where an organisation
// can have an owner grant wait for a second person (docs/approvals.md). Only while
// the organisation has no owner, so a run of setup never hands the role to
// anybody else; and only once the person has an account, which the link
// makes, so a run before that waits.
func (r *setupRun) grantOwner(ctx context.Context) error {
	conn, err := r.engine(ctx)
	if err != nil {
		return err
	}
	if r.adminID == "" {
		if r.adminID, err = accountFor(ctx, conn, r.db.orgID, r.a.email); err != nil {
			return err
		}
	}
	if r.adminID == "" {
		return errWaiting
	}
	_, err = store.GrantRole(ctx, conn, store.RoleBinding{OrgID: r.db.orgID, Role: ownerRole, UserID: r.adminID})
	if err != nil && !errors.Is(err, store.ErrRoleHeld) {
		return err
	}
	r.db.owners++
	return nil
}

// undo takes back what a failed run made, in the reverse order, and says what
// it kept and why. Once the first administrator's step has begun, signing keys
// may be sealed under the root key, so the key stays, and the env file and the
// password with it.
func (r *setupRun) undo() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var undone, kept []string
	if r.bootstrapStarted {
		kept = append(kept, "the root key and the env file, since signing keys may already be sealed under the key")
	} else {
		if r.passwordSet && r.su != nil {
			// On a connection of its own: an interrupt that ended the step may
			// have ended the one it used.
			su, err := connectAs(ctx, r.su.cfg, "")
			if err == nil {
				err = setEnginePassword(ctx, su, r.pg.roleVerifier)
				_ = su.Close(ctx)
			}
			if err == nil {
				undone = append(undone, engineRole+"'s password, which is as it was")
			} else {
				kept = append(kept, engineRole+"'s new password, which could not be taken back: "+err.Error())
			}
		}
		if r.createdEnv {
			if err := os.Remove(r.a.envFile); err == nil {
				undone = append(undone, r.a.envFile)
			}
		}
		if r.rewroteEnv {
			if err := writeFileAtomic(r.prior.path, r.envBefore, false, r.h.euid, nil); err == nil {
				undone = append(undone, "the settings added to "+r.prior.path)
			}
		}
		if r.createdKey {
			if err := os.Remove(r.a.rootKeyFile); err == nil {
				undone = append(undone, r.a.rootKeyFile)
			}
		}
		for i := len(r.madeDirs) - 1; i >= 0; i-- {
			if os.Remove(r.madeDirs[i]) == nil {
				undone = append(undone, r.madeDirs[i])
			}
		}
	}
	if r.createdDB {
		kept = append(kept, "the database "+r.a.database+", which this run made and which is never dropped for you")
	}
	if slices.ContainsFunc(r.steps, func(s setupStep) bool {
		return (s.name == "schema" || s.name == "migrations") && (s.state == "done" || s.state == "failed")
	}) {
		kept = append(kept, "the migrations already applied, each in its own transaction")
	}
	if len(undone) > 0 {
		fmt.Fprintf(r.out, "\n  Taken back, as this run made them: %s.\n", strings.Join(undone, "; "))
	}
	if len(kept) > 0 {
		fmt.Fprintf(r.out, "  Kept: %s.\n", strings.Join(kept, "; "))
	}
	fmt.Fprintln(r.out, "  Running setup again goes on from where this stopped.")
}

// startCommand is how to start the engine with what setup wrote.
func (r *setupRun) startCommand() string {
	if r.h.unitInstalled {
		return "systemctl enable --now signari"
	}
	return fmt.Sprintf("set -a; . %s; set +a; signari serve", r.a.envFile)
}

func (r *setupRun) printSummary() {
	w := r.out
	pad := "                 "
	fmt.Fprintf(w, "\n  Signari is set up.\n\n")
	fmt.Fprintf(w, "  %-14s %s\n", "Address", r.a.issuer)
	switch {
	case r.link != "":
		fmt.Fprintf(w, "  %-14s %s finishes setting up here, once, within %d hours:\n\n%s%s\n\n", "First admin",
			r.a.email, int(bootstrapLinkLife.Hours()), pad, r.link)
		fmt.Fprintf(w, "%sIt is stored hashed and cannot be shown again; signari bootstrap\n%smakes another.\n", pad, pad)
	case r.db.peopled:
		fmt.Fprintf(w, "  %-14s people are signing in here already\n", "First admin")
	case r.db.linkEmail != "":
		fmt.Fprintf(w, "  %-14s a link for %s is open until %s\n", "First admin", r.db.linkEmail,
			r.db.linkUntil.UTC().Format("2 Jan 2006 15:04 UTC"))
	}
	switch {
	case r.db.owners > 0 && r.adminID != "":
		fmt.Fprintf(w, "  %-14s %s holds %s: every right in the organisation, in the\n%sconsole and the Admin API.\n",
			"Owner", r.a.email, ownerRole, pad)
	case r.db.owners > 0:
		fmt.Fprintf(w, "  %-14s the organisation has one\n", "Owner")
	case r.db.orgID != "" && r.a.email != "":
		fmt.Fprintf(w, "  %-14s once %s has set a password, run signari setup again:\n%s"+
			"it makes them %s, which the console and the Admin API read\n%stheir rights from. Or, with the env file loaded:\n%s"+
			"signari role grant -org %s -email %s -role %s\n", "Owner", r.a.email, pad, ownerRole, pad, pad,
			r.db.orgID, r.a.email, ownerRole)
	}
	fmt.Fprintf(w, "  %-14s %s\n", "Root key", r.a.rootKeyFile)
	fmt.Fprintf(w, "%sCopy it off this machine now, to wherever you keep secrets.\n", pad)
	fmt.Fprintf(w, "%sSignari keeps no other copy: without it the signing keys and every\n", pad)
	fmt.Fprintf(w, "%ssealed secret are lost, whatever database backup you hold.\n", pad)
	if r.f.printRootKey {
		if key := r.rootKey(); key != "" {
			fmt.Fprintf(w, "%sThe key, as -print-root-key asked: %s\n", pad, key)
		}
	}
	fmt.Fprintf(w, "  %-14s %s, which holds the engine's database\n%spassword: keep it 0600.\n", "Env file", r.a.envFile, pad)
	fmt.Fprintf(w, "\n  %-14s %s\n", "Start it", r.startCommand())
	fmt.Fprintf(w, "  %-14s set -a; . %s; set +a; signari doctor\n", "Check it", r.a.envFile)
	if u, err := url.Parse(r.a.issuer); err == nil && u.Scheme == "https" {
		fmt.Fprintf(w, "  %-14s it listens on %s in plain HTTP: put a proxy that ends TLS for\n%s%s in front, and add\n%s"+
			"SIGNARI_TRUSTED_PROXIES and SIGNARI_CLIENT_IP_SOURCE to the env\n%sfile (docs/configuration.md, behind a reverse proxy).\n",
			"Behind TLS", r.a.addr, pad, u.Host, pad, pad)
	}
	if r.h.unitInstalled {
		fmt.Fprintf(w, "  %-14s systemctl disable --now signari, then delete %s,\n%s%s, and the binary, %s.\n",
			"Remove it", unitPath, pad, r.a.envFile, binaryPath())
	} else {
		fmt.Fprintf(w, "  %-14s stop signari serve, then delete %s and the binary,\n%s%s.\n", "Remove it",
			r.a.envFile, pad, binaryPath())
	}
	fmt.Fprintf(w, "%sThe root key and the database %s are never deleted for you:\n", pad, r.a.database)
	fmt.Fprintf(w, "%sonce you are sure, DROP DATABASE %s and delete %s.\n\n", pad, r.a.database, r.a.rootKeyFile)
}

// binaryPath is where this binary is, for the summary's way to remove it.
func binaryPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "wherever this binary is"
}

// rootKey is the root key's text, for -print-root-key.
func (r *setupRun) rootKey() string {
	if r.rootKeyText != "" {
		return r.rootKeyText
	}
	b, err := os.ReadFile(r.a.rootKeyFile) // #nosec G304 G703 -- the operator names the file
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// setupResult is the line -json prints.
type setupResult struct {
	OK          bool              `json:"ok"`
	DryRun      bool              `json:"dry_run,omitempty"`
	Issuer      string            `json:"issuer,omitempty"`
	Email       string            `json:"email,omitempty"`
	Database    string            `json:"database,omitempty"`
	Addr        string            `json:"addr,omitempty"`
	RootKeyFile string            `json:"root_key_file,omitempty"`
	EnvFile     string            `json:"env_file,omitempty"`
	Link        string            `json:"link,omitempty"`
	LinkExpires *time.Time        `json:"link_expires,omitempty"`
	RootKey     string            `json:"root_key,omitempty"`
	Start       string            `json:"start,omitempty"`
	Steps       []setupResultStep `json:"steps"`
	Missing     []string          `json:"missing,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type setupResultStep struct {
	Step   string `json:"step"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

func (r *setupRun) result(err error) setupResult {
	res := setupResult{OK: err == nil, DryRun: r.f.dryRun, Issuer: r.a.issuer, Email: r.a.email,
		Database: r.a.database, Addr: r.a.addr, RootKeyFile: r.a.rootKeyFile, EnvFile: r.a.envFile,
		Link: r.link, Steps: []setupResultStep{}}
	for _, m := range r.missing {
		res.Missing = append(res.Missing, "-"+m)
	}
	if !r.linkExpires.IsZero() {
		t := r.linkExpires.UTC()
		res.LinkExpires = &t
	}
	if err == nil && !r.f.dryRun {
		res.Start = r.startCommand()
		if r.f.printRootKey {
			res.RootKey = r.rootKey()
		}
	}
	for _, s := range r.steps {
		detail := s.what
		if s.skip != "" {
			detail += ": " + s.skip
		}
		res.Steps = append(res.Steps, setupResultStep{Step: s.name, State: s.state, Detail: detail})
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// errIncomplete is `setup -check` finding something missing, which exits 2,
// as a check that could not be made exits 1.
var errIncomplete = errors.New("setup is not complete here")

// checkItem is one line of `setup -check`.
type checkItem struct {
	What string `json:"what"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"`
}

// setupCheck is `signari setup -check`: what is set up and what is missing,
// read from the env file and through the engine's own connection, needing no
// superuser. It exits 0 when all of it is there, 2 when anything is missing,
// and 1 when it could not tell.
func setupCheck(ctx context.Context, stdout, out io.Writer, h setupHost, f setupFlags) (err error) {
	// With -json, one line whatever happens: a script reads it, and a check
	// that could not be made is an answer too.
	printed := false
	defer func() {
		if f.json && !printed && err != nil && !errors.Is(err, errIncomplete) {
			line, _ := json.Marshal(map[string]any{"complete": false, "error": err.Error()})
			fmt.Fprintln(stdout, string(line))
		}
	}()
	for name := range f.given {
		switch name {
		case "check", "env-file", "json", "timeout":
		default:
			return usageError{fmt.Errorf("-check reads what the env file says, and takes -env-file and -json only, "+
				"not -%s", name)}
		}
	}
	path := f.envFile
	if path == "" {
		path = setupDefault("env-file", h, setupAnswers{})
	}
	if path, err = filepath.Abs(path); err != nil {
		return err
	}
	var items []checkItem
	add := func(ok bool, what, note string) { items = append(items, checkItem{What: what, OK: ok, Note: note}) }
	report := func() error {
		complete := true
		for _, it := range items {
			mark := "[ok]     "
			if !it.OK {
				mark, complete = "[missing]", false
			}
			if it.Note != "" {
				fmt.Fprintf(out, "  %s %s: %s\n", mark, it.What, it.Note)
			} else {
				fmt.Fprintf(out, "  %s %s\n", mark, it.What)
			}
		}
		if f.json {
			line, err := json.Marshal(struct {
				Complete bool        `json:"complete"`
				EnvFile  string      `json:"env_file"`
				Items    []checkItem `json:"items"`
			}{complete, path, items})
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, string(line))
			printed = true
		}
		if !complete {
			return errIncomplete
		}
		fmt.Fprintln(out, "  Signari is set up here.")
		return nil
	}

	env, err := readEnvFile(path)
	if err != nil {
		return err
	}
	if !env.exists {
		add(false, "env file "+path, "there is none: setup has not run here, or wrote it elsewhere (-env-file)")
		return report()
	}
	var absent []string
	for _, k := range envKeys {
		if env.values[k] == "" {
			absent = append(absent, k)
		}
	}
	add(len(absent) == 0, "env file "+path, when(len(absent) > 0, "it lacks "+strings.Join(absent, ", ")))
	keyPath := env.values["SIGNARI_ROOT_KEY_FILE"]
	var root *keys.RootKey
	if keyPath != "" {
		exists, kerr := rootKeyFileState(keyPath)
		switch {
		case kerr != nil:
			add(false, "root key "+keyPath, kerr.Error())
		case !exists:
			add(false, "root key "+keyPath, "there is no file there")
		default:
			if root, kerr = loadRootKeyFile(keyPath); kerr != nil {
				return kerr
			}
			add(true, "root key "+keyPath, "")
		}
	}
	dsn := env.values["SIGNARI_DSN"]
	if dsn == "" {
		return report()
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("%s: SIGNARI_DSN: %w", path, err)
	}
	conn, err := connectAs(ctx, cfg, "")
	switch {
	case authRefused(err):
		add(false, "the engine's sign-in", "PostgreSQL turned it away ("+err.Error()+"); run signari setup again")
		return report()
	case pgCode(err) == "3D000":
		add(false, "the database", "it does not exist; run signari setup again")
		return report()
	case err != nil:
		return fmt.Errorf("could not reach PostgreSQL to check: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	session, current, privileged, err := roleAttrs(ctx, conn)
	if err != nil {
		return err
	}
	add(!privileged, "the engine signs in as "+session, when(privileged,
		"it, or "+current+", is a superuser or may bypass row-level security"))
	if err := migrate.Verify(ctx, conn); err != nil {
		add(false, "the schema", err.Error())
		return report()
	}
	add(true, "the schema, as this binary expects it", "")
	issuer := env.values["SIGNARI_ISSUER"]
	d, err := readDBFacts(ctx, conn, issuer)
	if err != nil {
		return err
	}
	switch {
	case d.instanceID == "":
		add(false, "the instance "+issuer, "there is none; run signari setup again")
	case d.signing < 2:
		add(false, "the instance "+issuer, "its signing keys are missing; run signari setup again")
	default:
		note := ""
		if root != nil {
			if err := rootKeyOpens(ctx, conn, d.instanceID, root); err != nil {
				note = "the root key does not open its signing keys: " + err.Error()
			}
		}
		add(note == "", "the instance "+issuer+", with its signing keys", note)
	}
	switch {
	case d.orgID == "":
		add(false, "an organisation", "there is none; run signari setup again")
	case d.peopled:
		add(true, "the first administrator, who has signed in", "")
	case d.linkUntil.After(h.now()):
		add(true, "the first administrator's link, open until "+d.linkUntil.UTC().Format("2 Jan 2006 15:04 UTC"), "")
	default:
		add(false, "the first administrator", "nobody has signed in and no link is open; "+
			"signari bootstrap, with the env file loaded, makes one")
	}
	if d.orgID != "" {
		add(d.owners > 0, "an owner, holding "+ownerRole, when(d.owners == 0,
			"nobody holds it; once the first administrator has set a password, run signari setup again"))
	}
	return report()
}
