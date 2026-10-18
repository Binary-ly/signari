package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every in-process cache of database configuration must be declared.
//
// # What went wrong
//
// ADR-008 described a configuration bus: `pg_notify` carrying `(kind, id,
// version)`, nodes holding a `LISTEN`, an unconditional 5-15s poll, a full
// reload on reconnect, 0-9s of jitter, and "exactly one code path that loads
// config". Measured against the tree, the count of `pg_notify` was zero, of
// `LISTEN` zero, of config pollers zero, and the one code path was three.
//
// Only the first sentence was true -- every mutation does bump
// `core.config_version` in the same transaction -- and it is true for a
// different reason than the ADR gave: the counter is what the admin API's
// `If-Match` preconditions compare against.
//
// The bus was never needed, because ADR-007 designed the problem away. Nothing
// security-negative is cached, so there is no snapshot to invalidate.
//
// # Why a test rather than a corrected paragraph
//
// The paragraph was wrong for long enough to be quoted, and the way it got
// there is ordinary: it described an intention, the intention was overtaken by
// ADR-007, and nothing failed. Replacing it with a truer paragraph reproduces
// exactly that setup.
//
// So the durable part is this list. Three consumers cache configuration and
// each refreshes on its own timer; a fourth added later inherits none of that
// reasoning and would silently widen the window in which a node acts on
// configuration an administrator has already changed. When this test fails,
// the answer is not to add the name -- it is to decide whether the new cache
// may hold security-relevant state at all, and only then to record its delay.
//
// Split from `mutation_test.go`'s drift list on purpose: that one guards the
// WRITE side, this one the READ side, and they fail for different reasons.

// declaredCache is one place the engine holds configuration in memory.
type declaredCache struct {
	symbol string
	// delays is whether it introduces a window in which the process acts on
	// configuration the database has already changed. A cache that re-reads its
	// source on every call and only avoids re-allocating does not.
	delays bool
	why    string
}

var declaredCaches = []declaredCache{
	{
		symbol: "originsCache",
		delays: true,
		why: "CORS origins, one-minute TTL. The only cached value with a " +
			"security edge: a deregistered SPA's origin stays allowed for up " +
			"to a minute. Bounded, and it widens what a browser may READ, " +
			"never what it may DO.",
	},
	{
		symbol: "jwksCache",
		delays: false,
		why: "jwksBody calls MarshalJWKS on every request and uses the cache " +
			"only to hand back one allocation when the ETag is unchanged. " +
			"Never stale, so it carries no propagation delay.",
	},
	{
		symbol: "ssfKeys",
		delays: false,
		why: "Remote transmitters' signing keys, not this deployment's " +
			"configuration. Fetched over HTTP and cached to keep an outbound " +
			"request off the request path.",
	},
	{
		symbol: "assertionKeys",
		delays: false,
		why: "Trusted issuers' signing keys for the RFC 7523 jwt-bearer grant. " +
			"Remote, same reasoning as ssfKeys.",
	},
	{
		symbol: "policies",
		delays: false,
		why: "Access policies, memoised by the digest of each organisation's " +
			"document. The digest is read on every decision, so a new rule -- " +
			"a deny rule included -- applies on the next request. It was a " +
			"thirty-second reload until 1.10, invisible to this test because " +
			"the field is not called anything-cache.",
	},
	{
		symbol: "flows",
		delays: true,
		why: "Sign-in flows, refreshed every thirty seconds and served stale " +
			"while one goroutine reloads: a synchronous reload inside " +
			"completeSignIn's transaction deadlocked the pool under load " +
			"(flowdrive.go). A flow change takes up to that long per node.",
	},
}

// timeHeldButNotConfiguration are Server fields that keep a time, which is
// how timeBoundFields finds a cache, and hold nothing an administrator
// configures in the database. Each says what it holds instead; a field must
// still exist to stay here.
var timeHeldButNotConfiguration = map[string]string{
	"jwks":       "a rate-limit bucket: request counts per window, not configuration",
	"login":      "a rate-limit bucket: request counts per window, not configuration",
	"device":     "a rate-limit bucket: request counts per window, not configuration",
	"register":   "a rate-limit bucket: request counts per window, not configuration",
	"federation": "a rate-limit bucket: request counts per window, not configuration",
	"captcha": "the captcha verifier, configured from the environment at startup; " +
		"its time is a request timeout, and it reads nothing from the database",
	"pwPolicy": "the password policy, configured from the environment at startup; " +
		"its times are rules, not the age of anything held",
	"originsExpire": "the expiry of originsCache, declared with it",
}

// serverField is one line of the Server struct: a field name and its type.
var serverField = regexp.MustCompile(`^\t([a-zA-Z][A-Za-z0-9]*)\s+([^/]+?)\s*(//.*)?$`)

// cacheFields returns the fields of httpapi's Server whose NAME OR TYPE says
// they cache. By type as well as by name: the access policy cache was a field
// called `policies` of type *policyCache, and a guard that read field names
// alone could not see it.
func cacheFields(src string) []string {
	start := strings.Index(src, "type Server struct {")
	if start < 0 {
		return nil
	}
	body := src[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		m := serverField.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.Contains(strings.ToLower(m[1]+" "+m[2]), "cache") {
			out = append(out, m[1])
		}
	}
	return out
}

// timeBoundFields returns the Server fields whose type, followed into this
// package or any other engine package, is a struct that keeps a time.Time or
// a time.Duration: something held now and judged by when it was got. That is
// what a cache is, whatever it is called. `ssfKeys` is a *ssf.KeyFetcher, a
// cache named for neither, and the name-and-type match could see it only
// through an exception written for it by hand.
func timeBoundFields(t *testing.T, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	parsed := map[string][]*ast.File{}
	load := func(dir string) []*ast.File {
		if fs, ok := parsed[dir]; ok {
			return fs
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			parsed[dir] = nil
			return nil
		}
		var files []*ast.File
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
			if perr != nil {
				t.Fatal(perr)
			}
			files = append(files, f)
		}
		parsed[dir] = files
		return files
	}
	engine := filepath.Join(root, "engine")
	dirOf := func(f *ast.File, alias string) string {
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name == alias && strings.HasPrefix(p, "signari.dev/engine/") {
				return filepath.Join(engine, strings.TrimPrefix(p, "signari.dev/engine/"))
			}
		}
		return ""
	}
	find := func(dir, name string) (*ast.StructType, *ast.File) {
		for _, f := range load(dir) {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, s := range gd.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == name {
						st, _ := ts.Type.(*ast.StructType)
						return st, f
					}
				}
			}
		}
		return nil, nil
	}
	var holdsTime func(dir string, file *ast.File, expr ast.Expr, depth int) bool
	holdsTime = func(dir string, file *ast.File, expr ast.Expr, depth int) bool {
		if depth > 3 {
			return false
		}
		switch e := expr.(type) {
		case *ast.StarExpr:
			return holdsTime(dir, file, e.X, depth)
		case *ast.ArrayType:
			return holdsTime(dir, file, e.Elt, depth)
		case *ast.MapType:
			return holdsTime(dir, file, e.Value, depth)
		case *ast.SelectorExpr:
			x, ok := e.X.(*ast.Ident)
			if !ok {
				return false
			}
			if x.Name == "time" {
				return e.Sel.Name == "Time" || e.Sel.Name == "Duration"
			}
			if d := dirOf(file, x.Name); d != "" {
				if st, f := find(d, e.Sel.Name); st != nil {
					return structHoldsTime(st, func(fe ast.Expr) bool { return holdsTime(d, f, fe, depth+1) })
				}
			}
		case *ast.Ident:
			if st, f := find(dir, e.Name); st != nil {
				return structHoldsTime(st, func(fe ast.Expr) bool { return holdsTime(dir, f, fe, depth+1) })
			}
		}
		return false
	}

	httpapi := filepath.Join(engine, "internal", "httpapi")
	server, file := find(httpapi, "Server")
	if server == nil {
		t.Fatal("httpapi has no Server struct")
	}
	var out []string
	for _, fld := range server.Fields.List {
		if holdsTime(httpapi, file, fld.Type, 0) {
			for _, n := range fld.Names {
				out = append(out, n.Name)
			}
		}
	}
	return out
}

func structHoldsTime(st *ast.StructType, check func(ast.Expr) bool) bool {
	for _, f := range st.Fields.List {
		if check(f.Type) {
			return true
		}
	}
	return false
}

func TestEveryConfigConsumerThatCachesIsDeclared(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "engine", "internal", "httpapi", "server.go"))
	if err != nil {
		t.Fatal(err)
	}

	declared := map[string]bool{}
	for _, c := range declaredCaches {
		declared[c.symbol] = true
	}

	found := cacheFields(string(src))
	if len(found) < 3 {
		t.Fatalf("found only %v caching fields on Server; the struct is not being read", found)
	}
	timed := timeBoundFields(t, root)
	for _, name := range timed {
		if timeHeldButNotConfiguration[name] == "" && !slices.Contains(found, name) {
			found = append(found, name)
		}
	}
	for name := range timeHeldButNotConfiguration {
		if !slices.Contains(timed, name) {
			t.Errorf("timeHeldButNotConfiguration names %q, which no Server field "+
				"holding a time is called any more; remove it", name)
		}
	}
	seen := map[string]bool{}
	for _, name := range found {
		seen[name] = true
		if !declared[name] {
			t.Errorf("%s caches state on the Server and is not declared in "+
				"declaredCaches. Decide first whether it may hold "+
				"security-relevant configuration at all -- ADR-007 says a "+
				"security-negative answer is never cached -- and if it may "+
				"not, that is the bug. If it may, declare it with its "+
				"refresh interval and add a row to the ADR-008 table.", name)
		}
	}

	// Both directions, like every other docsync test. A declared cache that has
	// been deleted leaves a note describing a delay the system no longer has,
	// which is the same class of wrongness this file exists to stop.
	for _, c := range declaredCaches {
		if !seen[c.symbol] {
			t.Errorf("declaredCaches names %q, which no longer exists in "+
				"httpapi/server.go", c.symbol)
		}
	}
}

// A ticker-driven reload in the entrypoint is a config consumer too.
//
// These are the ones that exist because something did NOT propagate: the RADIUS
// loop was added after disabling an access point turned out to do nothing until
// a restart. A new one appearing means another consumer has discovered the same
// gap independently, which is the moment to ask whether the general mechanism
// is finally worth building rather than to add a fourth interval.
func TestEveryReloadLoopInTheEntrypointIsAccountedFor(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "engine", "cmd", "signari", "main.go"))
	if err != nil {
		t.Fatal(err)
	}

	const expected = 2 // signing keys, RADIUS clients
	got := strings.Count(string(src), "time.NewTicker")
	if got != expected {
		t.Errorf("cmd/signari/main.go starts %d ticker loops; %d are accounted "+
			"for (signing keys, RADIUS clients). A new one is a third consumer "+
			"polling on its own interval. Record what it reloads and how stale "+
			"it may be in the ADR-008 table, or make the case that the config "+
			"bus ADR-008 describes should finally be built.", got, expected)
	}
}

// The ADR must not describe the bus as though it exists.
//
// Skipped rather than failed when the file is absent: docs/adr/README.md is
// local-only (.git/info/exclude), so it is not in a clone, and a committed test
// that required it would pass here and fail for everyone else -- the exact trap
// CLAUDE.md warns about for links.
func TestTheConfigBusIsNotDescribedAsBuilt(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "docs", "adr", "README.md")
	src, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("docs/adr/README.md is local-only and absent from this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	// The engine must not have grown the mechanism without the ADR being
	// rewritten again -- checked from the code side, so the two cannot drift
	// apart in either direction.
	engineSrc, err := os.ReadFile(filepath.Join(root, "engine", "internal",
		"adminapi", "server.go"))
	if err != nil {
		t.Fatal(err)
	}
	built := strings.Contains(string(engineSrc), "pg_notify")

	claims := strings.Contains(body, "fires `pg_notify`") ||
		strings.Contains(body, "Engine nodes `LISTEN`")
	if claims && !built {
		t.Error("ADR-008 describes a pg_notify/LISTEN config bus. There is no " +
			"pg_notify anywhere in the engine. Either the ADR is wrong again, " +
			"or the bus was built and this test needs updating.")
	}
	if built && !claims {
		t.Error("the engine now uses pg_notify but ADR-008 no longer claims a " +
			"bus. If it has been built, the ADR should say so.")
	}
}
