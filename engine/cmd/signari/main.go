// Command signari is the engine's operator CLI.
//
//	signari migrate bootstrap   roles, schemas, grants  (requires superuser)
//	signari migrate up          tables, policies, views (runs as signari_engine)
//	signari migrate status      what the database is at, and what this binary expects
//	signari verify              the startup gate, runnable on its own
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/adminapi"
	"signari.dev/engine/internal/doctor"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/httpapi"
	"signari.dev/engine/internal/importer"
	"signari.dev/engine/internal/janitor"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/policy"
	"signari.dev/engine/internal/proxycheck"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "signari: %v\n", err)
		os.Exit(1)
	}
}

func usage() error {
	fmt.Fprint(os.Stderr, `usage: signari <command> [flags]

commands:
  migrate bootstrap   apply 0001 (roles, schemas, grants) -- needs a superuser DSN
  migrate up          apply 0002+ (tables, policies, views) as signari_engine
  migrate all         bootstrap then up, in one invocation (for containers)
  migrate status      show applied version, pending migrations, live fingerprint
  verify              run the startup schema gate and exit
  instance create     create an instance and its first signing keys
  user create         create a user with a password
  client create       register an OAuth client
  client set-keys     switch a client to private_key_jwt with its public JWKS
  janitor once        run one maintenance pass (serve runs this continuously)
  import keycloak     import users and clients from a Keycloak realm export
  keys list           show signing keys, their state and when each may advance
  keys rotate         advance the rotation one safe step (run it again later)
  proxy check         prove a forward-auth deployment actually protects the app
  saml add-sp         register a SAML service provider
  saml list           show registered SAML service providers
  idp add             register an external sign-in provider (Google, GitHub, ...)
  idp list            show external sign-in providers
  scim add            register a SCIM provisioning target
  scim list           show provisioning targets
  scim sync           converge targets on this directory (preview unless -apply)
  scim verify         read each target back and report anyone still active
  group create        create a group
  group member        add or remove a member (-remove)
  group release       let a client see group membership
  group list          show groups and their sizes
  policy test         check a policy file (no database needed -- for CI)
  policy apply        install a policy file
  policy show         print the policy in force
  serve               serve the OIDC endpoints

env:
  SIGNARI_ROOT_KEY        base64 of 32 random bytes; wraps stored private key material

flags:
  -dsn string   PostgreSQL connection string (or set SIGNARI_DSN)
  -to int       stop at this version instead of the latest
`)
	return fmt.Errorf("no command given")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	fs := flag.NewFlagSet("signari", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("SIGNARI_DSN"), "PostgreSQL connection string")
	to := fs.Int("to", 0, "stop at this version (0 = latest)")
	issuer := fs.String("issuer", "", "issuer URL, e.g. https://id.example.com")
	name := fs.String("name", "", "instance display name")
	addr := fs.String("addr", ":8080", "listen address for `serve`")
	tlsCert := fs.String("tls-cert", os.Getenv("SIGNARI_TLS_CERT"), "PEM certificate chain; enables HTTPS")
	tlsKey := fs.String("tls-key", os.Getenv("SIGNARI_TLS_KEY"), "PEM private key")
	adminAddr := fs.String("admin-addr", os.Getenv("SIGNARI_ADMIN_ADDR"), "listen address for the admin API (empty = disabled)")
	email := fs.String("email", "", "user email")
	password := fs.String("password", "", "user password")
	clientID := fs.String("client-id", "", "OAuth client_id (settable verbatim, for migration)")
	redirect := fs.String("redirect", "", "registered redirect_uri (exact match)")
	public := fs.Bool("public", false, "register a public client (PKCE, no secret)")
	file := fs.String("file", "", "path to a realm export (import)")
	orgID := fs.String("org", "", "organisation uuid to import into")
	dryRun := fs.Bool("dry-run", false, "report what would be imported and change nothing")
	alg := fs.String("alg", "", "restrict `keys rotate` to one algorithm (default: all in use)")
	promoteNow := fs.Bool("now", false, "promote without waiting for the publication dwell -- key compromise only")
	appURL := fs.String("app", "", "protected application URL, as the browser reaches it (proxy check)")
	origin := fs.String("origin", "", "the application's own address, to test the bypass (proxy check)")
	probePath := fs.String("path", "", "extra path to probe, repeatable as a comma-separated list (proxy check)")
	insecure := fs.Bool("insecure", false, "skip certificate verification (internal CA or self-signed only)")
	entityID := fs.String("entity-id", "", "the service provider's SAML EntityID")
	acsURL := fs.String("acs", "", "AssertionConsumerService URL, matched exactly (https only)")
	nameIDFormat := fs.String("nameid-format", "persistent", "persistent (pairwise), emailAddress or transient")
	sloURL := fs.String("slo", "", "the provider's SingleLogoutService URL (https)")
	spCert := fs.String("sp-cert", "", "path to the provider's signing certificate (PEM), required for single logout")
	slug := fs.String("slug", "", "short name used in /login/with/<slug>")
	kind := fs.String("kind", "oidc", "oidc, google, github or microsoft")
	extClientID := fs.String("client-id-ext", "", "client id issued by the external provider")
	extSecret := fs.String("client-secret", "", "client secret issued by the external provider")
	allowSignup := fs.Bool("allow-signup", true, "let this provider create new accounts")
	allowLinking := fs.Bool("allow-linking", true, "let users add this provider to an existing account")
	trustEmail := fs.Bool("trust-email-verification", false, "generic OIDC only: believe this provider's email_verified claim")
	baseURL := fs.String("base-url", "", "SCIM base URL of the target application")
	scimToken := fs.String("token", "", "bearer token the SCIM target issued")
	onDeactivate := fs.String("on-deactivate", "deactivate", "deactivate, delete or nothing")
	dryRun2 := fs.Bool("scim-dry-run", false, "register the target in dry-run mode: record, never send")
	groupName := fs.String("group", "", "group name")
	memberEmail := fs.String("email-member", "", "member's email or username")
	removeMember := fs.Bool("remove", false, "remove the member instead of adding")
	policyFile := fs.String("policy-file", "", "path to a policy file")
	jwksPath := fs.String("jwks", "", "file containing the client's PUBLIC JWKS")
	onlyGroups := fs.String("only", "", "comma-separated groups to release (default: all)")
	apply := fs.Bool("apply", false, "actually make changes (scim sync defaults to a preview)")

	cmd := args[0]
	rest := args[1:]
	if cmd == "migrate" || cmd == "instance" || cmd == "user" || cmd == "client" ||
		cmd == "janitor" || cmd == "keys" || cmd == "import" || cmd == "proxy" ||
		cmd == "saml" || cmd == "idp" || cmd == "scim" || cmd == "group" ||
		cmd == "policy" {
		if len(rest) == 0 {
			return usage()
		}
		cmd, rest = cmd+" "+rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	// `policy test` needs no database either: checking a file before it is
	// deployed is something you do in CI, where there is no database to reach.
	if cmd == "policy test" {
		return policyTest(*policyFile)
	}

	// `proxy check` deliberately runs BEFORE the database is required. It is a
	// black-box prober: it must be runnable from a laptop, from CI, or from
	// outside the network entirely -- which is where an attacker sits, and
	// therefore the only place the answer is meaningful. Needing the database
	// would confine it to the one host where the result matters least.
	if cmd == "proxy check" {
		return proxyCheck(*appURL, *issuer, *origin, *probePath, *insecure)
	}

	if *dsn == "" {
		return fmt.Errorf("no -dsn given and SIGNARI_DSN is unset")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	switch cmd {
	case "migrate bootstrap":
		return up(ctx, conn, migrate.TierBootstrap, *to)
	case "migrate up":
		return up(ctx, conn, migrate.TierCore, *to)
	case "migrate all":
		// One command so the container image needs no shell to chain two.
		// The runtime image is distroless -- there is no /bin/sh to fall back on,
		// and adding one to a security product to save a CLI verb is a bad trade.
		if err := up(ctx, conn, migrate.TierBootstrap, *to); err != nil {
			return err
		}
		return up(ctx, conn, migrate.TierCore, *to)
	case "migrate status":
		return status(ctx, conn)
	case "doctor":
		return doctorCmd(ctx, conn, *issuer)
	case "verify":
		if err := migrate.Verify(ctx, conn); err != nil {
			return err
		}
		fmt.Println("schema ok")
		return nil
	case "instance create":
		return instanceCreate(ctx, conn, *issuer, *name)
	case "user create":
		return userCreate(ctx, conn, *email, *password)
	case "client set-keys":
		return clientSetKeys(ctx, conn, *clientID, *jwksPath)
	case "client create":
		return clientCreate(ctx, conn, *clientID, *redirect, *public)
	case "serve":
		return serve(conn, *addr, *tlsCert, *tlsKey, *adminAddr)
	case "janitor once":
		return janitorOnce(ctx, conn)
	case "import keycloak":
		return importKeycloak(ctx, conn, *file, *orgID, *dryRun)
	case "keys list":
		return keysList(ctx, conn)
	case "keys rotate":
		return keysRotate(ctx, conn, *alg, *promoteNow)
	case "saml add-sp":
		return samlAddSP(ctx, conn, *orgID, *entityID, *name, *acsURL, *nameIDFormat, *sloURL, *spCert)
	case "saml list":
		return samlListSPs(ctx, conn)
	case "idp add":
		return idpAdd(ctx, conn, *orgID, *slug, *name, *kind, *extClientID, *extSecret,
			*issuer, *allowSignup, *allowLinking, *trustEmail)
	case "idp list":
		return idpList(ctx, conn)
	case "scim add":
		return scimAdd(ctx, conn, *orgID, *slug, *name, *baseURL, *scimToken, *onDeactivate, *dryRun2)
	case "scim list":
		return scimList(ctx, conn)
	case "scim sync":
		return scimSync(ctx, conn, *slug, *apply)
	case "scim verify":
		return scimVerify(ctx, conn, *slug)
	case "group create":
		return groupCreate(ctx, conn, *orgID, *groupName, *name)
	case "group member":
		return groupMember(ctx, conn, *orgID, *groupName, *memberEmail, *removeMember)
	case "group release":
		return groupRelease(ctx, conn, *orgID, *clientID, *onlyGroups)
	case "group list":
		return groupList(ctx, conn)
	case "policy apply":
		return policyApply(ctx, conn, *orgID, *policyFile)
	case "policy show":
		return policyShow(ctx, conn, *orgID)
	default:
		return usage()
	}
}

// janitorOnce runs a single maintenance pass and reports it.
//
// `serve` already runs the janitor, so this exists for the cases where that is
// not what you want: a one-shot after an incident, a cron in a deployment that
// runs the engine read-only, or simply seeing what a pass would do. It takes the
// same advisory lock, so running it against a live cluster is safe.
func janitorOnce(ctx context.Context, conn *pgx.Conn) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	pool, err := pgxpool.New(ctx, conn.Config().ConnString())
	if err != nil {
		return fmt.Errorf("creating connection pool: %w", err)
	}
	defer pool.Close()

	st, err := janitor.RunOnce(ctx, pool, log)
	if err != nil {
		return err
	}
	if st.Skipped {
		fmt.Println("janitor: another node holds the lock; nothing done")
		return nil
	}

	fmt.Printf("janitor: swept %d expired session(s), purged %d code(s)\n",
		st.SessionsSwept, st.CodesPurged)
	if len(st.Parked) == 0 {
		return nil
	}
	// Printed to stdout as well as logged: this is the output an operator ran the
	// command to see.
	fmt.Printf("\n%d relying part%s were never told a session ended:\n",
		len(st.Parked), map[bool]string{true: "y", false: "ies"}[len(st.Parked) == 1])
	for _, p := range st.Parked {
		fmt.Printf("  - %s\n", p)
	}
	return nil
}

// loadInstanceKeys is the shared preamble of the keys commands.
func loadInstanceKeys(ctx context.Context, conn *pgx.Conn) (instanceID string, set *keys.Set, root *keys.RootKey, err error) {
	root, err = rootKey()
	if err != nil {
		return "", nil, nil, err
	}
	var issuer string
	if err = conn.QueryRow(ctx,
		`SELECT id::text, issuer FROM core.instances ORDER BY created_at LIMIT 1`).
		Scan(&instanceID, &issuer); err != nil {
		return "", nil, nil, fmt.Errorf("no instance found -- run `signari instance create -issuer …` first: %w", err)
	}
	set, err = keys.LoadSet(ctx, conn, instanceID, root)
	if err != nil {
		return "", nil, nil, fmt.Errorf("loading signing keys: %w", err)
	}
	return instanceID, set, root, nil
}

func keysList(ctx context.Context, conn *pgx.Conn) error {
	_, set, _, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}

	fmt.Printf("%-24s %-8s %-8s %-22s %s\n", "KID", "ALG", "STATE", "PUBLISHED", "NOTE")
	for _, k := range set.Keys() {
		note := ""
		if k.State() == keys.StateNext {
			if ok, wait := set.CanPromote(k); ok {
				note = "ready to promote"
			} else {
				note = fmt.Sprintf("promotable in %s", wait.Round(time.Minute))
			}
		}
		fmt.Printf("%-24s %-8s %-8s %-22s %s\n",
			k.KID(), k.Algorithm(), k.State(),
			k.PublishedAt().UTC().Format(time.RFC3339), note)
	}
	return nil
}

// keysRotate advances the rotation by exactly one safe step, per algorithm.
//
// Rotation is a process, not a button, and the CLI is shaped to say so. Each run
// does whichever step is legal now:
//
//	no `next` key      -> generate one. It is published in the JWKS immediately
//	                      and cannot sign anything.
//	`next` not ripe     -> report how long remains, change nothing.
//	`next` ripe         -> promote it to active and demote the old active to
//	                      passive, in one transaction.
//
// The dwell between step one and step three is the entire safety property. A
// relying party that cached the JWKS before the new key existed will reject
// everything the new key signs, and plenty of them refresh only at boot. Signing
// with a key nobody has fetched is how a routine rotation becomes an outage --
// so the wait is enforced rather than documented.
func keysRotate(ctx context.Context, conn *pgx.Conn, only string, promoteNow bool) error {
	instanceID, set, root, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}

	// Algorithms currently in use. Rotation replaces what exists; it is not the
	// place to introduce a new algorithm.
	algs := set.Algorithms()
	if only != "" {
		algs = []keys.Algorithm{keys.Algorithm(only)}
	}
	if len(algs) == 0 {
		return fmt.Errorf("no active signing keys to rotate")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, a := range algs {
		var next keys.Key
		for _, k := range set.Keys() {
			if k.Algorithm() == a && k.State() == keys.StateNext {
				next = k
				break
			}
		}

		if next == nil {
			generated, err := keys.Generate(keys.NewKID(), a)
			if err != nil {
				return fmt.Errorf("generating %s key: %w", a, err)
			}
			if err := keys.Save(ctx, tx, instanceID, generated, root); err != nil {
				return err
			}
			fmt.Printf("%s: published %s as `next`. Run `signari keys rotate` again after %s to promote it.\n",
				a, generated.KID(), keys.MinPublishBeforeActive)
			continue
		}

		if ok, wait := set.CanPromote(next); !ok {
			if !promoteNow {
				fmt.Printf("%s: %s is published but not promotable for another %s. Nothing changed.\n",
					a, next.KID(), wait.Round(time.Minute))
				continue
			}
			// Deliberately loud. This is correct for a compromised key, where
			// continuing to sign with it is worse than some relying parties
			// failing verification until their JWKS cache expires -- and wrong
			// for anything else.
			fmt.Fprintf(os.Stderr,
				"WARNING: promoting %s %s after only %s of publication. Relying parties whose "+
					"JWKS cache predates this key will REJECT its signatures until they refresh.\n",
				a, next.KID(), (keys.MinPublishBeforeActive - wait).Round(time.Minute))
		}

		// Demote the outgoing key rather than deleting it: tokens it signed are
		// still live, and passive keys stay in the JWKS precisely so those keep
		// verifying. Deleting here would invalidate every unexpired token.
		if current, err := set.Active(a); err == nil {
			demoted, err := keys.WithState(current, keys.StatePassive)
			if err != nil {
				return err
			}
			if err := keys.Save(ctx, tx, instanceID, demoted, root); err != nil {
				return err
			}
			fmt.Printf("%s: demoted %s to passive (still published, so existing tokens verify).\n",
				a, current.KID())
		}

		promoted, err := keys.WithState(next, keys.StateActive)
		if err != nil {
			return err
		}
		if err := keys.Save(ctx, tx, instanceID, promoted, root); err != nil {
			return err
		}
		fmt.Printf("%s: promoted %s to active. It signs from the next restart or config reload.\n",
			a, promoted.KID())
	}

	return tx.Commit(ctx)
}

// rootKey reads the wrapping key for private key material. It is deliberately
// required rather than defaulted: a generated-on-boot root key would silently
// make every restart invalidate every stored signing key.
func rootKey() (*keys.RootKey, error) {
	b64 := os.Getenv("SIGNARI_ROOT_KEY")
	if b64 == "" {
		return nil, fmt.Errorf(
			"SIGNARI_ROOT_KEY is unset (32 random bytes, base64) -- generate one with:\n" +
				"  head -c 32 /dev/urandom | base64")
	}
	return keys.NewRootKeyFromBase64(os.Getenv("SIGNARI_ROOT_KEY_REF"), b64)
}

func instanceCreate(ctx context.Context, conn *pgx.Conn, issuer, name string) error {
	if issuer == "" {
		return fmt.Errorf("-issuer is required")
	}
	if name == "" {
		name = issuer
	}
	root, err := rootKey()
	if err != nil {
		return err
	}

	var id string
	err = conn.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name) VALUES ($1, $2)
		ON CONFLICT (issuer) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id::text`, issuer, name).Scan(&id)
	if err != nil {
		return fmt.Errorf("creating instance: %w", err)
	}
	fmt.Printf("instance %s\n  issuer %s\n", id, issuer)

	// ES256 as the default for new clients, RS256 always available as the
	// universal floor that every relying-party library can verify.
	created, err := keys.Ensure(ctx, conn, id, root, keys.ES256, keys.RS256)
	if err != nil {
		return fmt.Errorf("ensuring signing keys: %w", err)
	}
	for _, k := range created {
		fmt.Printf("  generated %s key %s (%s)\n", k.Algorithm(), k.KID(), k.State())
	}
	if len(created) == 0 {
		fmt.Println("  signing keys already present")
	}
	return nil
}

func serve(conn *pgx.Conn, addr, tlsCert, tlsKey, adminAddr string) error {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The startup gate. A drifted or half-migrated database must fail here, at
	// boot, with a clear message -- not at 3am inside a query.
	if err := migrate.Verify(ctx, conn); err != nil {
		return err
	}

	root, err := rootKey()
	if err != nil {
		return err
	}

	// Which instance to serve.
	//
	// Previously "the oldest one", which is fine with exactly one and silently
	// wrong with more than one -- the server comes up claiming an issuer nobody
	// intended, and every token it mints is audienced to the wrong deployment.
	// It is the kind of failure that looks like a client misconfiguration.
	//
	// So: name it explicitly, or be told what the choices are.
	instanceID, issuer, err := selectInstance(ctx, conn, os.Getenv("SIGNARI_ISSUER"))
	if err != nil {
		return err
	}

	set, err := keys.LoadSet(ctx, conn, instanceID, root)
	if err != nil {
		return fmt.Errorf("loading signing keys: %w", err)
	}

	pool, err := pgxpool.New(ctx, conn.Config().ConnString())
	if err != nil {
		return fmt.Errorf("creating connection pool: %w", err)
	}
	defer pool.Close()

	// Mail is optional to START but never optional to HAVE: without SMTP the log
	// driver keeps account recovery working locally and warns on every send, which
	// is better than a deployment that looks configured and silently sends nothing.
	mailer := buildMailer(log)

	insecureIssuer := os.Getenv("SIGNARI_INSECURE_ISSUER") == "1"
	if insecureIssuer {
		log.Warn("SIGNARI_INSECURE_ISSUER is set: the issuer may be plaintext HTTP. " +
			"Every token, code and client secret in the flow crosses the network readable. " +
			"This must never be set outside local testing.")
	}

	// Legacy issuers this deployment also claims, so tokens minted for clients
	// mid-migration are still accepted by our own userinfo and introspection.
	var aliases []string
	if rows, err := pool.Query(ctx,
		`SELECT issuer FROM core.instance_issuer_aliases WHERE instance_id = $1::uuid
		   AND (retire_after IS NULL OR retire_after > now())`, instanceID); err == nil {
		for rows.Next() {
			var a string
			if rows.Scan(&a) == nil {
				aliases = append(aliases, a)
			}
		}
		rows.Close()
		if len(aliases) > 0 {
			log.Info("accepting legacy issuer aliases for migrated clients", "aliases", aliases)
		}
	} else {
		log.Error("loading issuer aliases", "err", err)
	}

	srv, err := httpapi.New(oidc.Config{
		Issuer:              issuer,
		IssuerAliases:       aliases,
		ProxyCookieDomain:   os.Getenv("SIGNARI_PROXY_COOKIE_DOMAIN"),
		Keys:                set,
		Root:                root,
		AllowInsecureIssuer: insecureIssuer,
	}, pool, log, mailer)
	if err != nil {
		return err
	}

	// The outbox worker is a SINGLETON: running it on every node would deliver
	// each logout notice once per node. It claims rows FOR UPDATE SKIP LOCKED so
	// a second worker started by mistake divides the work rather than duplicating
	// it, but the intent is one.
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go outbox.New(pool, set, issuer, log).Run(workerCtx, 2*time.Second)

	// The janitor is likewise a singleton, but it enforces that itself with an
	// advisory lock rather than by convention -- so it is safe to start on every
	// node, and there is no separate unit an operator can forget to deploy. The
	// jobs it runs are the ones whose absence is invisible until it matters:
	// relying parties never told a session ended, and a table that only grows.
	go janitor.Run(workerCtx, pool, log, janitor.DefaultInterval)

	// The admin API listens on its OWN address, and is off unless one is given.
	// It is the write surface for the entire identity provider; exposing it on
	// the same public listener as the protocol endpoints would put it one
	// misconfigured route away from the internet. Bind it to a private interface.
	if adminAddr != "" {
		adminToken := os.Getenv("SIGNARI_ADMIN_TOKEN")
		adminSrv, err := adminapi.New(pool, log, adminToken)
		if err != nil {
			return fmt.Errorf("admin API: %w", err)
		}
		go func() {
			log.Info("admin API listening", "addr", adminAddr)
			ah := &http.Server{
				Addr:              adminAddr,
				Handler:           adminSrv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := ah.ListenAndServe(); err != nil {
				log.Error("admin API stopped", "err", err)
			}
		}()
	}

	// The LDAP shim, for applications that can only authenticate by binding to a
	// directory. Off unless an address is given: it is a second authentication
	// surface, and one nobody asked for should not be listening.
	if ldapAddr := os.Getenv("SIGNARI_LDAP_ADDR"); ldapAddr != "" {
		// ONE organisation per listener, and it is named explicitly.
		//
		// LDAP has no way to express which tenant a bind belongs to -- the DN is
		// the only input, and it is chosen by the client. Serving several
		// organisations from one port would mean inferring the tenant from
		// attacker-controlled data, and inferring it wrong means binding somebody
		// against another organisation's directory.
		//
		// So: stated, not derived. The single-organisation case is filled in
		// automatically because there is nothing to be ambiguous about.
		ldapOrgID := os.Getenv("SIGNARI_LDAP_ORG_ID")
		if ldapOrgID == "" {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM core.organizations`).Scan(&n); err != nil {
				return fmt.Errorf("counting organisations for the LDAP listener: %w", err)
			}
			if n != 1 {
				return fmt.Errorf("SIGNARI_LDAP_ORG_ID is not set and this database holds "+
					"%d organisations. An LDAP listener serves exactly one, and which one "+
					"cannot be inferred from a bind DN the client chose", n)
			}
			if err := pool.QueryRow(ctx, `SELECT id::text FROM core.organizations`).Scan(&ldapOrgID); err != nil {
				return fmt.Errorf("resolving the organisation for the LDAP listener: %w", err)
			}
		}
		baseDN := os.Getenv("SIGNARI_LDAP_BASE_DN")
		if baseDN == "" {
			return fmt.Errorf("SIGNARI_LDAP_ADDR is set but SIGNARI_LDAP_BASE_DN is not; " +
				"the base DN is what every bind DN must sit under and there is no safe default")
		}
		ldapSrv := ldapd.New(ldapd.Config{
			BaseDN:   baseDN,
			UserAttr: envOr("SIGNARI_LDAP_USER_ATTR", "uid"),
			// Anonymous search stays off unless asked for: it publishes a user
			// directory to anyone who can reach the port.
			AllowAnonymousSearch: os.Getenv("SIGNARI_LDAP_ANONYMOUS_SEARCH") == "1",
		}, httpapi.NewLDAPAuthenticator(pool,
			passwords.NewHasher(passwords.MemoryBudgetMiB), ldapOrgID), log)

		ln, err := net.Listen("tcp", ldapAddr)
		if err != nil {
			return fmt.Errorf("LDAP listener: %w", err)
		}
		if tlsCert == "" {
			log.Warn("LDAP is listening WITHOUT TLS: every bind sends a password in the " +
				"clear. Supply -tls-cert and -tls-key, or restrict this listener to a " +
				"trusted network.")
		} else {
			cert, cerr := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if cerr != nil {
				return fmt.Errorf("LDAP TLS: %w", cerr)
			}
			ln = tls.NewListener(ln, &tls.Config{
				Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			})
		}
		go func() {
			log.Info("LDAP listening", "addr", ldapAddr, "base_dn", baseDN, "tls", tlsCert != "")
			if err := ldapSrv.Serve(ctx, ln); err != nil {
				log.Error("LDAP stopped", "err", err)
			}
		}()
	}

	h := &http.Server{
		Addr:    addr,
		Handler: srv.Routes(),
		// A slow-header attack costs an attacker nothing and holds a connection
		// open indefinitely without this.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if tlsCert == "" || tlsKey == "" {
		log.Info("serving over plaintext HTTP", "addr", addr, "issuer", issuer,
			"algs", set.Algorithms())
		log.Warn("no TLS configured: browsers will refuse to store the __Host- session " +
			"cookie over plaintext on any host except localhost, so sign-in will silently " +
			"fail to persist. Supply -tls-cert and -tls-key outside local testing.")
		return h.ListenAndServe()
	}

	// TLS 1.2 floor. 1.0 and 1.1 are deprecated and their cipher suites are not
	// worth the compatibility they buy for a service whose whole job is secrets.
	h.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Go picks sane defaults for TLS 1.3; this constrains 1.2 to suites with
		// forward secrecy and AEAD only.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	log.Info("serving over HTTPS", "addr", addr, "issuer", issuer, "algs", set.Algorithms())
	return h.ListenAndServeTLS(tlsCert, tlsKey)
}

func up(ctx context.Context, conn *pgx.Conn, tier migrate.Tier, to int) error {
	applied, err := migrate.Up(ctx, conn, tier, to)
	// Report what did land even when a later migration fails -- knowing where it
	// stopped is the difference between a five-minute fix and a restore.
	for _, m := range applied {
		fmt.Printf("applied %04d_%s\n", m.Version, m.Name)
	}
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("nothing to apply")
	}
	return nil
}

func status(ctx context.Context, conn *pgx.Conn) error {
	all, err := migrate.Load()
	if err != nil {
		return err
	}
	current, err := migrate.Applied(ctx, conn)
	if err != nil {
		return err
	}

	fmt.Printf("database version : %d\n", current)
	fmt.Printf("binary expects   : %d\n", all[len(all)-1].Version)

	if current > 0 {
		fp, err := migrate.Fingerprint(ctx, conn)
		if err != nil {
			return err
		}
		fmt.Printf("live fingerprint : %s\n", fp)
	}

	var pending []migrate.Migration
	for _, m := range all {
		if m.Version > current {
			pending = append(pending, m)
		}
	}
	if len(pending) == 0 {
		fmt.Println("pending          : none")
		return nil
	}
	fmt.Println("pending          :")
	for _, m := range pending {
		tier := "core"
		if m.Tier() == migrate.TierBootstrap {
			tier = "bootstrap (superuser)"
		}
		fmt.Printf("  %04d_%-24s %s\n", m.Version, m.Name, tier)
	}
	return nil
}

// firstOrg returns the only organisation, creating a default one if the instance
// has none. Development convenience; the admin API owns this in production.
func firstOrg(ctx context.Context, conn *pgx.Conn) (string, error) {
	var orgID string
	err := conn.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&orgID)
	if err == nil {
		return orgID, nil
	}
	var instanceID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.instances ORDER BY created_at LIMIT 1`).Scan(&instanceID); err != nil {
		return "", fmt.Errorf("no instance -- run `signari instance create` first: %w", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1, 'default', 'Default') RETURNING id::text`, instanceID).Scan(&orgID); err != nil {
		return "", err
	}
	return orgID, nil
}

func userCreate(ctx context.Context, conn *pgx.Conn, email, password string) error {
	if email == "" || password == "" {
		return fmt.Errorf("-email and -password are both required")
	}
	orgID, err := firstOrg(ctx, conn)
	if err != nil {
		return err
	}

	// 64 random bytes, stable for the life of the account. This is the WebAuthn
	// user handle and it must never be the email or a sequential id: it is sent
	// to authenticators and stored on the user's device essentially forever.
	handle := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, handle); err != nil {
		return err
	}

	hasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return err
	}

	var userID string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, $2, $3) RETURNING id::text`, orgID, handle, email).Scan(&userID); err != nil {
		return fmt.Errorf("creating user: %w", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1, $2, $3, 'argon2id')`, userID, orgID, hash); err != nil {
		return fmt.Errorf("storing credential: %w", err)
	}
	fmt.Printf("user %s\n  email %s\n", userID, email)
	return nil
}

func clientCreate(ctx context.Context, conn *pgx.Conn, clientID, redirect string, public bool) error {
	if clientID == "" || redirect == "" {
		return fmt.Errorf("-client-id and -redirect are both required")
	}
	orgID, err := firstOrg(ctx, conn)
	if err != nil {
		return err
	}

	kind, secret, secretHash := "public", "", ""
	if !public {
		kind = "confidential"
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return err
		}
		secret = base64.RawURLEncoding.EncodeToString(b)
		hasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
		if secretHash, err = hasher.Hash(ctx, secret); err != nil {
			return err
		}
	}

	// client_id is settable verbatim so an existing relying party's configuration
	// does not have to change during a migration.
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, scopes)
		VALUES ($1, $2, $1, $3, NULLIF($4, ''),
		        ARRAY['openid','profile','email','offline_access'])`,
		clientID, orgID, kind, secretHash); err != nil {
		return fmt.Errorf("creating client: %w", err)
	}
	if _, err := conn.Exec(ctx,
		`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
		clientID, redirect); err != nil {
		return fmt.Errorf("registering redirect_uri: %w", err)
	}

	fmt.Printf("client %s (%s)\n  redirect_uri %s\n", clientID, kind, redirect)
	if secret != "" {
		fmt.Printf("  client_secret %s\n  (shown once)\n", secret)
	}
	return nil
}

// buildMailer returns an SMTP sender when configured, or the logging driver.
func buildMailer(log *slog.Logger) mail.Sender {
	host := os.Getenv("SIGNARI_SMTP_HOST")
	from := os.Getenv("SIGNARI_MAIL_FROM")
	if host == "" || from == "" {
		log.Warn("no SMTP configured (SIGNARI_SMTP_HOST, SIGNARI_MAIL_FROM): " +
			"account recovery emails will be written to this log instead of sent")
		return mail.NewLogSender(log, "noreply@invalid")
	}
	port := 587
	if p := os.Getenv("SIGNARI_SMTP_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return &mail.SMTPSender{
		Host: host, Port: port,
		Username: os.Getenv("SIGNARI_SMTP_USERNAME"),
		Password: os.Getenv("SIGNARI_SMTP_PASSWORD"),
		FromAddr: from,
		FromName: os.Getenv("SIGNARI_MAIL_FROM_NAME"),
	}
}

// importKeycloak reads a realm export and creates the equivalent users and
// clients.
//
// One transaction, and a --dry-run that changes nothing: an import is run
// against a production directory by someone who wants to know what it will do
// before it does it, and refusing them that is how imports get run blind.
func importKeycloak(ctx context.Context, conn *pgx.Conn, path, orgID string, dryRun bool) error {
	if path == "" || orgID == "" {
		return fmt.Errorf("-file and -org are both required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	realm, err := importer.Parse(f)
	if err != nil {
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	res, err := importer.Import(ctx, tx, orgID, realm,
		passwords.NewHasher(passwords.MemoryBudgetMiB), dryRun)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("DRY RUN -- nothing was written.\n")
	} else if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("realm %q\n  users:   %d created, %d updated, %d skipped\n  clients: %d created, %d skipped\n",
		realm.Realm, res.UsersCreated, res.UsersUpdated, len(res.UsersSkipped),
		res.ClientsCreated, len(res.ClientsSkipped))

	// Skipped entries are PRINTED, never merely counted. A number tells an
	// operator something went wrong; the list tells them who cannot sign in.
	for _, s := range res.UsersSkipped {
		fmt.Printf("  skipped user:   %s\n", s)
	}
	for _, s := range res.ClientsSkipped {
		fmt.Printf("  skipped client: %s\n", s)
	}
	if !dryRun && res.UsersCreated+res.UsersUpdated > 0 {
		fmt.Printf("\nImported users are marked migration_state=pending and keep their Keycloak\n" +
			"password hash. Each one is upgraded to Argon2id on their first sign-in.\n")
	}
	return nil
}

// selectInstance resolves which instance this process serves.
//
// With one instance, no configuration is needed. With several, refusing to guess
// is the whole point: starting up under the wrong issuer produces tokens every
// relying party rejects, and the error surfaces at the client rather than here.
func selectInstance(ctx context.Context, conn *pgx.Conn, want string) (id, issuer string, err error) {
	if want != "" {
		err = conn.QueryRow(ctx,
			`SELECT id::text, issuer FROM core.instances WHERE issuer = $1`, want).Scan(&id, &issuer)
		if err != nil {
			return "", "", fmt.Errorf("no instance with issuer %q -- create it with "+
				"`signari instance create -issuer %s`: %w", want, want, err)
		}
		return id, issuer, nil
	}

	rows, err := conn.Query(ctx,
		`SELECT id::text, issuer FROM core.instances ORDER BY created_at`)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	type inst struct{ id, issuer string }
	var found []inst
	for rows.Next() {
		var i inst
		if err := rows.Scan(&i.id, &i.issuer); err != nil {
			return "", "", err
		}
		found = append(found, i)
	}

	switch len(found) {
	case 0:
		return "", "", fmt.Errorf("no instance found -- run `signari instance create -issuer …` first")
	case 1:
		return found[0].id, found[0].issuer, nil
	default:
		// Capped. A development database accumulates test instances, and printing
		// three hundred of them turns an actionable error into a wall of text
		// nobody reads.
		const show = 10
		var b strings.Builder
		for i, in := range found {
			if i == show {
				fmt.Fprintf(&b, "\n  ... and %d more", len(found)-show)
				break
			}
			fmt.Fprintf(&b, "\n  %s", in.issuer)
		}
		return "", "", fmt.Errorf("this database has %d instances; set SIGNARI_ISSUER to name "+
			"the one to serve. Available:%s", len(found), b.String())
	}
}

// proxyCheck probes a forward-auth deployment and prints what answered.
//
// Exit status is the point of the command: non-zero when anything served
// content to an anonymous request, so it can sit in CI or a deployment script
// and FAIL the deploy. A report nobody reads changes nothing; a failing exit
// code stops the release.
func proxyCheck(app, issuer, origin, extraPaths string, insecure bool) error {
	if app == "" {
		return fmt.Errorf("give -app, the protected application URL as the browser " +
			"reaches it, e.g. -app https://n8n.example.com")
	}
	var paths []string
	for _, p := range strings.Split(extraPaths, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			paths = append(paths, p)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rep, err := proxycheck.Run(ctx, proxycheck.Options{
		BaseURL: app, Issuer: issuer, Origin: origin, Paths: paths, Insecure: insecure,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n  forward-auth check: %s\n\n", app)
	label := map[proxycheck.Status]string{
		proxycheck.Protected: "  ok  ",
		proxycheck.Exposed:   " OPEN ",
		proxycheck.Absent:    "  --  ",
		proxycheck.Unknown:   "  ??  ",
	}
	for _, r := range rep.Results {
		fmt.Printf("  [%s] %-34s %s\n", label[r.Status], r.Probe, r.Detail)
		if r.Fix != "" {
			fmt.Printf("           -> %s\n", wrap(r.Fix, 66, "              "))
		}
	}

	open := rep.Exposed()
	fmt.Printf("\n  %d probes, %d open\n", len(rep.Results), len(open))

	// Never render a verdict on a host that never answered. A mistyped URL
	// otherwise produces a page of "could not tell" and a clean-looking summary,
	// which is the most dangerous output this command could produce.
	if !rep.Reached {
		fmt.Printf("\n  Nothing answered at %s, so nothing here was tested.\n"+
			"  Check the URL, and that this machine can reach it.\n\n", app)
		return fmt.Errorf("the application never answered; this run proves nothing")
	}

	if len(open) > 0 {
		// Named plainly, and named ACCURATELY -- an origin bypass is a different
		// sentence from an unprotected path, and an operator acts on the words.
		fmt.Printf("\n  %s\n\n", summarise(open))
		return fmt.Errorf("%d of %d probes reached the application unauthenticated",
			len(open), len(rep.Results))
	}
	fmt.Printf("\n  No probe reached the application unauthenticated.\n" +
		"  That is evidence, not a guarantee: it covers the paths and methods\n" +
		"  listed above, from where this ran.\n\n")
	return nil
}

// summarise says what was actually found, rather than one sentence stretched
// over every kind of finding.
func summarise(open []proxycheck.Result) string {
	var paths, methods, other int
	for _, r := range open {
		switch {
		case strings.HasPrefix(r.Probe, "unauthenticated GET"):
			paths++
		case strings.HasPrefix(r.Probe, "unauthenticated "):
			methods++
		default:
			other++
		}
	}
	var parts []string
	if paths > 0 {
		parts = append(parts, fmt.Sprintf("%d path(s) served content to an anonymous request", paths))
	}
	if methods > 0 {
		parts = append(parts, fmt.Sprintf("%d method(s) bypassed authentication", methods))
	}
	for _, r := range open {
		if strings.Contains(r.Probe, "direct-to-origin") {
			parts = append(parts, "the application answers directly, so the proxy is optional")
		}
		if strings.Contains(r.Probe, "header injection") {
			parts = append(parts, "a forged identity header was accepted")
		}
	}
	return "Found: " + strings.Join(parts, "; ") + "."
}

// wrap reflows a fix so a long sentence stays readable in a terminal.
func wrap(s string, width int, indent string) string {
	var out strings.Builder
	col := 0
	for _, w := range strings.Fields(s) {
		if col > 0 && col+len(w)+1 > width {
			out.WriteString("\n" + indent)
			col = 0
		} else if col > 0 {
			out.WriteString(" ")
			col++
		}
		out.WriteString(w)
		col += len(w)
	}
	return out.String()
}

// samlAddSP registers a service provider.
//
// The validation here is the same as the authorization endpoint applies to a
// redirect_uri, and for the same reason: the ACS URL is where a signed assertion
// for a real user gets delivered. Checking it at REGISTRATION means a mistake
// surfaces now, with a message about the registration, rather than during
// someone else's integration as an unexplained refusal.
func samlAddSP(ctx context.Context, conn *pgx.Conn, orgID, entityID, name, acs, nameIDFormat, slo, certPath string) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this service provider belongs to")
	case entityID == "":
		return fmt.Errorf("give -entity-id, the service provider's EntityID")
	case acs == "":
		return fmt.Errorf("give -acs, the AssertionConsumerService URL assertions are POSTed to")
	}
	if !strings.HasPrefix(acs, "https://") {
		return fmt.Errorf("the ACS URL must be https: %q would carry a signed assertion "+
			"for a real user across the network in the clear", acs)
	}
	if strings.Contains(acs, "*") {
		return fmt.Errorf("%q contains a wildcard. ACS URLs are matched exactly, because "+
			"anything looser lets a request steer where the assertion is delivered", acs)
	}
	if name == "" {
		name = entityID
	}
	switch nameIDFormat {
	case "", "persistent":
		nameIDFormat = "persistent"
	case "emailAddress", "transient":
	default:
		return fmt.Errorf("unknown NameID format %q: use persistent, emailAddress or transient",
			nameIDFormat)
	}

	// Single logout needs BOTH a place to send to and a certificate to verify
	// with. A provider configured with a logout URL and no certificate is the
	// dangerous half-configuration: it looks set up, and the endpoint refuses
	// every request because there is nothing to check the signature against.
	var certPEM string
	if certPath != "" {
		b, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("reading the service provider certificate: %w", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return fmt.Errorf("%s is not PEM. Export the provider's SIGNING certificate, "+
				"not its private key or metadata", certPath)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("%s did not parse as a certificate: %w", certPath, err)
		}
		certPEM = string(b)
	}
	if slo != "" && certPEM == "" {
		return fmt.Errorf("a logout URL was given with no -sp-cert. A LogoutRequest is " +
			"acted on only when signed, so without the provider's certificate every " +
			"logout would be refused -- which looks configured and is not")
	}
	if slo != "" && !strings.HasPrefix(slo, "https://") {
		return fmt.Errorf("the logout URL must be https: %q", slo)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name, name_id_format,
		                                 sp_signing_cert)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5,''))
		RETURNING id::text`, orgID, entityID, name, nameIDFormat, certPEM).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a service provider with entity id %q is already registered "+
				"in that organisation", entityID)
		}
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
		VALUES ($1::uuid, $2, 'HTTP-POST', true)`, id, acs); err != nil {
		return err
	}
	if slo != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.saml_slo_urls (provider_id, url, binding)
			VALUES ($1::uuid, $2, 'HTTP-Redirect')`, id, slo); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("registered %s\n  entity id : %s\n  ACS       : %s\n  NameID    : %s\n",
		name, entityID, acs, nameIDFormat)
	if nameIDFormat == "persistent" {
		fmt.Println("\n  The NameID is pairwise: this service provider sees an opaque identifier\n" +
			"  that no other provider can correlate, and it survives an email change.")
	}
	if slo != "" {
		fmt.Printf("  logout    : %s (signature verified against the certificate given)\n", slo)
	} else {
		fmt.Println("  logout    : not configured -- single logout is unavailable for this provider")
	}
	fmt.Println("\n  Point the service provider at /saml/metadata to import the certificate.")
	return nil
}

// samlListSPs shows what is registered.
func samlListSPs(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT p.entity_id, p.display_name, p.name_id_format, p.enabled,
		       COALESCE(string_agg(a.url, ', ' ORDER BY a.url), '(none)')
		FROM core.saml_providers p
		LEFT JOIN core.saml_acs_urls a ON a.provider_id = p.id
		GROUP BY p.id, p.entity_id, p.display_name, p.name_id_format, p.enabled
		ORDER BY p.display_name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-38s %-12s %-8s %s\n", "ENTITY ID", "NAMEID", "ENABLED", "ACS")
	var n int
	for rows.Next() {
		var entity, name, format, acs string
		var enabled bool
		if err := rows.Scan(&entity, &name, &format, &enabled, &acs); err != nil {
			return err
		}
		n++
		fmt.Printf("%-38s %-12s %-8t %s\n", truncateMiddle(entity, 38), format, enabled, acs)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari saml add-sp`)")
	}
	return rows.Err()
}

func truncateMiddle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	half := (n - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

// idpAdd registers an external identity provider.
func idpAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name, kind, clientID, secret,
	issuer string, allowSignup, allowLinking, trustEmail bool) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this provider belongs to")
	case slug == "":
		return fmt.Errorf("give -slug, the short name used in the URL /login/with/<slug>")
	case clientID == "":
		return fmt.Errorf("give -client-id, issued by the provider")
	}
	preset, err := federation.PresetFor(federation.Kind(kind))
	if err != nil {
		return err
	}
	// A generic provider is discovered NOW, so a wrong issuer fails in front of
	// the person who typed it rather than at somebody's first sign-in.
	var authorizeURL, tokenURL, userinfoURL, jwksURL string
	if kind == "oidc" {
		if issuer == "" {
			return fmt.Errorf("a generic OIDC provider needs -issuer, so its endpoints " +
				"and signing keys can be discovered")
		}
		d, derr := federation.Discover(ctx, &http.Client{Timeout: 15 * time.Second}, issuer)
		if derr != nil {
			return fmt.Errorf("discovering %s: %w", issuer, derr)
		}
		authorizeURL, tokenURL, userinfoURL, jwksURL = d.AuthorizeURL, d.TokenURL, d.UserinfoURL, d.JWKSURL
		fmt.Printf("discovered %s\n  authorize : %s\n  token     : %s\n  jwks      : %s\n\n",
			issuer, authorizeURL, tokenURL, jwksURL)
	}
	if name == "" {
		name = slug
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	var sealed []byte
	if secret != "" {
		if sealed, err = root.Seal([]byte(secret), "idp_client_secret"); err != nil {
			return fmt.Errorf("sealing the client secret: %w", err)
		}
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.identity_providers
			(org_id, slug, display_name, kind, client_id, client_secret, issuer,
			 authorize_url, token_url, userinfo_url, jwks_url,
			 scopes, allow_signup, allow_linking, trust_email_verification)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, NULLIF($7,''),
		        NULLIF($8,''), NULLIF($9,''), NULLIF($10,''), NULLIF($11,''),
		        $12, $13, $14, $15)`,
		orgID, slug, name, kind, clientID, sealed, issuer,
		authorizeURL, tokenURL, userinfoURL, jwksURL,
		preset.Scopes, allowSignup, allowLinking, trustEmail && kind == "oidc"); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a provider with slug %q is already registered in that "+
				"organisation", slug)
		}
		return err
	}

	fmt.Printf("registered %s (%s)\n", name, kind)
	fmt.Printf("  sign-in URL  : /login/with/%s\n", slug)
	fmt.Printf("  callback URL : <issuer>/login/callback/%s\n", slug)
	fmt.Print("     register that callback with the provider, exactly as written\n")
	fmt.Printf("  scopes       : %s\n", strings.Join(preset.Scopes, " "))

	// The email-verification policy is the part an operator most needs told,
	// because it decides whether sign-up works at all and there is no way to
	// discover it from the provider's own console.
	fmt.Print("\n  Email verification: ")
	switch {
	case preset.TrustsEmailVerification && preset.EmailNeedsSeparateCheck:
		fmt.Printf("established by an extra check.\n    %s\n", preset.Note)
	case preset.TrustsEmailVerification:
		fmt.Printf("trusted as returned.\n    %s\n", preset.Note)
	case kind == "oidc" && trustEmail:
		fmt.Print("trusted, because you passed -trust-email-verification.\n" +
			"    Signari cannot check that claim for an unknown provider. If this one\n" +
			"    does not actually verify addresses, anyone who can register there\n" +
			"    with somebody else's address can create an account here as them.\n")
	default:
		fmt.Printf("NOT trusted.\n    %s\n", preset.Note)
		fmt.Print("    This provider can link to existing accounts but cannot create\n" +
			"    new ones until verification can be established.\n")
	}
	fmt.Printf("\n  Accounts are matched on the provider's subject identifier only.\n"+
		"  A matching email address never links an account -- the user signs in\n"+
		"  locally first and adds the provider from /account/link/%s.\n", slug)
	return nil
}

// idpList shows configured providers.
func idpList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT slug, display_name, kind, allow_signup, allow_linking, enabled,
		       (SELECT count(*) FROM core.federated_identities f WHERE f.provider_id = p.id)
		FROM core.identity_providers p ORDER BY slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-14s %-12s %-8s %-8s %-8s %s\n",
		"SLUG", "KIND", "SIGNUP", "LINKING", "ENABLED", "LINKED ACCOUNTS")
	var n int
	for rows.Next() {
		var slug, name, kind string
		var signup, linking, enabled bool
		var linked int
		if err := rows.Scan(&slug, &name, &kind, &signup, &linking, &enabled, &linked); err != nil {
			return err
		}
		n++
		fmt.Printf("%-14s %-12s %-8t %-8t %-8t %d\n", slug, kind, signup, linking, enabled, linked)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari idp add`)")
	}
	return rows.Err()
}

// scimHTTPClient builds the client used to reach SCIM targets.
//
// SIGNARI_SCIM_CA_BUNDLE adds a certificate authority to the trust store for
// these requests. Internal provisioning targets frequently sit behind a private
// CA, and the alternative operators reach for is disabling verification
// entirely -- so a narrow, explicit way to trust the right CA is offered
// instead of a flag that trusts everything.
//
// It ADDS to the system pool rather than replacing it, so configuring an
// internal CA does not silently stop public targets from verifying.
func scimHTTPClient() (*http.Client, error) {
	bundle := os.Getenv("SIGNARI_SCIM_CA_BUNDLE")
	if bundle == "" {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	pem, err := os.ReadFile(bundle)
	if err != nil {
		return nil, fmt.Errorf("reading SIGNARI_SCIM_CA_BUNDLE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no certificates", bundle)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// scimAdd registers a provisioning target.
func scimAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name, baseURL, token,
	onDeactivate string, dryRun bool) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid")
	case slug == "":
		return fmt.Errorf("give -slug, a short name for this target")
	case baseURL == "":
		return fmt.Errorf("give -base-url, the target's SCIM base URL, e.g. " +
			"https://api.slack.com/scim/v2")
	case token == "":
		return fmt.Errorf("give -token, the bearer token the target issued")
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return fmt.Errorf("the base URL must be https: this token can create and delete " +
			"accounts in that system, and it is sent on every request")
	}
	switch onDeactivate {
	case "deactivate", "delete", "nothing":
	default:
		return fmt.Errorf("-on-deactivate must be deactivate, delete or nothing")
	}
	if name == "" {
		name = slug
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	if err := store.AddSCIMTarget(ctx, conn, root, orgID, slug, name, baseURL, token,
		onDeactivate, dryRun); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a target named %q is already registered", slug)
		}
		return err
	}

	fmt.Printf("registered %s\n  base URL      : %s\n  on deactivate : %s\n  dry run       : %t\n",
		name, baseURL, onDeactivate, dryRun)
	fmt.Println("\n  Nothing is sent until you run `signari scim sync`.")
	fmt.Println("  Run `signari scim verify` afterwards: it reads the target's actual state")
	fmt.Println("  back, which is the only way to know a deactivation really happened.")
	return nil
}

// scimVerify reconciles what each target holds against what it should hold.
//
// The command that makes deprovisioning checkable. Everything else records what
// we MEANT; this asks the target.
func scimVerify(ctx context.Context, conn *pgx.Conn, only string) error {
	root, err := rootKey()
	if err != nil {
		return err
	}
	targets, err := store.LoadSCIMTargets(ctx, conn, root, only)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("no enabled provisioning targets (add one with `signari scim add`)")
		return nil
	}

	var criticals, unreachable, findings int
	for _, t := range targets {
		desired, err := store.SCIMDesiredState(ctx, conn, t)
		if err != nil {
			return err
		}
		var expected []scim.Expected
		for _, d := range desired {
			if d.RemoteID == "" {
				continue // never provisioned; sync's job, not verify's
			}
			expected = append(expected, scim.Expected{
				UserID: d.UserID, RemoteID: d.RemoteID, UserName: d.UserName,
				Active: d.Active, Synced: d.Synced,
			})
		}

		hc, err := scimHTTPClient()
		if err != nil {
			return err
		}
		client := scim.NewClient(t, hc)
		rep, err := scim.Verify(ctx, client, expected, nil)
		if err != nil {
			return err
		}

		fmt.Printf("\n  %s\n", rep.Summary())
		if rep.Unreachable {
			unreachable++
			continue
		}
		for _, f := range rep.Findings {
			fmt.Printf("    [%-8s] %-28s %s\n", f.Severity, f.UserName, f.Summary)
			if f.Severity == scim.Critical {
				fmt.Printf("               -> %s\n", wrap(f.Fix, 62, "                  "))
			}
		}
		criticals += len(rep.CriticalFindings())
		findings += len(rep.Findings)
	}

	fmt.Println()
	switch {
	case criticals > 0:
		// Non-zero exit, so this can gate a deploy or run from cron and be noticed.
		return fmt.Errorf("%d user(s) retain access at a target after being deactivated here",
			criticals)
	case unreachable > 0:
		return fmt.Errorf("%d target(s) could not be reached, so their state is unknown",
			unreachable)
	case findings > 0:
		// Exit 0: nobody has access they should not, which is what this command
		// gates on. But saying "every target agrees" here would be a plain
		// falsehood -- it printed the disagreements four lines earlier.
		fmt.Printf("  %d finding(s), none of them a security problem. "+
			"Nobody has access they should not.\n", findings)
		return nil
	}
	fmt.Println("  Every target agrees with this directory.")
	return nil
}

// scimSync converges each target on the desired state.
func scimSync(ctx context.Context, conn *pgx.Conn, only string, apply bool) error {
	root, err := rootKey()
	if err != nil {
		return err
	}
	targets, err := store.LoadSCIMTargets(ctx, conn, root, only)
	if err != nil {
		return err
	}

	for _, t := range targets {
		desired, err := store.SCIMDesiredState(ctx, conn, t)
		if err != nil {
			return err
		}
		hc, err := scimHTTPClient()
		if err != nil {
			return err
		}
		client := scim.NewClient(t, hc)
		var created, deactivated, deleted, failed int

		for _, d := range desired {
			switch {
			case d.RemoteID == "" && d.Active:
				if !apply {
					created++
					continue
				}
				u := scim.NewUser(d.UserID, d.UserName, d.DisplayName, d.Email, true)
				id, err := client.CreateUser(ctx, u)
				if err != nil {
					// A conflict means the account is already there; find it and
					// record its id rather than creating a duplicate or giving up.
					var se *scim.Error
					if errors.As(err, &se) && se.Conflict {
						if found, ferr := client.FindByUserName(ctx, d.UserName); ferr == nil && found != nil {
							id = found.ID
						}
					}
					if id == "" {
						fmt.Printf("    create %s: %v\n", d.UserName, err)
						failed++
						continue
					}
				}
				if err := store.RecordSCIMLink(ctx, conn, t.ID, d.UserID, t.OrgID, id, true); err != nil {
					return err
				}
				created++

			case d.RemoteID != "" && !d.Active:
				if t.OnDeactivate == "nothing" {
					continue
				}
				if !apply {
					deactivated++
					continue
				}
				if err := store.MarkSCIMIntent(ctx, conn, t.ID, d.UserID, false); err != nil {
					return err
				}
				if t.OnDeactivate == "delete" {
					if err := client.DeleteUser(ctx, d.RemoteID); err != nil {
						fmt.Printf("    delete %s: %v\n", d.UserName, err)
						failed++
						continue
					}
					if err := store.DropSCIMLink(ctx, conn, t.ID, d.UserID); err != nil {
						return err
					}
					deleted++
					continue
				}
				if err := client.SetActive(ctx, d.RemoteID, false); err != nil {
					fmt.Printf("    deactivate %s: %v\n", d.UserName, err)
					failed++
					continue
				}
				if err := store.ConfirmSCIMSync(ctx, conn, t.ID, d.UserID); err != nil {
					return err
				}
				deactivated++
			}
		}

		verb := "would"
		if apply {
			verb = "did"
		}
		fmt.Printf("  %s: %s create %d, deactivate %d, delete %d, failed %d\n",
			t.Slug, verb, created, deactivated, deleted, failed)
	}

	if !apply {
		fmt.Println("\n  Nothing was sent. Re-run with -apply to make these changes.")
		return nil
	}
	fmt.Println("\n  Run `signari scim verify` to confirm the targets agree.")
	return nil
}

// scimList shows configured targets.
func scimList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT t.slug, t.display_name, t.base_url, t.on_deactivate, t.dry_run, t.enabled,
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id),
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id AND NOT l.should_be_active)
		FROM core.scim_targets t ORDER BY t.slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-12s %-38s %-12s %-8s %s\n", "SLUG", "BASE URL", "ON DEACTIVATE", "LINKED", "SHOULD BE GONE")
	var n int
	for rows.Next() {
		var slug, name, base, onDeact string
		var dry, enabled bool
		var linked, inactive int
		if err := rows.Scan(&slug, &name, &base, &onDeact, &dry, &enabled, &linked, &inactive); err != nil {
			return err
		}
		n++
		fmt.Printf("%-12s %-38s %-12s %-8d %d\n", slug, truncateMiddle(base, 38), onDeact, linked, inactive)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari scim add`)")
	}
	return rows.Err()
}

// envOr reads an environment variable with a fallback.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// groupCreate adds a group.
func groupCreate(ctx context.Context, conn *pgx.Conn, orgID, name, displayName string) error {
	if orgID == "" || name == "" {
		return fmt.Errorf("give -org and -name")
	}
	if _, err := store.CreateGroup(ctx, conn, orgID, name, displayName, ""); err != nil {
		if strings.Contains(err.Error(), "groups_name_shape") {
			return fmt.Errorf("%q is not a usable group name. It travels through JSON "+
				"arrays, SAML attribute values and LDAP filters, so it must be letters, "+
				"digits, dot, underscore or hyphen only", name)
		}
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a group named %q already exists in that organisation", name)
		}
		return err
	}
	fmt.Printf("created group %s\n", name)
	fmt.Println("\n  No client sees this group until you release it:")
	fmt.Println("    signari group release -org <uuid> -client-id <id>")
	fmt.Println("  Group membership is authorization data, so release is an allow-list.")
	return nil
}

// groupMember adds or removes a member.
func groupMember(ctx context.Context, conn *pgx.Conn, orgID, name, email string, remove bool) error {
	if orgID == "" || name == "" || email == "" {
		return fmt.Errorf("give -org, -name and -email")
	}
	var userID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.users WHERE org_id = $1::uuid
		   AND (lower(email) = lower($2) OR lower(username) = lower($2))`,
		orgID, email).Scan(&userID); err != nil {
		return fmt.Errorf("no user %q in that organisation", email)
	}

	if remove {
		removed, err := store.RemoveGroupMember(ctx, conn, orgID, name, userID)
		if err != nil {
			return err
		}
		if !removed {
			fmt.Printf("%s was not in %s; nothing to do\n", email, name)
			return nil
		}
		fmt.Printf("removed %s from %s\n", email, name)
		// The honest caveat. Access tokens already issued keep their claims until
		// they expire, and saying so is the difference between an operator who
		// knows to revoke the session and one who assumes the removal was instant.
		fmt.Println("\n  Tokens ALREADY ISSUED still carry this group until they expire.")
		fmt.Println("  New tokens will not: membership is read at issuance, not cached.")
		fmt.Println("  To cut it off now, end their sessions:")
		fmt.Println("    PATCH /admin/users/<id> {\"active\": false}  (then re-activate)")
		return nil
	}

	if err := store.AddGroupMember(ctx, conn, orgID, name, userID, ""); err != nil {
		return err
	}
	fmt.Printf("added %s to %s\n", email, name)
	return nil
}

// groupRelease permits a client to see group membership.
func groupRelease(ctx context.Context, conn *pgx.Conn, orgID, clientID, only string) error {
	if orgID == "" || clientID == "" {
		return fmt.Errorf("give -org and -client-id")
	}
	var onlyGroups []string
	for _, g := range strings.Split(only, ",") {
		if g = strings.TrimSpace(g); g != "" {
			onlyGroups = append(onlyGroups, g)
		}
	}
	if err := store.ReleaseGroupsToClient(ctx, conn, orgID, clientID, onlyGroups); err != nil {
		return err
	}
	if len(onlyGroups) == 0 {
		fmt.Printf("%s may now see ALL group membership\n", clientID)
	} else {
		fmt.Printf("%s may now see only: %s\n", clientID, strings.Join(onlyGroups, ", "))
	}
	fmt.Println("\n  The client must also request the `groups` scope. Both gates apply:")
	fmt.Println("  the scope is asked for by the client, the release is decided by you.")
	return nil
}

// groupList shows groups and their sizes.
func groupList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT g.name, g.display_name,
		       (SELECT count(*) FROM core.group_members m WHERE m.group_id = g.id)
		FROM core.groups g ORDER BY g.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Printf("%-24s %-28s %s\n", "NAME", "DISPLAY NAME", "MEMBERS")
	var n int
	for rows.Next() {
		var name, disp string
		var members int
		if err := rows.Scan(&name, &disp, &members); err != nil {
			return err
		}
		n++
		fmt.Printf("%-24s %-28s %d\n", name, disp, members)
	}
	if n == 0 {
		fmt.Println("(none -- create one with `signari group create`)")
	}
	return rows.Err()
}

// clientSetKeys configures a client for private_key_jwt.
func clientSetKeys(ctx context.Context, conn *pgx.Conn, clientID, jwksPath string) error {
	if clientID == "" || jwksPath == "" {
		return fmt.Errorf("give -client-id and -jwks (a file containing the client's PUBLIC JWKS)")
	}
	raw, err := os.ReadFile(jwksPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", jwksPath, err)
	}

	// Parsed and checked HERE rather than at first use. A key set that turns out
	// to be unusable at 3am, during somebody's first token request, is a much
	// worse discovery than one refused at the moment it is registered.
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("%s is not a JWKS document: %w", jwksPath, err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("%s contains no keys", jwksPath)
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return fmt.Errorf("%s contains PRIVATE key material. Register the public "+
				"half only -- the whole point of private_key_jwt is that we never hold "+
				"anything that can authenticate as this client", jwksPath)
		}
		if !k.Valid() {
			return fmt.Errorf("%s contains a key that is not usable", jwksPath)
		}
	}

	tag, err := conn.Exec(ctx, `
		UPDATE core.clients
		SET token_endpoint_auth_method = 'private_key_jwt', jwks = $2::jsonb,
		    client_secret_hash = NULL, updated_at = now()
		WHERE client_id = $1`, clientID, string(raw))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client with id %q", clientID)
	}

	fmt.Printf("%s now authenticates with private_key_jwt (%d key(s))\n", clientID, len(set.Keys))
	// The secret is dropped, not kept. Leaving it would let an attacker who
	// obtained it keep authenticating -- the exact thing this change retires.
	fmt.Println("\n  The client secret has been REMOVED. It would otherwise remain a")
	fmt.Println("  working credential, which is what moving to keys was meant to end.")
	return nil
}

// policyTest checks a policy file without deploying it.
//
// The same load path the engine uses, so "it passes here" and "it will load"
// are the same statement rather than two things that drift.
func policyTest(path string) error {
	if path == "" {
		return fmt.Errorf("give -policy-file, the policy file to check")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	f, err := policy.Parse(data)
	if err != nil {
		return err
	}
	fmt.Printf("  %s: %s\n", path, f.Summary())
	for _, tc := range f.Tests {
		fmt.Printf("    ok   %s\n", tc.Name)
	}
	fmt.Println("\n  This file will load. Its rules do what its tests say.")
	return nil
}

// policyApply installs a policy file.
func policyApply(ctx context.Context, conn *pgx.Conn, orgID, path string) error {
	if orgID == "" || path == "" {
		return fmt.Errorf("give -org and -policy-file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// Parsed BEFORE storing. A file that would not load must not reach the
	// database, or the next engine start fails on something an operator already
	// believes is deployed.
	f, err := policy.Parse(data)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.access_policies (org_id, document, applied_at)
		VALUES ($1::uuid, $2, now())
		ON CONFLICT (org_id) DO UPDATE
			SET document = EXCLUDED.document, applied_at = now()`,
		orgID, string(data)); err != nil {
		return err
	}
	fmt.Printf("applied %s (%s)\n", path, f.Summary())
	return nil
}

// policyShow prints the policy currently in force.
func policyShow(ctx context.Context, conn *pgx.Conn, orgID string) error {
	var doc string
	var applied time.Time
	if err := conn.QueryRow(ctx,
		`SELECT document, applied_at FROM core.access_policies WHERE org_id = $1::uuid`,
		orgID).Scan(&doc, &applied); err != nil {
		fmt.Println("no policy is in force for that organisation (everything is allowed)")
		return nil
	}
	fmt.Printf("# applied %s\n%s", applied.UTC().Format(time.RFC3339), doc)
	return nil
}

// doctorCmd inspects a deployment and reports what is wrong with it.
//
// Exit status is the point: non-zero when anything critical is found, so it can
// gate a deploy or run from cron. A report nobody reads changes nothing.
func doctorCmd(ctx context.Context, conn *pgx.Conn, issuer string) error {
	if issuer == "" {
		issuer = os.Getenv("SIGNARI_ISSUER")
	}
	rep, err := doctor.Inspect(ctx, conn, issuer)
	if err != nil {
		return err
	}

	fmt.Printf("\n  signari doctor\n\n")
	if len(rep.Findings) == 0 {
		fmt.Println("  Nothing to report.")
	}
	for _, f := range rep.Findings {
		fmt.Printf("  [%-8s] %-14s %s\n", f.Severity, f.Area, f.Summary)
		if f.Severity != doctor.Info {
			fmt.Printf("               -> %s\n", wrap(f.Fix, 62, "                  "))
		}
	}

	// What RAN is printed, always. "No findings" and "nothing ran" have looked
	// identical at least three times in this project's own history, and each
	// time the difference mattered.
	fmt.Printf("\n  checked: %s\n", strings.Join(rep.Checked, ", "))

	crit, warn := rep.Count(doctor.Critical), rep.Count(doctor.Warning)
	fmt.Printf("  %d critical, %d warning, %d info\n\n", crit, warn, rep.Count(doctor.Info))
	if crit > 0 {
		return fmt.Errorf("%d critical finding(s)", crit)
	}
	return nil
}
