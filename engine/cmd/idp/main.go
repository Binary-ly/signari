// Command idp is the engine's operator CLI.
//
//	idp migrate bootstrap   roles, schemas, grants  (requires superuser)
//	idp migrate up          tables, policies, views (runs as idp_engine)
//	idp migrate status      what the database is at, and what this binary expects
//	idp verify              the startup gate, runnable on its own
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sulimanbenhalim/idp/engine/internal/adminapi"
	"github.com/sulimanbenhalim/idp/engine/internal/httpapi"
	"github.com/sulimanbenhalim/idp/engine/internal/janitor"
	"github.com/sulimanbenhalim/idp/engine/internal/keys"
	"github.com/sulimanbenhalim/idp/engine/internal/migrate"
	"github.com/sulimanbenhalim/idp/engine/internal/oidc"
	"github.com/sulimanbenhalim/idp/engine/internal/outbox"
	"github.com/sulimanbenhalim/idp/engine/internal/passwords"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "idp: %v\n", err)
		os.Exit(1)
	}
}

func usage() error {
	fmt.Fprint(os.Stderr, `usage: idp <command> [flags]

commands:
  migrate bootstrap   apply 0001 (roles, schemas, grants) -- needs a superuser DSN
  migrate up          apply 0002+ (tables, policies, views) as idp_engine
  migrate all         bootstrap then up, in one invocation (for containers)
  migrate status      show applied version, pending migrations, live fingerprint
  verify              run the startup schema gate and exit
  instance create     create an instance and its first signing keys
  user create         create a user with a password
  client create       register an OAuth client
  janitor once        run one maintenance pass (serve runs this continuously)
  keys list           show signing keys, their state and when each may advance
  keys rotate         advance the rotation one safe step (run it again later)
  serve               serve the OIDC endpoints

env:
  IDP_ROOT_KEY        base64 of 32 random bytes; wraps stored private key material

flags:
  -dsn string   PostgreSQL connection string (or set IDP_DSN)
  -to int       stop at this version instead of the latest
`)
	return fmt.Errorf("no command given")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	fs := flag.NewFlagSet("idp", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("IDP_DSN"), "PostgreSQL connection string")
	to := fs.Int("to", 0, "stop at this version (0 = latest)")
	issuer := fs.String("issuer", "", "issuer URL, e.g. https://id.example.com")
	name := fs.String("name", "", "instance display name")
	addr := fs.String("addr", ":8080", "listen address for `serve`")
	tlsCert := fs.String("tls-cert", os.Getenv("IDP_TLS_CERT"), "PEM certificate chain; enables HTTPS")
	tlsKey := fs.String("tls-key", os.Getenv("IDP_TLS_KEY"), "PEM private key")
	adminAddr := fs.String("admin-addr", os.Getenv("IDP_ADMIN_ADDR"), "listen address for the admin API (empty = disabled)")
	email := fs.String("email", "", "user email")
	password := fs.String("password", "", "user password")
	clientID := fs.String("client-id", "", "OAuth client_id (settable verbatim, for migration)")
	redirect := fs.String("redirect", "", "registered redirect_uri (exact match)")
	public := fs.Bool("public", false, "register a public client (PKCE, no secret)")
	alg := fs.String("alg", "", "restrict `keys rotate` to one algorithm (default: all in use)")
	promoteNow := fs.Bool("now", false, "promote without waiting for the publication dwell -- key compromise only")

	cmd := args[0]
	rest := args[1:]
	if cmd == "migrate" || cmd == "instance" || cmd == "user" || cmd == "client" ||
		cmd == "janitor" || cmd == "keys" {
		if len(rest) == 0 {
			return usage()
		}
		cmd, rest = cmd+" "+rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("no -dsn given and IDP_DSN is unset")
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
	case "client create":
		return clientCreate(ctx, conn, *clientID, *redirect, *public)
	case "serve":
		return serve(conn, *addr, *tlsCert, *tlsKey, *adminAddr)
	case "janitor once":
		return janitorOnce(ctx, conn)
	case "keys list":
		return keysList(ctx, conn)
	case "keys rotate":
		return keysRotate(ctx, conn, *alg, *promoteNow)
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
		return "", nil, nil, fmt.Errorf("no instance found -- run `idp instance create -issuer …` first: %w", err)
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
			fmt.Printf("%s: published %s as `next`. Run `idp keys rotate` again after %s to promote it.\n",
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
	b64 := os.Getenv("IDP_ROOT_KEY")
	if b64 == "" {
		return nil, fmt.Errorf(
			"IDP_ROOT_KEY is unset (32 random bytes, base64) -- generate one with:\n" +
				"  head -c 32 /dev/urandom | base64")
	}
	return keys.NewRootKeyFromBase64(os.Getenv("IDP_ROOT_KEY_REF"), b64)
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

	var instanceID, issuer string
	err = conn.QueryRow(ctx,
		`SELECT id::text, issuer FROM core.instances ORDER BY created_at LIMIT 1`).
		Scan(&instanceID, &issuer)
	if err != nil {
		return fmt.Errorf("no instance found -- run `idp instance create -issuer …` first: %w", err)
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

	insecureIssuer := os.Getenv("IDP_INSECURE_ISSUER") == "1"
	if insecureIssuer {
		log.Warn("IDP_INSECURE_ISSUER is set: the issuer may be plaintext HTTP. " +
			"Every token, code and client secret in the flow crosses the network readable. " +
			"This must never be set outside local testing.")
	}

	srv, err := httpapi.New(oidc.Config{
		Issuer:              issuer,
		Keys:                set,
		AllowInsecureIssuer: insecureIssuer,
	}, pool, log)
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
		adminToken := os.Getenv("IDP_ADMIN_TOKEN")
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
		return "", fmt.Errorf("no instance -- run `idp instance create` first: %w", err)
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
