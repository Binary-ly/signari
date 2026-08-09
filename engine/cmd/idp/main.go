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

	"github.com/sulimanbenhalim/idp/engine/internal/httpapi"
	"github.com/sulimanbenhalim/idp/engine/internal/keys"
	"github.com/sulimanbenhalim/idp/engine/internal/migrate"
	"github.com/sulimanbenhalim/idp/engine/internal/oidc"
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
  migrate status      show applied version, pending migrations, live fingerprint
  verify              run the startup schema gate and exit
  instance create     create an instance and its first signing keys
  user create         create a user with a password
  client create       register an OAuth client
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
	email := fs.String("email", "", "user email")
	password := fs.String("password", "", "user password")
	clientID := fs.String("client-id", "", "OAuth client_id (settable verbatim, for migration)")
	redirect := fs.String("redirect", "", "registered redirect_uri (exact match)")
	public := fs.Bool("public", false, "register a public client (PKCE, no secret)")

	cmd := args[0]
	rest := args[1:]
	if cmd == "migrate" || cmd == "instance" || cmd == "user" || cmd == "client" {
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
		return serve(conn, *addr)
	default:
		return usage()
	}
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

func serve(conn *pgx.Conn, addr string) error {
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

	srv, err := httpapi.New(oidc.Config{Issuer: issuer, Keys: set}, pool, log)
	if err != nil {
		return err
	}

	log.Info("serving", "addr", addr, "issuer", issuer, "algs", set.Algorithms())
	h := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return h.ListenAndServe()
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
