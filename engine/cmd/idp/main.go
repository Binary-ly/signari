// Command idp is the engine's operator CLI.
//
//	idp migrate bootstrap   roles, schemas, grants  (requires superuser)
//	idp migrate up          tables, policies, views (runs as idp_engine)
//	idp migrate status      what the database is at, and what this binary expects
//	idp verify              the startup gate, runnable on its own
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sulimanbenhalim/idp/engine/internal/httpapi"
	"github.com/sulimanbenhalim/idp/engine/internal/keys"
	"github.com/sulimanbenhalim/idp/engine/internal/migrate"
	"github.com/sulimanbenhalim/idp/engine/internal/oidc"
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
  serve               serve discovery + JWKS

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

	cmd := args[0]
	rest := args[1:]
	if cmd == "migrate" || cmd == "instance" {
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

	srv, err := httpapi.New(oidc.Config{Issuer: issuer, Keys: set}, log)
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
