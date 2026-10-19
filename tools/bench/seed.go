package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// benchDomain is the only domain the seeder writes or removes, so it cannot
// touch an account it did not make. `.invalid` is reserved and resolves
// nowhere, so nothing is ever mailed to one.
const benchDomain = "bench.invalid"

// seedCommand fills a Signari organisation with people for the scenarios that
// need a directory of a realistic size: bench-1@bench.invalid upwards, each
// with the password of a template account, so -username and -password can name
// any of them. Written straight to the database as signari_engine, which is a
// thing to do to a benchmark database and nothing else: none of it is audited.
func seedCommand(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "Signari's database, as signari_engine")
	org := fs.String("org", "", "organisation uuid")
	template := fs.String("template", "", "an account in it whose password every seeded person gets")
	users := fs.Int("users", 10000, "how many people")
	remove := fs.Bool("remove", false, "delete every @"+benchDomain+" person in the organisation instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" || *org == "" {
		return fmt.Errorf("give -dsn and -org")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	if *remove {
		tag, err := conn.Exec(ctx, `DELETE FROM core.users WHERE org_id = $1::uuid AND email LIKE $2`,
			*org, "%@"+benchDomain)
		if err != nil {
			return err
		}
		fmt.Printf("removed %d seeded people\n", tag.RowsAffected())
		return nil
	}
	if *template == "" || *users < 1 {
		return fmt.Errorf("give -template and a positive -users")
	}
	var hash, algorithm string
	if err := conn.QueryRow(ctx, `
		SELECT p.hash, p.algorithm FROM core.users u
		  JOIN core.password_credentials p ON p.user_id = u.id
		 WHERE u.org_id = $1::uuid AND lower(u.email) = lower($2)`, *org, *template).
		Scan(&hash, &algorithm); err != nil {
		return fmt.Errorf("the template %s has no password in that organisation: %w", *template, err)
	}

	const batch = 10000
	added := 0
	for from := 1; from <= *users; from += batch {
		to := min(from+batch-1, *users)
		tag, err := conn.Exec(ctx, `
			WITH n AS (
				INSERT INTO core.users (org_id, email, user_handle)
				SELECT $1::uuid, 'bench-' || g || '@' || $5,
				       decode(md5(random()::text) || md5(random()::text) ||
				              md5(random()::text) || md5(random()::text), 'hex')
				  FROM generate_series($2::int, $3::int) g
				ON CONFLICT DO NOTHING
				RETURNING id)
			INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
			SELECT n.id, $1::uuid, $4, $6 FROM n`,
			*org, from, to, hash, benchDomain, algorithm)
		if err != nil {
			return fmt.Errorf("seeding %d-%d: %w", from, to, err)
		}
		added += int(tag.RowsAffected())
	}
	fmt.Printf("seeded %d people (bench-1@%s to bench-%d@%s); %d already existed\n",
		added, benchDomain, *users, benchDomain, *users-added)
	return nil
}
