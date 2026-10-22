package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/config"
	"signari.dev/engine/internal/store"
)

// An organisation's export and its deletion (6.11).

// exportOrgCmd writes an organisation's configuration as the file `signari
// apply` takes: applied to an empty deployment it recreates it, and applied
// to this one it plans nothing. Secrets are not in it (config.Export).
func exportOrgCmd(ctx context.Context, conn *pgx.Conn, orgID, out string) error {
	if orgID == "" {
		return fmt.Errorf("export org needs -org")
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.organizations WHERE id::text = $1)`,
		orgID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no organisation %s", orgID)
	}
	f, err := config.Export(ctx, tx, orgID)
	if err != nil {
		return err
	}
	body, err := f.Marshal()
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if out != "" {
		file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		w = file
	}
	_, err = w.Write(body)
	return err
}

// orgCensus is what deleting an organisation removes, counted.
type orgCensus struct {
	slug, name, status               string
	users, clients, groups, sessions int
}

func readCensus(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string, lock bool) (orgCensus, error) {
	var c orgCensus
	forUpdate := ""
	if lock {
		forUpdate = " FOR UPDATE"
	}
	err := q.QueryRow(ctx, `SELECT slug, display_name, status FROM core.organizations
		WHERE id::text = $1`+forUpdate, orgID).Scan(&c.slug, &c.name, &c.status)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return c, err
	}
	err = q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core.users WHERE org_id::text = $1),
		(SELECT count(*) FROM core.clients WHERE org_id::text = $1),
		(SELECT count(*) FROM core.groups WHERE org_id::text = $1),
		(SELECT count(*) FROM core.sessions WHERE org_id::text = $1 AND revoked_at IS NULL AND not_after > now())`,
		orgID).Scan(&c.users, &c.clients, &c.groups, &c.sessions)
	return c, err
}

// confirmation is the code the second phase must give: a digest of the
// organisation and of what it holds, so a code read before anything changed
// confirms that deletion and no other.
func (c orgCensus) confirmation(orgID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("org-delete-confirmation\x00%s\x00%s\x00%d\x00%d\x00%d",
		orgID, c.slug, c.users, c.clients, c.groups)))
	return hex.EncodeToString(sum[:6])
}

// instanceOrgDelete deletes an organisation in two phases. Without -confirm it
// says what would go and the code to confirm it with; with the code, on an
// organisation suspended first, it erases every person (their keys shredded,
// their sessions ended and their applications told, as erasure does), removes
// the clients and then the organisation, in one transaction, and records it.
// The audit trail is kept: it is append-only and names people by id only.
func instanceOrgDelete(ctx context.Context, conn *pgx.Conn, orgID, confirm string) error {
	if orgID == "" {
		return fmt.Errorf("instance org-delete needs -org")
	}
	c, err := readCensus(ctx, conn, orgID, false)
	if err != nil {
		return err
	}
	code := c.confirmation(orgID)
	if confirm == "" {
		fmt.Printf("Deleting %s (%s) removes, irreversibly:\n", c.slug, c.name)
		fmt.Printf("  %d people, each erased: their key shredded, %d live session(s) ended, applications told\n",
			c.users, c.sessions)
		fmt.Printf("  %d client(s), %d group(s), and every setting, provider and record of the organisation\n",
			c.clients, c.groups)
		fmt.Println("The audit trail is kept; it names people by id only.")
		if c.status != "suspended" {
			fmt.Println("\nSuspend it first, so nothing signs in while it goes:")
			fmt.Printf("  signari instance org-status -org %s -status suspended\n", orgID)
		}
		fmt.Printf("\nThen confirm with:\n  signari instance org-delete -org %s -confirm %s\n", orgID, code)
		return nil
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err = readCensus(ctx, tx, orgID, true)
	if err != nil {
		return err
	}
	switch {
	case c.status != "suspended":
		return fmt.Errorf("%s is %s; suspend it first (`signari instance org-status -status suspended`) "+
			"so nothing signs in while it goes. Nothing was deleted", c.slug, c.status)
	case confirm != c.confirmation(orgID):
		return fmt.Errorf("that code does not confirm deleting %s as it is now; run without -confirm "+
			"to see what it holds and the code for it. Nothing was deleted", c.slug)
	}

	rows, err := tx.Query(ctx, `SELECT id::text FROM core.users WHERE org_id::text = $1`, orgID)
	if err != nil {
		return err
	}
	var people []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		people = append(people, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	ended := 0
	for _, id := range people {
		rep, err := store.EraseSubject(ctx, tx, id, true)
		if err != nil {
			return fmt.Errorf("erasing %s: %w. Nothing was deleted", id, err)
		}
		ended += rep.SessionsEnded
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.clients WHERE org_id::text = $1`, orgID); err != nil {
		return fmt.Errorf("removing the clients: %w. Nothing was deleted", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.organizations WHERE id::text = $1`, orgID); err != nil {
		return fmt.Errorf("removing the organisation: %w. Nothing was deleted", err)
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "admin.organization_deleted", OrgID: orgID,
		Detail: map[string]any{"slug": c.slug, "people_erased": len(people), "clients": c.clients,
			"groups": c.groups, "sessions_ended": ended, "via": "cli", "operator": cliOperator()}}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("deleted %s: %d people erased, %d client(s) and %d group(s) removed, %d session(s) ended\n",
		c.slug, len(people), c.clients, c.groups, ended)
	return nil
}
