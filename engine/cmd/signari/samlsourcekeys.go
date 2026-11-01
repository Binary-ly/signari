package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// This deployment's own keys toward a SAML upstream (8.04), and what the upstream
// is held to using them for.

func samlSourceOrg(ctx context.Context, conn *pgx.Conn, slug string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("give -slug")
	}
	var orgID string
	err := conn.QueryRow(ctx, `SELECT org_id::text FROM core.identity_providers WHERE slug = $1 AND kind = 'saml'`,
		slug).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("no SAML upstream has the slug %q", slug)
	}
	return orgID, err
}

// idpSAMLKey makes a key, retires one, or with neither lists them.
func idpSAMLKey(ctx context.Context, conn *pgx.Conn, slug, purpose, retire string) error {
	orgID, err := samlSourceOrg(ctx, conn, slug)
	if err != nil {
		return err
	}
	if purpose != "" && retire != "" {
		return fmt.Errorf("give -purpose to make a key or -retire to end one, not both")
	}
	if purpose == "" && retire == "" {
		list, err := store.SAMLSourceKeys(ctx, conn, orgID, slug)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("no keys")
		}
		for _, k := range list {
			state := "live"
			if k.RetiredAt != nil {
				state = "retired " + k.RetiredAt.Format("2006-01-02")
			}
			fmt.Printf("%s  %-10s  made %s  %s\n", k.ID, k.Purpose, k.CreatedAt.Format("2006-01-02"), state)
		}
		return nil
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	event := audit.Event{Type: "admin.saml_source_key_retired", OrgID: orgID,
		Detail: map[string]any{"provider": slug, "key": retire}}
	if retire != "" {
		if err := store.RetireSAMLSourceKey(ctx, tx, orgID, slug, retire); err != nil {
			return err
		}
	} else {
		root, err := rootKey()
		if err != nil {
			return err
		}
		k, err := store.AddSAMLSourceKey(ctx, tx, root, orgID, slug, purpose)
		if err != nil {
			return err
		}
		event.Type, event.Detail["key"], event.Detail["purpose"] = "admin.saml_source_key_added", k.ID, purpose
		fmt.Printf("key %s made, for %s. Its certificate is in the upstream's metadata:\n\n%s\n", k.ID, purpose, k.Certificate)
	}
	if err := audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	return tx.Commit(ctx)
}

// idpSAMLUse says what a SAML upstream is held to.
func idpSAMLUse(ctx context.Context, conn *pgx.Conn, slug string, signRequests, requireEncryption *bool) error {
	orgID, err := samlSourceOrg(ctx, conn, slug)
	if err != nil {
		return err
	}
	if signRequests == nil && requireEncryption == nil {
		return fmt.Errorf("give -sign-requests=true|false, -require-encryption=true|false, or both")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetSAMLSourceKeyUse(ctx, tx, orgID, slug, signRequests, requireEncryption); err != nil {
		return err
	}
	event := audit.Event{Type: "admin.saml_source_key_use_set", OrgID: orgID, Detail: map[string]any{"provider": slug}}
	if signRequests != nil {
		event.Detail["sign_requests"] = *signRequests
		fmt.Printf("%s: requests to it are signed: %v\n", slug, *signRequests)
	}
	if requireEncryption != nil {
		event.Detail["require_encryption"] = *requireEncryption
		fmt.Printf("%s: an assertion from it must be encrypted: %v\n", slug, *requireEncryption)
	}
	if err := audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	return tx.Commit(ctx)
}
