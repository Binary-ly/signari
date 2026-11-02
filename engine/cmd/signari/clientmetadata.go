package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// clientMetadataAllow lets client_id URLs under a prefix sign people in, each document
// read when one of them first arrives. Until there is a rule nothing is ever fetched.
func clientMetadataAllow(ctx context.Context, conn *pgx.Conn, prefix, org, scopes string) error {
	if prefix == "" || org == "" {
		return fmt.Errorf("-url-prefix and -org are required")
	}
	rule := store.ClientMetadataRule{URLPrefix: prefix, OrgID: org, Scopes: splitList(scopes)}
	if err := rule.Validate(); err != nil {
		return err
	}
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	if err := store.SetClientMetadataRule(ctx, conn, instanceID, rule); err != nil {
		return err
	}
	fmt.Printf("a client_id under %s may sign people in to organisation %s from its next request\n", prefix, org)
	return nil
}

func clientMetadataRules(ctx context.Context, conn *pgx.Conn, format string) error {
	out, err := newOutput(format)
	if err != nil {
		return err
	}
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	rows, err := store.ClientMetadataRules(ctx, conn, instanceID)
	if err != nil {
		return err
	}
	if len(rows) == 0 && out.text() {
		fmt.Println("no rules, so no metadata document is ever fetched")
		return nil
	}
	for _, r := range rows {
		out.add(map[string]any{"url_prefix": r.URLPrefix, "org_id": r.OrgID, "scopes": nonNilList(r.Scopes)})
		if out.text() {
			fmt.Printf("%s  organisation %s  scopes %v\n", r.URLPrefix, r.OrgID, r.Scopes)
		}
	}
	return out.flush()
}

// clientMetadataForget stops fetching under a prefix, and deletes what it admitted.
func clientMetadataForget(ctx context.Context, conn *pgx.Conn, prefix string) error {
	if prefix == "" {
		return fmt.Errorf("-url-prefix is required")
	}
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	gone, err := store.RemoveClientMetadataRule(ctx, tx, instanceID, prefix)
	if errors.Is(err, store.ErrClientMetadataRuleUnknown) {
		return fmt.Errorf("no rule for %s", prefix)
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("no longer fetching under %s; %d clients it admitted are gone\n", prefix, gone)
	return nil
}
