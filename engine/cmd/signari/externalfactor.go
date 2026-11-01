package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// `signari external-factor`: the services an external_factor stage may ask
// (10.03), through the writers the Admin API and `apply` share.

func externalFactorAdd(ctx context.Context, conn *pgx.Conn, orgID, name, target, issuer, jwksPath, amr string) error {
	if orgID == "" || name == "" || target == "" || issuer == "" || jwksPath == "" || amr == "" {
		return errors.New("external-factor add needs --org, --name, --url, --issuer, --jwks and --amr")
	}
	blob, err := os.ReadFile(jwksPath)
	if err != nil {
		return fmt.Errorf("reading the service's JWKS: %w", err)
	}
	n, err := store.SetExternalFactor(ctx, conn, orgID, store.ExternalFactor{
		Name: name, URL: target, Issuer: issuer, JWKS: blob, AMR: strings.Split(amr, ",")})
	if err != nil {
		return fmt.Errorf("registering the external factor: %w", err)
	}
	fmt.Printf("registered external factor %q with %d key(s)\n", name, n)
	fmt.Printf("name it in a flow with {stage: external_factor, factor: %s}\n", name)
	return nil
}

func externalFactorList(ctx context.Context, conn *pgx.Conn, orgID, format string) error {
	if orgID == "" {
		return errors.New("external-factor list needs --org")
	}
	out, err := newOutput(format)
	if err != nil {
		return err
	}
	factors, err := store.ExternalFactors(ctx, conn, orgID)
	if err != nil {
		return err
	}
	for _, f := range factors {
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(f.JWKS, &set); err != nil {
			return fmt.Errorf("reading %s's keys: %w", f.Name, err)
		}
		out.add(map[string]any{"name": f.Name, "url": f.URL, "issuer": f.Issuer, "amr": f.AMR,
			"keys": len(set.Keys), "created_at": f.CreatedAt.UTC()})
		if out.text() {
			fmt.Printf("%-24s %s  amr %s  %d key(s)\n", f.Name, f.URL, strings.Join(f.AMR, ","), len(set.Keys))
		}
	}
	if len(factors) == 0 && out.text() {
		fmt.Println("no external factors registered")
	}
	return out.flush()
}

func externalFactorRemove(ctx context.Context, conn *pgx.Conn, orgID, name string) error {
	if orgID == "" || name == "" {
		return errors.New("external-factor remove needs --org and --name")
	}
	removed, err := store.RemoveExternalFactor(ctx, conn, orgID, name)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("no external factor %q in this organisation", name)
	}
	fmt.Printf("removed external factor %q\n", name)
	return nil
}
