package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// idpAddVP registers a wallet sign-in: this deployment as an OpenID4VP verifier
// (12.12). It believes no issuer until `idp vp-issuer` names one.
func idpAddVP(ctx context.Context, conn *pgx.Conn, orgID, slug, name string, allowSignup, allowLinking,
	trustEmail bool, vp store.VPSpec, keyFile, chainFile string) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation this wallet sign-in belongs to")
	case slug == "":
		return fmt.Errorf("give -slug, the short name in /oid4vp/<slug>/start")
	}
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		vp.KeyPEM = string(b)
	}
	if chainFile != "" {
		b, err := os.ReadFile(chainFile)
		if err != nil {
			return err
		}
		vp.ChainPEM = string(b)
	}
	spec := store.IdentityProviderSpec{Slug: slug, Name: name, Kind: "oid4vp", AllowSignup: allowSignup,
		AllowLinking: allowLinking, TrustEmailVerification: trustEmail, VP: &vp}
	if err := spec.Validate(); err != nil {
		return err
	}
	root, err := rootKey()
	if err != nil && vp.KeyPEM != "" {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.AddIdentityProvider(ctx, tx, root, orgID, spec); err != nil {
		if errors.Is(err, store.ErrIdPSlugTaken) {
			return errSlugTaken(slug)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("registered %s (wallet sign-in, %s)\n", spec.Name, vp.Prefix)
	fmt.Printf("  sign-in URL  : /oid4vp/%s/start\n", slug)
	fmt.Printf("  response URI : <issuer>/oid4vp/%s/response\n", slug)
	fmt.Print("\n  It believes no issuer yet: name each one, with the keys its\n")
	fmt.Printf("  credentials are signed with, by `signari idp vp-issuer -slug %s`.\n", slug)
	return nil
}

// idpVPIssuer believes an issuer for a wallet sign-in, with the keys in jwksFile, or
// with -remove stops believing it.
func idpVPIssuer(ctx context.Context, conn *pgx.Conn, slug, issuer, jwksFile string, remove bool) error {
	switch {
	case slug == "":
		return fmt.Errorf("give -slug, the wallet sign-in")
	case issuer == "":
		return fmt.Errorf("give -issuer, exactly as the iss its credentials carry")
	case remove && jwksFile != "":
		return fmt.Errorf("-remove takes no -jwks-file")
	case remove:
		if err := store.RemoveVPTrustedIssuer(ctx, conn, "", slug, issuer); err != nil {
			return err
		}
		fmt.Printf("%s no longer believes %s\n", slug, issuer)
		return nil
	case jwksFile == "":
		return fmt.Errorf("give -jwks-file, the issuer's public signing keys as a JWK Set")
	}
	jwks, err := os.ReadFile(jwksFile)
	if err != nil {
		return err
	}
	if err := store.SetVPTrustedIssuer(ctx, conn, "", slug, issuer, jwks); err != nil {
		return err
	}
	fmt.Printf("%s believes credentials from %s, checked with the keys in %s\n", slug, issuer, jwksFile)
	return nil
}
