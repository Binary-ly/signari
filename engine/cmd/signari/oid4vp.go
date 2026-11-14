package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oid4vp"
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

// idpVPCrossDevice lets a wallet sign-in's wallet be on another device, or with -remove
// stops it.
func idpVPCrossDevice(ctx context.Context, conn *pgx.Conn, slug string, on bool) error {
	if slug == "" {
		return fmt.Errorf("give -slug, the wallet sign-in")
	}
	if err := idpChange(ctx, conn, slug, store.IdentityProviderChange{CrossDevice: &on}); err != nil {
		return err
	}
	if !on {
		fmt.Printf("%s: the wallet has to be on the device the sign-in began on\n", slug)
		return nil
	}
	fmt.Printf("%s: the sign-in page offers a code to scan with a wallet on another device too.\n", slug)
	fmt.Println("  Such an answer cannot be told from one somebody relayed to another person's phone, so it")
	fmt.Println("  signs in only an account already linked to the credential, and only once the code emailed")
	fmt.Println("  to that account's address is typed where the sign-in began. Mail has to be set up.")
	return nil
}

// idpVPIssuer believes an issuer for a wallet sign-in, with the keys in jwksFile, with
// -keys-from-metadata those its metadata publishes, or with -root-cert the key of the
// certificate chain its credentials carry to those roots; or with -remove stops
// believing it.
func idpVPIssuer(ctx context.Context, conn *pgx.Conn, slug, issuer, jwksFile string, fromMetadata bool,
	rootsFile string, remove bool) error {
	ways := 0
	for _, given := range []bool{jwksFile != "", fromMetadata, rootsFile != ""} {
		if given {
			ways++
		}
	}
	switch {
	case slug == "":
		return fmt.Errorf("give -slug, the wallet sign-in")
	case issuer == "":
		return fmt.Errorf("give -issuer, exactly as the iss its credentials carry")
	case remove && ways > 0:
		return fmt.Errorf("-remove takes no -jwks-file, -keys-from-metadata or -root-cert")
	case remove:
		if err := store.RemoveVPTrustedIssuer(ctx, conn, "", slug, issuer); err != nil {
			return err
		}
		fmt.Printf("%s no longer believes %s\n", slug, issuer)
		return nil
	case ways > 1:
		return fmt.Errorf("give one of -jwks-file, -keys-from-metadata or -root-cert: an issuer is believed one way, " +
			"so a credential cannot choose how it is checked")
	case rootsFile != "":
		roots, err := os.ReadFile(rootsFile)
		if err != nil {
			return err
		}
		if err := store.SetVPTrustedIssuerByX5C(ctx, conn, "", slug, issuer, string(roots)); err != nil {
			return err
		}
		fmt.Printf("%s believes credentials from %s whose x5c chain leads to a root in %s and names %s, "+
			"and checks the CRLs that chain names for each presentation\n", slug, issuer, rootsFile, issuer)
		return nil
	case fromMetadata:
		if err := store.SetVPTrustedIssuerByMetadata(ctx, conn, "", slug, issuer); err != nil {
			return err
		}
		where, _ := oid4vp.IssuerMetadataURL(issuer)
		fmt.Printf("%s believes credentials from %s, checked with the keys published at %s, read for each presentation\n",
			slug, issuer, where)
		return nil
	case jwksFile == "":
		return fmt.Errorf("give -jwks-file, the issuer's public signing keys as a JWK Set, -keys-from-metadata, " +
			"or -root-cert, the CAs its certificate chain leads to")
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
