package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// A SAML partner registered from its metadata, and asked again (8.01).

// metadataFlags name a document and how far to believe it.
type metadataFlags struct {
	source     string // a file, or an https URL
	signerPath string
	unsigned   bool
	encrypt    bool
}

// read reads and verifies a partner's metadata, a file being handed over and a
// URL something to go back to.
func (f metadataFlags) read(ctx context.Context, entityID string, was store.SAMLMetadataOrigin) (*saml.EntityMetadata,
	store.SAMLMetadataOrigin, error) {
	r := store.SAMLMetadataRequest{Unsigned: f.unsigned}
	if f.signerPath != "" {
		b, err := os.ReadFile(f.signerPath)
		if err != nil {
			return nil, was, fmt.Errorf("reading the metadata's signer: %w", err)
		}
		r.SignerPEM = string(b)
	}
	switch {
	case strings.Contains(f.source, "://"):
		r.URL = f.source
	case f.source != "":
		b, err := os.ReadFile(f.source)
		if err != nil {
			return nil, was, err
		}
		r.Document = b
	}
	return store.ReadSAMLMetadata(ctx, safedial.Client(30*time.Second), r, entityID, was)
}

// namedOnly is a flag's value when it was given, and empty when it is only its
// default, which is no answer where the metadata lists one of its own.
func namedOnly(fs *flag.FlagSet, name, value string) string {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	if !given {
		return ""
	}
	return value
}

func printMetadataNotes(notes []string) {
	for _, n := range notes {
		fmt.Printf("note: %s\n", n)
	}
}

// samlAddSPFromMetadata registers a service provider from what it says of itself.
func samlAddSPFromMetadata(ctx context.Context, conn *pgx.Conn, orgID, entityID, name, nameIDFormat, acs, slo,
	certPath, encCertPath, keyTransport string, wantSignedRequests bool, meta metadataFlags) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this service provider belongs to")
	case acs != "" || slo != "" || certPath != "" || encCertPath != "":
		return fmt.Errorf("-metadata says where assertions go and which keys are believed; -acs, -slo, -sp-cert " +
			"and -sp-encryption-cert would be a second answer")
	}
	entity, origin, err := meta.read(ctx, entityID, store.SAMLMetadataOrigin{})
	if err != nil {
		return err
	}
	if entity.SP == nil {
		return fmt.Errorf("the metadata of %q declares no SAML 2.0 service provider", entity.EntityID)
	}
	if meta.encrypt && entity.SP.EncryptionCertPEM == "" {
		return fmt.Errorf("-metadata-encrypt was given and the metadata offers no key for encryption")
	}
	spec := store.SAMLProviderSpec{Name: name, NameIDFormat: nameIDFormat, KeyTransport: keyTransport,
		WantSignedRequests: wantSignedRequests}
	spec.ApplyMetadata(entity.EntityID, entity.SP, meta.encrypt, origin)
	if err := spec.Validate(); err != nil {
		return err
	}
	if err := registerSP(ctx, conn, orgID, spec); err != nil {
		return err
	}
	fmt.Printf("registered %s\n  entity id : %s\n  ACS       : %s\n  NameID    : %s\n", spec.Name, spec.EntityID,
		strings.Join(entity.SP.ACSURLs, " "), spec.NameIDFormat)
	if spec.SLOURL != "" {
		fmt.Printf("  logout    : %s on %s\n", spec.SLOURL, spec.SLOBinding)
	}
	printMetadataNotes(entity.Notes)
	if entity.SP.EncryptionCertPEM != "" && !meta.encrypt {
		fmt.Println("note: the provider offers a key for encrypted assertions, which are not on: " +
			"-metadata-encrypt uses it, if it can read AES-256-GCM")
	}
	if origin.URL == "" {
		fmt.Println("note: read from a file, so `saml refresh-sp` will need -metadata again")
	}
	return nil
}

// samlRefreshSP reads a service provider's metadata again and applies it, or with
// -dry-run says what that would do. Only ever when asked: this is what decides
// where assertions go.
func samlRefreshSP(ctx context.Context, conn *pgx.Conn, org, entityID string, meta metadataFlags, dryRun bool) error {
	if entityID == "" {
		return fmt.Errorf("give -entity-id")
	}
	id, orgID, err := store.SAMLProviderByEntity(ctx, conn, org, entityID)
	if errors.Is(err, store.ErrSAMLProviderUnknown) {
		return fmt.Errorf("no service provider has the entity id %q", entityID)
	}
	if err != nil {
		return err
	}
	_, was, err := store.SAMLProviderOriginOf(ctx, conn, orgID, id)
	if err != nil {
		return err
	}
	entity, origin, err := meta.read(ctx, entityID, was)
	if err != nil {
		return err
	}
	if entity.SP == nil {
		return fmt.Errorf("the metadata of %q no longer declares a SAML 2.0 service provider", entityID)
	}
	return refreshed(ctx, conn, orgID, entity.Notes, origin, dryRun, map[string]any{"provider": id, "entity_id": entityID},
		func(tx pgx.Tx) ([]store.SAMLMetadataChange, error) {
			return store.RefreshSAMLProvider(ctx, tx, orgID, id, entity.SP, origin)
		})
}

// idpRefreshSAML is samlRefreshSP for an upstream.
func idpRefreshSAML(ctx context.Context, conn *pgx.Conn, slug string, meta metadataFlags, dryRun bool) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	var orgID string
	if err := conn.QueryRow(ctx, `SELECT org_id::text FROM core.identity_providers WHERE slug = $1 AND kind = 'saml'`,
		slug).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no SAML upstream has the slug %q", slug)
		}
		return err
	}
	entityID, was, err := store.SAMLSourceOriginOf(ctx, conn, orgID, slug)
	if err != nil {
		return err
	}
	entity, origin, err := meta.read(ctx, entityID, was)
	if err != nil {
		return err
	}
	if entity.IdP == nil {
		return fmt.Errorf("the metadata of %q no longer declares a SAML 2.0 identity provider", entityID)
	}
	return refreshed(ctx, conn, orgID, entity.Notes, origin, dryRun, map[string]any{"slug": slug, "entity_id": entityID},
		func(tx pgx.Tx) ([]store.SAMLMetadataChange, error) {
			return store.RefreshSAMLSource(ctx, tx, orgID, slug, entity.IdP, origin)
		})
}

// refreshed runs a refresh, reports it, and for a dry run takes it back.
func refreshed(ctx context.Context, conn *pgx.Conn, orgID string, notes []string, origin store.SAMLMetadataOrigin,
	dryRun bool, detail map[string]any, apply func(pgx.Tx) ([]store.SAMLMetadataChange, error)) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	changes, err := apply(tx)
	if err != nil {
		return err
	}
	printMetadataNotes(notes)
	if len(changes) == 0 {
		fmt.Println("nothing has changed")
	}
	var fields []string
	for _, c := range changes {
		fields = append(fields, c.Field)
		fmt.Printf("%s\n  was : %s\n  now : %s\n", c.Field, c.From, c.To)
	}
	if dryRun {
		fmt.Println("\n-dry-run: nothing was changed")
		return nil
	}
	detail["changes"], detail["signed"], detail["url"], detail["via"] = fields, origin.SignerPEM != "", origin.URL, "cli"
	if err := audit.Write(ctx, tx, audit.Event{Type: "admin.saml_metadata_read", OrgID: orgID, Detail: detail}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	return tx.Commit(ctx)
}
