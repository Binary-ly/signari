package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oid4vci"
)

// What `signari credential` and the Admin API configure for OID4VCI issuance
// (6.07): the credentials an organisation issues, the roots an x5c key proof
// may verify to, and the offers that start an issuance.

// CredentialClaims are the claim names a credential may carry.
//
// A fixed list, not "any column": every value here ends up inside a credential
// the holder can present to anybody, so what may appear is a decision rather
// than a projection of whatever the users table happens to hold.
var CredentialClaims = []string{"sub", "email", "email_verified", "preferred_username"}

// ErrCredentialInvalid is a configuration or offer the rules refuse; its
// message says which rule.
var ErrCredentialInvalid = errors.New("the credential setting is not one this issuer can honour")

type credentialInvalid struct{ msg string }

func (e credentialInvalid) Error() string        { return e.msg }
func (e credentialInvalid) Is(target error) bool { return target == ErrCredentialInvalid }

func refuseCredential(format string, a ...any) error {
	return credentialInvalid{fmt.Sprintf(format, a...)}
}

// CredentialSpec is one credential configuration, which becomes one key of
// the issuer metadata's credential_configurations_supported (OID4VCI §12.2).
type CredentialSpec struct {
	ConfigID, VCT, DisplayName string
	Always, Selective          []string
	// Lifetime is how long an issued credential is valid; zero puts no exp
	// in it.
	Lifetime time.Duration
	// RequireKeyAttestation nil keeps a configuration's setting, so
	// redefining the claims does not quietly drop a requirement somebody set.
	RequireKeyAttestation *bool
}

// Validate refuses a configuration that would assert nothing, or something
// that is not on the claims list.
func (c CredentialSpec) Validate() error {
	switch {
	case strings.TrimSpace(c.ConfigID) == "":
		return refuseCredential("a credential configuration needs the identifier a wallet sends as " +
			"credential_configuration_id")
	case strings.TrimSpace(c.VCT) == "":
		return refuseCredential("a credential configuration needs its vct, the credential type identifier; " +
			"SD-JWT VC section 3.2.2.1 requires a collision-resistant name, so use a URL you control, such as " +
			"https://example.com/identity_credential")
	case len(c.Always)+len(c.Selective) == 0:
		return refuseCredential("a credential carrying no claims asserts nothing; available: %s",
			strings.Join(CredentialClaims, ", "))
	case c.Lifetime < 0:
		return refuseCredential("a credential cannot be valid for a negative time")
	}
	for _, name := range append(append([]string{}, c.Always...), c.Selective...) {
		if !slices.Contains(CredentialClaims, name) {
			return refuseCredential("%q is not a claim this issuer can put in a credential; available: %s",
				name, strings.Join(CredentialClaims, ", "))
		}
	}
	for _, name := range c.Always {
		if slices.Contains(c.Selective, name) {
			return refuseCredential("%q is both always visible and selective; revealing it would put the claim "+
				"in the credential twice", name)
		}
	}
	return nil
}

// DefineCredential stores a validated configuration, replacing one of the
// same identifier, and answers whether it requires an attested key. The
// format is written from the constant issuance checks rather than left to the
// column default: the one format implemented is then a fact this states, and
// a second format is a field here and a value that constant's check admits
// (2.30).
func DefineCredential(ctx context.Context, q outpostDB, orgID string, c CredentialSpec) (bool, error) {
	if err := c.Validate(); err != nil {
		return false, err
	}
	var interval any
	if c.Lifetime > 0 {
		interval = fmt.Sprintf("%d seconds", int(c.Lifetime.Seconds()))
	}
	var required bool
	if err := q.QueryRow(ctx, `
		INSERT INTO core.credential_configurations
			(org_id, config_id, vct, always_claims, selective_claims, lifetime, display_name,
			 require_key_attestation, format)
		VALUES ($1::uuid, $2, $3, $4, $5, $6::interval, NULLIF($7,''), COALESCE($8::boolean, false), $9)
		ON CONFLICT (org_id, config_id) DO UPDATE
		SET format = EXCLUDED.format, vct = EXCLUDED.vct, always_claims = EXCLUDED.always_claims,
		    selective_claims = EXCLUDED.selective_claims,
		    lifetime = EXCLUDED.lifetime, display_name = EXCLUDED.display_name,
		    require_key_attestation = COALESCE($8::boolean,
		        credential_configurations.require_key_attestation)
		RETURNING require_key_attestation`,
		orgID, strings.TrimSpace(c.ConfigID), strings.TrimSpace(c.VCT), nonNil(c.Always), nonNil(c.Selective),
		interval, c.DisplayName, c.RequireKeyAttestation, oid4vci.FormatSDJWTVC).Scan(&required); err != nil {
		return false, fmt.Errorf("defining the credential: %w", err)
	}
	return required, nil
}

// ParseProofRootPEM is the one certificate a PEM file names, refusing a file
// with none, with several, or with a private key: a server holding the CA's
// key could mint the chains it is meant to be checking.
func ParseProofRootPEM(blob []byte) ([]byte, error) {
	var der []byte
	for rest := blob; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			return nil, fmt.Errorf("%w: the PEM holds a private key; register only the CA's certificate",
				ErrInvalidProofRoot)
		case block.Type == "CERTIFICATE" && der == nil:
			der = block.Bytes
		case block.Type == "CERTIFICATE":
			return nil, fmt.Errorf("%w: the PEM holds more than one certificate; register each root under "+
				"its own name", ErrInvalidProofRoot)
		}
	}
	if der == nil {
		return nil, fmt.Errorf("%w: it holds no PEM certificate", ErrInvalidProofRoot)
	}
	return der, nil
}

// ErrProofRootUnknown is a root withdrawn that was never registered.
var ErrProofRootUnknown = errors.New("the organisation has no credential proof root of that name")

// RemoveCredentialProofRoot withdraws a root. Chains to it are refused from
// the next credential request, since the endpoint reads the roots on each.
func RemoveCredentialProofRoot(ctx context.Context, q outpostDB, orgID, name string) error {
	tag, err := q.Exec(ctx, `DELETE FROM core.credential_proof_roots WHERE org_id = $1::uuid AND name = $2`,
		orgID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProofRootUnknown
	}
	return nil
}

// ProofRoot is one registered root as an administrator sees it.
type ProofRoot struct {
	Name, Subject string
	// NotAfter is zero for a stored certificate that does not parse.
	NotAfter time.Time
}

// ProofRoots lists an organisation's roots by name.
func ProofRoots(ctx context.Context, q Querier, orgID string) ([]ProofRoot, error) {
	rows, err := q.Query(ctx, `SELECT name, certificate FROM core.credential_proof_roots
		WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProofRoot{}
	for rows.Next() {
		var r ProofRoot
		var der []byte
		if err := rows.Scan(&r.Name, &der); err != nil {
			return nil, err
		}
		r.Subject = "(does not parse)"
		if cert, perr := x509.ParseCertificate(der); perr == nil {
			r.Subject, r.NotAfter = cert.Subject.String(), cert.NotAfter
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OfferSpec is a Credential Offer to mint: the holder, the wallet client the
// redemption uses, what it offers, and whether a transaction code guards it.
type OfferSpec struct {
	UserID, ClientID string
	// CredentialIssuer is the identifier the wallet fetches metadata from.
	CredentialIssuer string
	ConfigIDs        []string
	TxCode           bool
	TxLength         int
	TTL              time.Duration
}

// ErrOfferClientCannotRedeem is a wallet client not registered for the
// pre-authorized code grant, so the offer could not be redeemed.
var ErrOfferClientCannotRedeem = errors.New("the client is not registered for the pre-authorized code grant")

// MintedOffer is an offer made: the offer itself, which carries the
// pre-authorized code, and the transaction code, empty when none guards it.
// Both are bearer secrets shown once.
type MintedOffer struct {
	Offer  *oid4vci.Offer
	TxCode string
}

// OrgIssuer is the issuer of the instance an organisation is served by, the
// Credential Issuer identifier an offer names when this deployment is both
// the authorization server and the credential issuer.
func OrgIssuer(ctx context.Context, q outpostDB, orgID string) (string, error) {
	var issuer string
	err := q.QueryRow(ctx, `SELECT COALESCE(i.issuer, '') FROM core.organizations o
		LEFT JOIN core.instances i ON i.id = o.instance_id WHERE o.id = $1::uuid`, orgID).Scan(&issuer)
	return issuer, err
}

// offerDB is what minting an offer reads and writes through: a connection, a
// pool or a transaction.
type offerDB interface {
	outpostDB
	Querier
}

// MintCredentialOffer checks an offer and records its pre-authorized code,
// OID4VCI's pre-authorized code grant: §6.1 lets the wallet redeem it sending
// nothing but the code, so everything that decides what the resulting token
// can do is decided here, and checked now rather than at redemption, where
// the holder would be the one to find out, wherever they scanned it.
func MintCredentialOffer(ctx context.Context, q offerDB, orgID string, s OfferSpec) (*MintedOffer, error) {
	switch {
	case s.ClientID == "":
		return nil, refuseCredential("an offer needs the wallet client whose scopes and token lifetimes the " +
			"redemption uses; OID4VCI section 6.1 lets the wallet omit client_id when it redeems, so this is " +
			"the only chance to decide it")
	case len(s.ConfigIDs) == 0:
		return nil, refuseCredential("an offer needs at least one credential_configuration_id, as it appears " +
			"in the Credential Issuer's metadata; an offer of nothing is not an offer")
	case s.TTL <= 0 || s.TTL > time.Hour:
		return nil, refuseCredential("an offer lasts between a moment and an hour; section 3.5 says a "+
			"pre-authorized code MUST be short lived, and it is redeemed within seconds of being scanned "+
			"(got %s)", s.TTL)
	}
	if err := oid4vci.ValidateIssuer(s.CredentialIssuer); err != nil {
		return nil, refuseCredential("%v", err)
	}
	var clientOrg string
	var grants []string
	if err := q.QueryRow(ctx, `SELECT org_id::text, grant_types FROM core.clients WHERE client_id = $1`,
		s.ClientID).Scan(&clientOrg, &grants); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, refuseCredential("no client %q is registered; the offer would redeem into a token with "+
				"no audience", s.ClientID)
		}
		return nil, err
	}
	if clientOrg != orgID {
		return nil, refuseCredential("client %q belongs to another organisation than the holder; a token "+
			"minted for it would cross a tenant boundary", s.ClientID)
	}
	if !slices.Contains(grants, oid4vci.GrantType) {
		return nil, fmt.Errorf("%w: %s is not, so this offer could not be redeemed", ErrOfferClientCannotRedeem,
			s.ClientID)
	}
	var inOrg bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE id = $1::uuid AND org_id = $2::uuid)`,
		s.UserID, orgID).Scan(&inOrg); err != nil {
		return nil, err
	}
	if !inOrg {
		return nil, refuseCredential("the holder is not in the organisation")
	}
	// §4.1.1: the ids "each identify one of the keys in the name/value pairs
	// stored in the credential_configurations_supported Credential Issuer
	// metadata". Without the check a typo makes a well-formed offer that the
	// credential endpoint answers unsupported_credential_type after the
	// holder has done everything asked of them correctly.
	configured, err := CredentialConfigurations(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	var unknown []string
	for _, id := range s.ConfigIDs {
		if _, ok := configured[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(configured))
		for id := range configured {
			known = append(known, id)
		}
		sort.Strings(known)
		if len(known) == 0 {
			return nil, refuseCredential("this organisation issues no credentials, so an offer naming %s could "+
				"not be redeemed; define one first", strings.Join(unknown, ", "))
		}
		return nil, refuseCredential("no credential configuration named %s; this issuer advertises %s",
			strings.Join(unknown, ", "), strings.Join(known, ", "))
	}

	code, codeHash, err := NewPreAuthCode()
	if err != nil {
		return nil, err
	}
	var tx *oid4vci.TxCode
	var txPlain string
	var txHash []byte
	if s.TxCode {
		if txPlain, txHash, err = NewTxCode(s.TxLength); err != nil {
			return nil, refuseCredential("%v", err)
		}
		tx = &oid4vci.TxCode{InputMode: oid4vci.InputNumeric, Length: s.TxLength,
			Description: fmt.Sprintf("Enter the %d-digit code from the issuer", s.TxLength)}
	}
	offer, err := oid4vci.BuildOffer(s.CredentialIssuer, s.ConfigIDs, code, tx)
	if err != nil {
		return nil, refuseCredential("%v", err)
	}
	if err := NewPreAuthorizedCode(ctx, q, orgID, s.UserID, s.ClientID, codeHash, s.ConfigIDs, tx, txHash,
		s.TTL); err != nil {
		return nil, err
	}
	return &MintedOffer{Offer: offer, TxCode: txPlain}, nil
}
