package config

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// The kinds whose material is public, so it is in the file (6.25): RFC 9396
// authorization details types and which clients may ask for them, the client
// attesters attestation-based client authentication trusts (their public key
// sets), the credentials this issuer offers, and the CA certificates a
// wallet's key attestation must chain to. Each checked as its writer checks
// it, before anything is written.

// DetailType is an authorization details type the organisation accepts.
type DetailType struct {
	Type        string   `yaml:"type"`
	Fields      []string `yaml:"fields"`
	Required    []string `yaml:"required,omitempty"`
	Description string   `yaml:"description,omitempty"`
	// Clients may ask for it: exactly these when given, left as they are
	// when absent.
	Clients *[]string `yaml:"clients,omitempty"`
}

func (d DetailType) stored() store.DetailType {
	return store.DetailType{Type: d.Type, Fields: d.Fields, Required: d.Required, Description: d.Description}
}

type detailTypeSection struct{}

func (detailTypeSection) kind() string { return "authorization_detail_type" }

// first is false: a type names clients the file may make.
func (detailTypeSection) first() bool { return false }

func (detailTypeSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "authorization_detail_types")
	for i, d := range f.DetailTypes {
		if !once(i, d.Type) {
			continue
		}
		if _, err := store.CheckDetailType(d.stored()); err != nil {
			add("authorization_detail_types[%s]: %v", d.Type, err)
		}
	}
}

func (detailTypeSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.OrgDetailTypes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	inFile := map[string]bool{}
	for _, c := range f.Clients {
		inFile[c.ClientID] = true
	}
	for _, d := range f.DetailTypes {
		if d.Clients == nil {
			continue
		}
		for _, c := range *d.Clients {
			if inFile[c] {
				continue
			}
			// The grant is written by client id alone, so another
			// organisation's client is refused here, not granted there.
			var ours bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1 AND org_id = $2::uuid)`,
				c, orgID).Scan(&ours); err != nil {
				return err
			}
			if !ours {
				return refuse("authorization_detail_types[%s]: the organisation has no client %s; declare it in "+
					"clients", d.Type, c)
			}
		}
	}
	planKeyed(p, "authorization_detail_type", keyBy(f.DetailTypes, func(d DetailType) string { return d.Type }),
		keyBy(have, func(t store.DetailType) string { return t.Type }), prune,
		func(h store.DetailType, w DetailType) string {
			var c changed
			c.note(!sameSet(h.Fields, w.Fields) || !sameSet(h.Required, w.Required), "fields")
			c.note(h.Description != w.Description, "description")
			c.note(w.Clients != nil && !sameSet(h.Clients, *w.Clients), "clients")
			return c.String()
		}, "clients can no longer ask for it")
	return nil
}

func (detailTypeSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.OrgDetailTypes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	// Each client's grants are written whole, so the types the file gives
	// clients for are taken from every client holding them and given to the
	// ones named, and a client's other types are kept.
	governed, want := map[string]bool{}, map[string][]string{}
	affected := map[string]bool{}
	for _, d := range f.DetailTypes {
		c, ok := p.planned("authorization_detail_type", d.Type)
		if ok && c.Action != "delete" {
			if err := store.RegisterDetailType(ctx, tx, orgID, d.stored()); err != nil {
				return refuse("authorization_detail_types[%s]: %v", d.Type, err)
			}
		}
		if !ok || d.Clients == nil {
			continue
		}
		governed[d.Type] = true
		for _, client := range *d.Clients {
			want[client] = append(want[client], d.Type)
			affected[client] = true
		}
	}
	for _, t := range have {
		if governed[t.Type] {
			for _, client := range t.Clients {
				affected[client] = true
			}
		}
	}
	for _, client := range sortedKeys(affected) {
		held, err := store.ClientDetailTypes(ctx, tx, client)
		if err != nil {
			return err
		}
		types := want[client]
		for _, t := range held {
			if !governed[t] {
				types = append(types, t)
			}
		}
		if err := store.SetClientDetailTypes(ctx, tx, client, types); err != nil {
			return refuse("authorization_detail_types: client %s: %v", client, err)
		}
	}
	return nil
}

func (detailTypeSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	_, err := store.RemoveDetailType(ctx, tx, orgID, name)
	return err
}

func (detailTypeSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.OrgDetailTypes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, t := range have {
		clients := sortedCopy(t.Clients)
		f.DetailTypes = append(f.DetailTypes, DetailType{Type: t.Type, Fields: t.Fields, Required: t.Required,
			Description: t.Description, Clients: &clients})
	}
	return nil
}

// Attester is a client attester whose attestations a client may authenticate
// with: its public key set, in the file as JSON Web Keys.
type Attester struct {
	Name        string         `yaml:"name"`
	JWKS        map[string]any `yaml:"jwks"`
	Description string         `yaml:"description,omitempty"`
}

// canonical is a key set as JSON with its keys sorted, so the file's and the
// stored one compare as what they say.
func canonical(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}

func (a Attester) jwks() []byte {
	b, _ := json.Marshal(a.JWKS)
	return b
}

type attesterSection struct{}

func (attesterSection) kind() string { return "client_attester" }
func (attesterSection) first() bool  { return false }

func (attesterSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "client_attesters")
	for i, a := range f.Attesters {
		if !once(i, a.Name) {
			continue
		}
		if _, err := store.CheckAttesterKeys(a.jwks()); err != nil {
			add("client_attesters[%s]: %v", a.Name, err)
		}
	}
}

func (attesterSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.AttesterKeySets(ctx, tx, orgID)
	if err != nil {
		return err
	}
	var failed error
	planKeyed(p, "client_attester", keyBy(f.Attesters, func(a Attester) string { return a.Name }), have, prune,
		func(h store.AttesterKeySet, w Attester) string {
			var c changed
			held, err := canonical(h.JWKS)
			if err != nil && failed == nil {
				failed = err
			}
			want, _ := canonical(w.jwks())
			c.note(held != want, "jwks")
			c.note(w.Description != "" && h.Description != w.Description, "description")
			return c.String()
		}, "clients it attests can no longer authenticate")
	return failed
}

func (attesterSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, a := range f.Attesters {
		if c, ok := p.planned("client_attester", a.Name); !ok || c.Action == "delete" {
			continue
		}
		if _, err := store.SetAttester(ctx, tx, orgID, a.Name, a.jwks(), a.Description); err != nil {
			return err
		}
	}
	return nil
}

func (attesterSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	_, err := store.RemoveAttester(ctx, tx, orgID, name)
	return err
}

func (attesterSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.AttesterKeySets(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(have) {
		var set map[string]any
		if err := json.Unmarshal(have[name].JWKS, &set); err != nil {
			return err
		}
		f.Attesters = append(f.Attesters, Attester{Name: name, JWKS: set, Description: have[name].Description})
	}
	return nil
}

// Credential is a verifiable credential this issuer offers (OID4VCI), written
// whole as `signari credential define` writes it.
type Credential struct {
	ConfigID        string   `yaml:"config_id"`
	VCT             string   `yaml:"vct"`
	DisplayName     string   `yaml:"display_name,omitempty"`
	AlwaysClaims    []string `yaml:"always_claims,omitempty"`
	SelectiveClaims []string `yaml:"selective_claims,omitempty"`
	// Lifetime is how long an issued credential is valid; absent puts no exp
	// in it.
	Lifetime time.Duration `yaml:"lifetime,omitempty"`
	// RequireKeyAttestation absent keeps the setting, off for a new one.
	RequireKeyAttestation *bool `yaml:"require_key_attestation,omitempty"`
}

func (c Credential) spec() store.CredentialSpec {
	return store.CredentialSpec{ConfigID: c.ConfigID, VCT: c.VCT, DisplayName: c.DisplayName, Always: c.AlwaysClaims,
		Selective: c.SelectiveClaims, Lifetime: c.Lifetime, RequireKeyAttestation: c.RequireKeyAttestation}
}

type credentialSection struct{}

func (credentialSection) kind() string { return "credential_configuration" }
func (credentialSection) first() bool  { return false }

func (credentialSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "credential_configurations")
	for i, c := range f.Credentials {
		if !once(i, c.ConfigID) {
			continue
		}
		if err := c.spec().Validate(); err != nil {
			add("credential_configurations[%s]: %v", c.ConfigID, err)
		}
	}
}

func (credentialSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.CredentialConfigurations(ctx, tx, orgID)
	if err != nil {
		return err
	}
	type held = struct {
		VCT, DisplayName  string
		Always, Selective []string
		Lifetime          time.Duration
		Require           bool
	}
	byID := map[string]held{}
	for id, c := range have {
		byID[id] = held{c.VCT, c.DisplayName, c.AlwaysClaims, c.SelectiveClaims, c.Lifetime, c.RequireKeyAttestation}
	}
	planKeyed(p, "credential_configuration", keyBy(f.Credentials, func(c Credential) string { return c.ConfigID }),
		byID, prune, func(h held, w Credential) string {
			var c changed
			c.note(h.VCT != w.VCT, "vct")
			c.note(h.DisplayName != w.DisplayName, "display_name")
			c.note(!sameSet(h.Always, w.AlwaysClaims) || !sameSet(h.Selective, w.SelectiveClaims), "claims")
			c.note(h.Lifetime != w.Lifetime, "lifetime")
			c.note(w.RequireKeyAttestation != nil && h.Require != *w.RequireKeyAttestation, "require_key_attestation")
			return c.String()
		}, "wallets can no longer be issued it; one already issued stays valid until it expires")
	return nil
}

func (credentialSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, c := range f.Credentials {
		if pc, ok := p.planned("credential_configuration", c.ConfigID); !ok || pc.Action == "delete" {
			continue
		}
		if _, err := store.DefineCredential(ctx, tx, orgID, c.spec()); err != nil {
			return err
		}
	}
	return nil
}

func (credentialSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	return store.RemoveCredentialConfiguration(ctx, tx, orgID, name)
}

func (credentialSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.CredentialConfigurations(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, id := range sortedKeys(have) {
		c := have[id]
		require := c.RequireKeyAttestation
		f.Credentials = append(f.Credentials, Credential{ConfigID: id, VCT: c.VCT, DisplayName: c.DisplayName,
			AlwaysClaims: c.AlwaysClaims, SelectiveClaims: c.SelectiveClaims, Lifetime: c.Lifetime,
			RequireKeyAttestation: &require})
	}
	return nil
}

// ProofRoot is a CA a wallet's key attestation must chain to, by its
// certificate in PEM.
type ProofRoot struct {
	Name        string `yaml:"name"`
	Certificate string `yaml:"certificate"`
}

func (r ProofRoot) der() ([]byte, error) {
	der, err := store.ParseProofRootPEM([]byte(r.Certificate))
	if err != nil {
		return nil, err
	}
	_, err = store.CheckProofRoot(der, time.Now())
	return der, err
}

type proofRootSection struct{}

func (proofRootSection) kind() string { return "credential_proof_root" }
func (proofRootSection) first() bool  { return false }

func (proofRootSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "credential_proof_roots")
	for i, r := range f.ProofRoots {
		if !once(i, r.Name) {
			continue
		}
		if _, err := r.der(); err != nil {
			add("credential_proof_roots[%s]: %v", r.Name, err)
		}
	}
}

func (proofRootSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.ProofRootCertificates(ctx, tx, orgID)
	if err != nil {
		return err
	}
	planKeyed(p, "credential_proof_root", keyBy(f.ProofRoots, func(r ProofRoot) string { return r.Name }), have,
		prune, func(h []byte, w ProofRoot) string {
			der, _ := w.der()
			if !bytes.Equal(h, der) {
				return "certificate"
			}
			return ""
		}, "a key attested under it is refused from the next credential request")
	return nil
}

func (proofRootSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, r := range f.ProofRoots {
		if c, ok := p.planned("credential_proof_root", r.Name); !ok || c.Action == "delete" {
			continue
		}
		der, err := r.der()
		if err != nil {
			return refuse("credential_proof_roots[%s]: %v", r.Name, err)
		}
		if err := store.SetCredentialProofRoot(ctx, tx, orgID, r.Name, der); err != nil {
			return err
		}
	}
	return nil
}

func (proofRootSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	return store.RemoveCredentialProofRoot(ctx, tx, orgID, name)
}

func (proofRootSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.ProofRootCertificates(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(have) {
		f.ProofRoots = append(f.ProofRoots, ProofRoot{Name: name,
			Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: have[name]}))})
	}
	return nil
}
