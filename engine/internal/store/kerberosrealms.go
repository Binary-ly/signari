package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/kerberos"
	"signari.dev/engine/internal/keys"
)

// An organisation's own Kerberos realm (8.10), as `signari kerberos add-realm` keeps
// it. The keytab is the key to every ticket of the service, so it is sealed here,
// opened only to use it, and never goes out.

const sealContextKerberosKeytab = "kerberos_keytab"

var (
	// ErrKerberosRealm is a realm that cannot be registered as given.
	ErrKerberosRealm = errors.New("that Kerberos realm cannot be registered")
	// ErrKerberosRealmTaken is a host or realm already registered.
	ErrKerberosRealmTaken = errors.New("that host, or that realm in this organisation, is already registered")
	// ErrKerberosRealmUnknown is no such realm in the organisation.
	ErrKerberosRealmUnknown = errors.New("no such Kerberos realm in this organisation")
)

// KerberosRealm is one realm of an organisation.
type KerberosRealm struct {
	ID               string    `json:"id"`
	OrgID            string    `json:"-"`
	Realm            string    `json:"realm"`
	Host             string    `json:"host"`
	ServicePrincipal string    `json:"service_principal"`
	StripRealm       bool      `json:"strip_realm"`
	TrustedRealms    []string  `json:"trusted_realms"`
	CreateAccounts   bool      `json:"create_accounts"`
	CreatedAt        time.Time `json:"created_at"`
	// Keytab is the file, opened, when the realm was read to be used.
	Keytab []byte `json:"-"`
}

// KerberosRealmSpec is a realm to register.
type KerberosRealmSpec struct {
	Realm, Host, ServicePrincipal string
	Keytab                        []byte
	StripRealm                    bool
	TrustedRealms                 []string
	CreateAccounts                bool
}

type kerberosRealmDB interface {
	rowQuerier
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// AddKerberosRealm registers a realm, refusing a keytab that could open nothing here.
func AddKerberosRealm(ctx context.Context, q kerberosRealmDB, root *keys.RootKey, orgID string,
	spec KerberosRealmSpec) (KerberosRealm, error) {

	if root == nil {
		return KerberosRealm{}, errors.New("a keytab is sealed under the root key, and none is configured")
	}
	r := KerberosRealm{OrgID: orgID, Realm: strings.ToUpper(strings.TrimSpace(spec.Realm)),
		Host: strings.ToLower(strings.TrimSpace(spec.Host)), ServicePrincipal: strings.TrimSpace(spec.ServicePrincipal),
		StripRealm: spec.StripRealm, TrustedRealms: []string{}, CreateAccounts: spec.CreateAccounts}
	if r.Realm == "" || r.Host == "" || r.ServicePrincipal == "" {
		return r, fmt.Errorf("%w: a realm, a host and a service principal are all required", ErrKerberosRealm)
	}
	for _, t := range spec.TrustedRealms {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t == "" || t == r.Realm || strings.ContainsAny(t, "@/ ") {
			return r, fmt.Errorf("%w: %q is not another realm to trust", ErrKerberosRealm, t)
		}
		r.TrustedRealms = append(r.TrustedRealms, t)
	}
	if strings.ContainsAny(r.Host, "/:@ ") {
		return r, fmt.Errorf("%w: the host is a name alone, as a browser sends it, not %q", ErrKerberosRealm, r.Host)
	}
	kt, err := kerberos.ParseKeytab(spec.Keytab, "the keytab")
	if err != nil {
		return r, fmt.Errorf("%w: %w", ErrKerberosRealm, err)
	}
	if !kerberos.Holds(kt, r.ServicePrincipal, r.Realm) {
		return r, fmt.Errorf("%w: the keytab has no key for %s in %s, so it would open no ticket",
			ErrKerberosRealm, r.ServicePrincipal, r.Realm)
	}
	sealed, err := root.Seal(spec.Keytab, sealContextKerberosKeytab)
	if err != nil {
		return r, fmt.Errorf("sealing the keytab: %w", err)
	}
	err = q.QueryRow(ctx, `
		INSERT INTO core.kerberos_realms (org_id, realm, host, service_principal, keytab_sealed, strip_realm,
		                                  trusted_realms, create_accounts)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text, created_at`,
		orgID, r.Realm, r.Host, r.ServicePrincipal, sealed, r.StripRealm, r.TrustedRealms, r.CreateAccounts).
		Scan(&r.ID, &r.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return r, ErrKerberosRealmTaken
	}
	return r, err
}

// KerberosRealms lists an organisation's realms, without their keytabs.
func KerberosRealms(ctx context.Context, q kerberosRealmDB, orgID string) ([]KerberosRealm, error) {
	rows, err := q.Query(ctx, `SELECT id::text, org_id::text, realm, host, service_principal, strip_realm,
		trusted_realms, create_accounts, created_at
		FROM core.kerberos_realms WHERE org_id = $1::uuid ORDER BY realm`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KerberosRealm{}
	for rows.Next() {
		var r KerberosRealm
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Realm, &r.Host, &r.ServicePrincipal, &r.StripRealm,
			&r.TrustedRealms, &r.CreateAccounts, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrKerberosNameTaken is a principal whose name an account already holds that is
// not one to sign in to: deactivated, locked, or waiting for approval.
var ErrKerberosNameTaken = errors.New("an account already holds this name")

// CreateUserFromKerberos makes an account for a principal a realm opted to admit,
// by the address it maps to, or its name where the realm strips itself off.
//
// DO NOTHING, and the conflict reported rather than the row returned: this runs
// because no ACTIVE account matched, and one that is deactivated must stay that way
// however good the ticket.
func CreateUserFromKerberos(ctx context.Context, tx pgx.Tx, orgID, name string) (string, error) {
	email, username := name, ""
	if !strings.Contains(name, "@") {
		email, username = "", name
	}
	var userID string
	// No password credential, for the reason CreateUserFromExternal gives.
	err := tx.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, username, user_handle, status)
		VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''),
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
		        'active')
		ON CONFLICT DO NOTHING RETURNING id::text`, orgID, email, username).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrKerberosNameTaken
	}
	return userID, err
}

// RemoveKerberosRealm forgets a realm and its keytab.
func RemoveKerberosRealm(ctx context.Context, q kerberosRealmDB, orgID, realm string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `DELETE FROM core.kerberos_realms WHERE org_id = $1::uuid AND realm = $2 RETURNING id::text`,
		orgID, strings.ToUpper(realm)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrKerberosRealmUnknown
	}
	return id, err
}

func openKerberosRealm(row pgx.Row, root *keys.RootKey) (*KerberosRealm, error) {
	var r KerberosRealm
	var sealed []byte
	err := row.Scan(&r.ID, &r.OrgID, &r.Realm, &r.Host, &r.ServicePrincipal, &r.StripRealm,
		&r.TrustedRealms, &r.CreateAccounts, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, errors.New("a keytab is sealed under the root key, and none is configured")
	}
	if r.Keytab, err = root.Open(sealed, sealContextKerberosKeytab); err != nil {
		return nil, fmt.Errorf("opening the keytab of %s (is the root key correct?): %w", r.Realm, err)
	}
	return &r, nil
}

// KerberosRealmForHost finds the realm a host answers for, in this instance, keytab
// opened, and nil when the host has none. Read on each request: removing a realm takes
// effect on commit, and a cached keytab would go on opening tickets.
func KerberosRealmForHost(ctx context.Context, q rowQuerier, root *keys.RootKey, instanceID, host string) (*KerberosRealm, error) {
	return openKerberosRealm(q.QueryRow(ctx, `
		SELECT k.id::text, k.org_id::text, k.realm, k.host, k.service_principal, k.strip_realm,
		       k.trusted_realms, k.create_accounts, k.keytab_sealed
		  FROM core.kerberos_realms k
		 WHERE k.host = $1 AND `+InInstance("k.org_id", "$2"), host, instanceID), root)
}

// KerberosRealmOfOrg finds an organisation's realm by name, keytab opened, and nil
// when it has none.
func KerberosRealmOfOrg(ctx context.Context, q rowQuerier, root *keys.RootKey, orgID, realm string) (*KerberosRealm, error) {
	return openKerberosRealm(q.QueryRow(ctx, `
		SELECT id::text, org_id::text, realm, host, service_principal, strip_realm,
		       trusted_realms, create_accounts, keytab_sealed
		  FROM core.kerberos_realms WHERE org_id = $1::uuid AND realm = $2`, orgID, strings.ToUpper(realm)), root)
}
