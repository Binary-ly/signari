package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// A directory source as a configuration file declares it (6.25): what
// Sources lists plus how it is reached, which a plan compares and an export
// writes, and a writer for those once it is registered.

// SourceSettings is a source's registration and settings, without its
// credentials.
type SourceSettings struct {
	Kind, Name, Domain, Impersonate, Tenant, Filter string
	LDAPURL, LDAPBindDN, LDAPBaseDN, LDAPFlavour    string
	LDAPCAPEM, GroupAttribute, OnMissing            string
	LDAPStartTLS, FetchGroups, Enabled, DryRun      bool
	MaxDeactivate                                   int
}

// SourceSettingsOf reads every source's settings, by slug.
func SourceSettingsOf(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) (map[string]SourceSettings, error) {
	rows, err := q.Query(ctx, `
		SELECT slug, kind, display_name, COALESCE(domain, ''), COALESCE(impersonate, ''), COALESCE(tenant_id, ''),
		       COALESCE(user_filter, ''), COALESCE(ldap_url, ''), COALESCE(ldap_bind_dn, ''),
		       COALESCE(ldap_base_dn, ''), COALESCE(ldap_flavour, ''), COALESCE(ldap_ca_pem, ''),
		       COALESCE(ldap_group_attribute, ''), on_missing, ldap_start_tls, fetch_groups, enabled, dry_run,
		       max_deactivate_percent
		  FROM core.directory_sources WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SourceSettings{}
	for rows.Next() {
		var slug string
		var s SourceSettings
		if err := rows.Scan(&slug, &s.Kind, &s.Name, &s.Domain, &s.Impersonate, &s.Tenant, &s.Filter, &s.LDAPURL,
			&s.LDAPBindDN, &s.LDAPBaseDN, &s.LDAPFlavour, &s.LDAPCAPEM, &s.GroupAttribute, &s.OnMissing,
			&s.LDAPStartTLS, &s.FetchGroups, &s.Enabled, &s.DryRun, &s.MaxDeactivate); err != nil {
			return nil, err
		}
		out[slug] = s
	}
	return out, rows.Err()
}

// SourceCredentials opens what a source authenticates with, so a plan can say
// whether the credentials a file names differ. Never shown.
func SourceCredentials(ctx context.Context, q DB, root *keys.RootKey, orgID, slug string) ([]byte, error) {
	var sealed []byte
	if err := q.QueryRow(ctx, `SELECT credentials_enc FROM core.directory_sources WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSourceUnknown
		}
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("source %q's credentials are sealed and no root key is loaded", slug)
	}
	return root.Open(sealed, SealContextCredentials)
}

// ErrCredentialsForAnotherDirectory is a source holding credentials moved to
// another directory without them: they were given for the one it reads, and
// would be sent to the new one.
var ErrCredentialsForAnotherDirectory = errors.New("a source's credentials were given for the directory it " +
	"reads; pointing it at another needs them given again, or they would be sent there")

// UpdateSource changes a registered source as a configuration file declares
// it, the whole registration checked as AddSource checks a new one. The kind
// is fixed. The LDAP URL, the bind DN, the Google administrator and the
// domain move only with the credentials, which were given for the old ones.
func UpdateSource(ctx context.Context, q interface {
	DB
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, root *keys.RootKey, orgID, slug string, s SourceSpec, withCredentials bool) error {
	held, err := SourceSettingsOf(ctx, q, orgID)
	if err != nil {
		return err
	}
	h, ok := held[slug]
	if !ok {
		return ErrSourceUnknown
	}
	if s.Kind != h.Kind {
		return sourceInvalid{fmt.Sprintf("%s is a %s source, and a source's kind is fixed", slug, h.Kind)}
	}
	moved := s.LDAPURL != h.LDAPURL || s.LDAPBindDN != h.LDAPBindDN || s.Impersonate != h.Impersonate ||
		s.Domain != h.Domain
	if moved && !withCredentials {
		return ErrCredentialsForAnotherDirectory
	}
	if !withCredentials {
		// Validate needs credentials to parse; the held ones are kept, so
		// they stand in for the check and are not written.
		creds, err := SourceCredentials(ctx, q, root, orgID, slug)
		if err != nil {
			return err
		}
		s.Credentials, s.LDAPPassword = creds, string(creds)
	}
	s.Slug = slug
	if err := s.Validate(); err != nil {
		return err
	}
	var sealed []byte
	if withCredentials {
		if root == nil {
			return fmt.Errorf("a source's credentials are sealed under SIGNARI_ROOT_KEY, which is not loaded")
		}
		if sealed, err = root.Seal(s.Credentials, SealContextCredentials); err != nil {
			return err
		}
	}
	_, err = q.Exec(ctx, `
		UPDATE core.directory_sources SET
			display_name = $3, credentials_enc = COALESCE($4, credentials_enc), domain = NULLIF($5,''),
			impersonate = NULLIF($6,''), tenant_id = NULLIF($7,''), user_filter = $8, ldap_url = NULLIF($9,''),
			ldap_bind_dn = NULLIF($10,''), ldap_base_dn = NULLIF($11,''), ldap_flavour = NULLIF($12,''),
			ldap_start_tls = $13, ldap_ca_pem = NULLIF($14,''), updated_at = now()
		 WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug, s.Name, sealed, s.Domain, s.Impersonate, s.Tenant, s.Filter, s.LDAPURL, s.LDAPBindDN,
		s.LDAPBaseDN, s.LDAPFlavour, s.LDAPStartTLS, s.LDAPCAPEM)
	if err != nil && strings.Contains(err.Error(), "check") {
		return sourceInvalid{err.Error()}
	}
	return err
}
