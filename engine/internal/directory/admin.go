package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
)

// Directory sources as `signari dir` and the Admin API manage them (6.07):
// registering one, changing how it syncs, mapping its groups onto local ones,
// and running a sync. One copy, so the command and the API cannot come to
// mean different things by "sync".

// SealContextCredentials binds a source's sealed credentials to its column.
const SealContextCredentials = "directory-credentials"

var (
	// ErrSourceInvalid is a source the rules refuse; its message says which.
	ErrSourceInvalid = errors.New("the directory source is not one this engine can use")
	// ErrSourceExists is a slug the organisation already gave a source.
	ErrSourceExists = errors.New("a directory source of that slug already exists in the organisation")
	// ErrSourceUnknown is a slug the organisation gave no source, or one
	// disabled when a sync is asked of it.
	ErrSourceUnknown = errors.New("no enabled directory source of that slug in the organisation")
	// ErrLocalGroupUnknown is a mapping onto a group the organisation does
	// not have.
	ErrLocalGroupUnknown = errors.New("no group of that name in the organisation")
	// ErrMappingUnknown is a mapping removed that was never made.
	ErrMappingUnknown = errors.New("the source does not map that remote group onto that group")
	// ErrSyncRefused is a plan the removal ceiling stopped: a fetch that
	// failed part-way and an upstream outage look identical to everybody
	// having left.
	ErrSyncRefused = errors.New("sync refused: the plan would deactivate or remove more than the source's ceiling")
)

type sourceInvalid struct{ msg string }

func (e sourceInvalid) Error() string        { return e.msg }
func (e sourceInvalid) Is(target error) bool { return target == ErrSourceInvalid }

// SourceSpec is a source to register: google by its service account key and
// an administrator to act as, entra by its credential JSON, ldap by URL, bind
// and base DN and flavour, its bind password the credential.
type SourceSpec struct {
	Kind, Slug, Name    string
	Credentials         []byte
	Domain, Impersonate string
	Filter              string
	LDAPURL, LDAPBindDN string
	LDAPPassword        string
	LDAPBaseDN          string
	LDAPFlavour         string
	LDAPCAPEM           string
	LDAPStartTLS        bool
	FetchGroups         bool
	GroupAttribute      string
	// Tenant is stored as given, except for an entra source, whose
	// credentials name it.
	Tenant string
}

// Validate refuses a source before anything is sealed or written. A
// credentials file is parsed now rather than at the first sync, so a wrong
// one is a refusal here instead of a sync failing quietly later.
func (s *SourceSpec) Validate() error {
	if s.Slug = strings.TrimSpace(s.Slug); s.Slug == "" {
		return sourceInvalid{"give a slug"}
	}
	if s.Name == "" {
		s.Name = s.Slug
	}
	if s.GroupAttribute != "" && s.Kind != "ldap" {
		return sourceInvalid{"a group attribute is for an ldap source; Google and Entra report groups by API"}
	}
	switch s.Kind {
	case "google":
		if _, err := ParseGoogleCredentials(s.Credentials); err != nil {
			return sourceInvalid{err.Error()}
		}
		if s.Impersonate == "" {
			return sourceInvalid{"give the administrator to act as: a Google service account reads nothing " +
				"without domain-wide delegation and one"}
		}
	case "entra":
		c, err := ParseEntraCredentials(s.Credentials)
		if err != nil {
			return sourceInvalid{err.Error()}
		}
		s.Tenant = c.TenantID
	case "ldap":
		switch {
		case s.LDAPURL == "" || s.LDAPBaseDN == "":
			return sourceInvalid{"give the LDAP URL and base DN"}
		case s.LDAPFlavour != "openldap" && s.LDAPFlavour != "ad" && s.LDAPFlavour != "freeipa":
			return sourceInvalid{fmt.Sprintf("the LDAP flavour is openldap, ad or freeipa: it decides which "+
				"attribute is the immutable identifier, and reading the wrong one makes every rename look "+
				"like a departure and an arrival (got %q)", s.LDAPFlavour)}
		case strings.HasPrefix(s.LDAPURL, "ldap://") && !s.LDAPStartTLS:
			return sourceInvalid{fmt.Sprintf("refusing a plaintext bind to %q: the bind password can usually "+
				"read the whole directory. Use ldaps:// or leave StartTLS on", s.LDAPURL)}
		}
		if s.LDAPCAPEM != "" {
			if p := x509.NewCertPool(); !p.AppendCertsFromPEM([]byte(s.LDAPCAPEM)) {
				return sourceInvalid{"the CA bundle contains no certificates"}
			}
		}
		// The bind password is the credential, sealed like any other.
		s.Credentials = []byte(s.LDAPPassword)
	default:
		return sourceInvalid{fmt.Sprintf("a directory source is google, entra or ldap, not %q", s.Kind)}
	}
	return nil
}

// DB is what a registration or a setting needs: a connection, a pool or a
// transaction.
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// AddSource registers a source, its credentials sealed with the root key. It
// starts in dry run, reporting missing people rather than deactivating them.
func AddSource(ctx context.Context, q DB, root *keys.RootKey, orgID string, s SourceSpec) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	if root == nil {
		return "", fmt.Errorf("a source's credentials are sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	sealed, err := root.Seal(s.Credentials, SealContextCredentials)
	if err != nil {
		return "", err
	}
	var id string
	if err := q.QueryRow(ctx, `
		INSERT INTO core.directory_sources
			(org_id, kind, slug, display_name, credentials_enc, domain, impersonate,
			 tenant_id, user_filter, ldap_url, ldap_bind_dn, ldap_base_dn,
			 ldap_flavour, ldap_start_tls, ldap_ca_pem, fetch_groups, ldap_group_attribute)
		VALUES ($1::uuid, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), $9,
		        NULLIF($10,''), NULLIF($11,''), NULLIF($12,''), NULLIF($13,''), $14,
		        NULLIF($15,''), $16, NULLIF($17,''))
		RETURNING id::text`,
		orgID, s.Kind, s.Slug, s.Name, sealed, s.Domain, s.Impersonate, s.Tenant, s.Filter,
		s.LDAPURL, s.LDAPBindDN, s.LDAPBaseDN, s.LDAPFlavour, s.LDAPStartTLS,
		s.LDAPCAPEM, s.FetchGroups, s.GroupAttribute).Scan(&id); err != nil {
		switch {
		case strings.Contains(err.Error(), "ldap_group_attribute"):
			return "", sourceInvalid{"the group attribute is an attribute name, such as memberOf"}
		case strings.Contains(err.Error(), "duplicate key"):
			return "", ErrSourceExists
		}
		return "", err
	}
	return id, nil
}

// SourceChange is what `dir set` changes; a nil field is left as it is, so
// changing one setting never quietly resets another to its default -- on
// the removal ceiling that would widen a safety limit.
type SourceChange struct {
	OnMissing      *string
	MaxDeactivate  *int
	Enabled        *bool
	DryRun         *bool
	FetchGroups    *bool
	GroupAttribute *string
}

// Empty reports whether the change names nothing.
func (c SourceChange) Empty() bool {
	return c.OnMissing == nil && c.MaxDeactivate == nil && c.Enabled == nil && c.DryRun == nil &&
		c.FetchGroups == nil && c.GroupAttribute == nil
}

// Validate refuses a change before anything is written.
func (c SourceChange) Validate() error {
	if c.OnMissing != nil && *c.OnMissing != "report" && *c.OnMissing != "deactivate" {
		return sourceInvalid{fmt.Sprintf("on missing is report or deactivate, not %q", *c.OnMissing)}
	}
	if c.MaxDeactivate != nil && (*c.MaxDeactivate < 0 || *c.MaxDeactivate > 100) {
		return sourceInvalid{"the deactivation ceiling is a percentage, 0 to 100"}
	}
	return nil
}

// ChangeSource applies a change to the organisation's source of that slug.
// An empty group attribute returns it to memberOf.
func ChangeSource(ctx context.Context, q DB, orgID, slug string, c SourceChange) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var groupAttr any
	if c.GroupAttribute != nil {
		groupAttr = *c.GroupAttribute
	}
	tag, err := q.Exec(ctx, `
		UPDATE core.directory_sources
		   SET on_missing             = COALESCE($3::text, on_missing),
		       max_deactivate_percent = COALESCE($4::int, max_deactivate_percent),
		       enabled                = COALESCE($5::boolean, enabled),
		       dry_run                = COALESCE($6::boolean, dry_run),
		       fetch_groups           = COALESCE($7::boolean, fetch_groups),
		       ldap_group_attribute   = CASE WHEN $8 THEN NULLIF($9::text, '') ELSE ldap_group_attribute END,
		       updated_at             = now()
		 WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug, c.OnMissing, c.MaxDeactivate, c.Enabled, c.DryRun, c.FetchGroups,
		c.GroupAttribute != nil, groupAttr)
	if err != nil {
		if strings.Contains(err.Error(), "ldap_group_attribute") {
			return sourceInvalid{"the group attribute is an attribute name, such as memberOf"}
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSourceUnknown
	}
	return nil
}

// MapGroup says which local group a directory group grants. A sync grants
// nothing that is not mapped: a directory reporting a group named `domain
// admins` cannot make anybody an administrator here unless somebody
// deliberately connected the two. A group whose members may impersonate is
// refused by the database, whoever asks.
func MapGroup(ctx context.Context, q DB, orgID, slug, remote, local string) error {
	sourceID, groupID, err := mappingEnds(ctx, q, orgID, slug, local)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `
		INSERT INTO core.directory_group_map (source_id, org_id, remote_group, group_id)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid)
		ON CONFLICT (source_id, remote_group, group_id) DO NOTHING`, sourceID, orgID, remote, groupID)
	switch {
	case err != nil && strings.Contains(err.Error(), "remote_group_check"):
		return sourceInvalid{"a remote group is 1 to 512 characters"}
	case err != nil && strings.Contains(err.Error(), "grants impersonation"):
		return ErrGroupImpersonates
	}
	return err
}

// ErrGroupImpersonates is a mapping onto a group whose members may act as
// other users: whoever administers the directory could add themselves.
var ErrGroupImpersonates = errors.New("that group's members may impersonate others, so no directory may grant it")

// Source is one registered source and what its last sync did, without its
// credentials.
type Source struct {
	ID, Slug, Name, Kind, OnMissing string
	Enabled, DryRun, FetchGroups    bool
	MaxDeactivate                   int
	LastSyncAt                      *time.Time
	LastCreated, LastUpdated        int
	LastDeactivated                 int
	LastError                       string
	Mappings                        []Mapping
}

// Mapping is one remote group and the local group it grants.
type Mapping struct{ RemoteGroup, Group string }

// Sources lists an organisation's sources by slug, with their mappings.
func Sources(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]Source, error) {
	rows, err := q.Query(ctx, `
		SELECT s.id::text, s.slug, s.display_name, s.kind, s.on_missing, s.enabled, s.dry_run, s.fetch_groups,
		       s.max_deactivate_percent, s.last_sync_at, s.last_created, s.last_updated, s.last_deactivated,
		       COALESCE(s.last_error, ''),
		       COALESCE((SELECT array_agg(m.remote_group || E'\t' || g.name ORDER BY m.remote_group, g.name)
		                   FROM core.directory_group_map m JOIN core.groups g ON g.id = m.group_id
		                  WHERE m.source_id = s.id), '{}')
		  FROM core.directory_sources s WHERE s.org_id = $1::uuid ORDER BY s.slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		var maps []string
		if err := rows.Scan(&s.ID, &s.Slug, &s.Name, &s.Kind, &s.OnMissing, &s.Enabled, &s.DryRun, &s.FetchGroups,
			&s.MaxDeactivate, &s.LastSyncAt, &s.LastCreated, &s.LastUpdated, &s.LastDeactivated, &s.LastError,
			&maps); err != nil {
			return nil, err
		}
		s.Mappings = []Mapping{}
		for _, m := range maps {
			remote, group, _ := strings.Cut(m, "\t")
			s.Mappings = append(s.Mappings, Mapping{RemoteGroup: remote, Group: group})
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SourceKind is the kind of the organisation's source of that slug, "" for
// none.
func SourceKind(ctx context.Context, q DB, orgID, slug string) (string, error) {
	var kind string
	err := q.QueryRow(ctx, `SELECT kind FROM core.directory_sources WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return kind, err
}

// UnmapGroup removes a mapping. Memberships it granted are left until the
// next sync, which then sees the group as ungoverned and leaves it alone.
func UnmapGroup(ctx context.Context, q DB, orgID, slug, remote, local string) error {
	sourceID, groupID, err := mappingEnds(ctx, q, orgID, slug, local)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `DELETE FROM core.directory_group_map
		WHERE source_id = $1::uuid AND remote_group = $2 AND group_id = $3::uuid`, sourceID, remote, groupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMappingUnknown
	}
	return nil
}

func mappingEnds(ctx context.Context, q DB, orgID, slug, local string) (sourceID, groupID string, err error) {
	if err := q.QueryRow(ctx, `SELECT id::text FROM core.directory_sources WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&sourceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrSourceUnknown
		}
		return "", "", err
	}
	if err := q.QueryRow(ctx, `SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, local).Scan(&groupID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrLocalGroupUnknown
		}
		return "", "", err
	}
	return sourceID, groupID, nil
}

// SyncReport is what one sync found and did.
type SyncReport struct {
	Upstream, ActiveBefore int
	// Plan describes what the people pass would do, Groups what the group
	// pass did, each as the command prints it.
	Plan, Groups string
	// Applied is false for a dry run: asked for, or configured on the source.
	Applied, DryRunConfigured bool
	// GroupsSkipped is set when mappings exist and the source does not fetch
	// group memberships, so nothing about groups was changed.
	GroupsSkipped bool
}

// Sync runs one reconciliation of the organisation's enabled source of that
// slug: fetch who is upstream, plan the changes here, and apply them unless
// it is a dry run, then the group memberships. A plan past the removal
// ceiling is refused, ErrSyncRefused, with the report saying what it was.
// A fetch or an apply that fails is recorded on the source. pool is tagged
// for the root key, since a sync seals a new person's subject key.
func Sync(ctx context.Context, pool *pgxpool.Pool, root *keys.RootKey, orgID, slug string, apply bool) (SyncReport, error) {
	var r SyncReport
	var id, kind, domain, impersonate, filter, onMissing string
	var lURL, lBindDN, lBaseDN, lFlavour, lCA, lGroupAttr string
	var lStartTLS, fetchGroups, dryRun bool
	var sealed []byte
	var maxPct int
	err := pool.QueryRow(ctx, `
		SELECT id::text, kind, credentials_enc, COALESCE(domain,''), COALESCE(impersonate,''), user_filter,
		       on_missing, dry_run, max_deactivate_percent,
		       COALESCE(ldap_url,''), COALESCE(ldap_bind_dn,''), COALESCE(ldap_base_dn,''),
		       COALESCE(ldap_flavour,''), ldap_start_tls, COALESCE(ldap_ca_pem,''), fetch_groups,
		       COALESCE(ldap_group_attribute, 'memberOf')
		FROM core.directory_sources WHERE org_id = $1::uuid AND slug = $2 AND enabled`, orgID, slug).
		Scan(&id, &kind, &sealed, &domain, &impersonate, &filter, &onMissing, &dryRun, &maxPct,
			&lURL, &lBindDN, &lBaseDN, &lFlavour, &lStartTLS, &lCA, &fetchGroups, &lGroupAttr)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrSourceUnknown
	}
	if err != nil {
		return r, err
	}
	r.DryRunConfigured = dryRun
	raw, err := root.Open(sealed, SealContextCredentials)
	if err != nil {
		return r, fmt.Errorf("unsealing the credentials: %w", err)
	}

	var remote []RemoteUser
	switch kind {
	case "google":
		creds, perr := ParseGoogleCredentials(raw)
		if perr != nil {
			return r, perr
		}
		remote, err = (&GoogleSource{Creds: creds, Impersonate: impersonate, Domain: domain, Query: filter,
			Groups: fetchGroups}).Fetch(ctx)
	case "entra":
		creds, perr := ParseEntraCredentials(raw)
		if perr != nil {
			return r, perr
		}
		remote, err = (&EntraSource{Creds: creds, Filter: filter, Groups: fetchGroups}).Fetch(ctx)
	case "ldap":
		var cas *x509.CertPool
		if lCA != "" {
			cas = x509.NewCertPool()
			if !cas.AppendCertsFromPEM([]byte(lCA)) {
				return r, fmt.Errorf("the stored CA bundle for %q contains no certificates", slug)
			}
		}
		src := &LDAPSource{CAs: cas, URL: lURL, BindDN: lBindDN, Password: string(raw), BaseDN: lBaseDN,
			Filter: filter, Flavour: LDAPFlavour(lFlavour), StartTLS: lStartTLS}
		if fetchGroups {
			src.GroupAttribute = lGroupAttr
			if src.Flavour == FlavourAD {
				// The groups a mapping names, resolved through nesting.
				mappings, merr := LoadGroupMappings(ctx, pool, id)
				if merr != nil {
					return r, merr
				}
				for _, m := range mappings {
					src.NestedGroups = append(src.NestedGroups, m.RemoteGroup)
				}
			}
		}
		remote, err = src.Fetch(ctx)
	}
	if err != nil {
		RecordFailure(ctx, pool, id, err)
		return r, err
	}

	local, err := LoadLocal(ctx, pool, id, orgID)
	if err != nil {
		return r, err
	}
	plan := BuildPlan(remote, local, onMissing, maxPct)
	r.Upstream, r.ActiveBefore, r.Plan = len(remote), plan.ActiveBefore, plan.Describe()
	if !plan.Safe() {
		return r, ErrSyncRefused
	}
	if dryRun || !apply {
		return r, nil
	}
	if err := Apply(ctx, pool, id, orgID, plan); err != nil {
		RecordFailure(ctx, pool, id, err)
		return r, err
	}
	r.Applied = true
	if err := syncGroups(ctx, pool, id, orgID, remote, maxPct, fetchGroups, &r); err != nil {
		RecordFailure(ctx, pool, id, err)
		return r, err
	}
	return r, nil
}

// syncGroups reconciles group membership after the people are in place: a
// membership references a user row, so the order is a requirement. It does
// nothing unless the source fetches groups, because a source with no group
// attribute returns everybody in no groups, which is "this source has
// nothing to say about groups", not "everybody left every group".
func syncGroups(ctx context.Context, pool *pgxpool.Pool, sourceID, orgID string, remote []RemoteUser,
	maxPct int, fetchesGroups bool, r *SyncReport) error {
	mappings, err := LoadGroupMappings(ctx, pool, sourceID)
	if err != nil {
		return err
	}
	if len(mappings) == 0 {
		return nil
	}
	if !fetchesGroups {
		r.GroupsSkipped = true
		return nil
	}
	byRemote, err := LoadLocal(ctx, pool, sourceID, orgID)
	if err != nil {
		return err
	}
	localOf := make(map[string]string, len(byRemote))
	for _, l := range byRemote {
		localOf[l.RemoteID] = l.UserID
	}
	remoteGroups := map[string][]string{}
	for _, u := range remote {
		if local, ok := localOf[u.ID]; ok {
			remoteGroups[local] = u.Groups
		}
	}
	current, err := LoadGroupState(ctx, pool, sourceID, orgID)
	if err != nil {
		return err
	}
	gp := BuildGroupPlan(mappings, remoteGroups, current, maxPct)
	r.Groups = gp.Describe()
	if !gp.Safe() {
		return fmt.Errorf("group sync refused")
	}
	return ApplyGroupPlan(ctx, pool, sourceID, orgID, gp)
}
