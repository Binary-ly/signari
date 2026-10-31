package provision

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// Provisioning targets as `signari scim` and `signari provision` and the
// Admin API manage them (6.07): registering one, converging it on the
// desired state, and creating or deleting the groups this deployment owns
// there. One copy, so the command and the API cannot come to mean different
// things by "sync".

// DB is what these need from a connection or a pool: no transaction is held
// across a call to a target.
type DB interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

var (
	// ErrTargetInvalid is a target the rules refuse; its message says which.
	ErrTargetInvalid = errors.New("the provisioning target is not one this engine can use")
	// ErrTargetExists is a slug the organisation already gave a target.
	ErrTargetExists = errors.New("a target of that slug already exists in the organisation")
	// ErrTargetUnknown is a slug the organisation gave no target.
	ErrTargetUnknown = errors.New("no provisioning target of that slug in the organisation")
	// ErrTargetDisabled is a target taken out of service.
	ErrTargetDisabled = errors.New("that target is disabled")
	// ErrTargetDryRun is a group operation on a target that records without
	// sending: a group cannot be created in a mode that sends nothing.
	ErrTargetDryRun = errors.New("that target is in dry-run mode, which records without sending; " +
		"take it out of dry-run to create or delete a group there")
	// ErrGroupUnknown is a group the organisation does not have.
	ErrGroupUnknown = errors.New("no group of that name in the organisation")
	// ErrGroupProvisioned is a group already created at the target.
	ErrGroupProvisioned = errors.New("that group already exists at the target; sync reconciles its members")
	// ErrGroupNotProvisioned is a group this deployment never created there.
	ErrGroupNotProvisioned = errors.New("that group is not provisioned to the target")
)

type targetInvalid struct{ msg string }

func (e targetInvalid) Error() string        { return e.msg }
func (e targetInvalid) Is(target error) bool { return target == ErrTargetInvalid }

// TargetSpec is a target to register. Kind is scim (the default), google or
// entra. A SCIM target has a base URL and the bearer token it issued; a
// native one has its credentials file, and Google an administrator to act as
// and a domain to create accounts in.
type TargetSpec struct {
	Kind, Slug, Name    string
	BaseURL, Token      string
	Credentials         []byte
	Impersonate, Domain string
	// OnDeactivate is what happens there to somebody deactivated here:
	// deactivate, delete or nothing.
	OnDeactivate string
	DryRun       bool
	// RecreateMissing gives somebody active here a new account when the one
	// linked to them is gone from the target.
	RecreateMissing bool
	// OAuthTokenURL and OAuthClientID have a SCIM target authenticate by the
	// client credentials grant, Token then being the client's secret, with
	// OAuthScope as the scope.
	OAuthTokenURL, OAuthClientID, OAuthScope string
	// Compatibility names what a SCIM target needs that the protocol does not
	// say it should.
	Compatibility []string
}

// validateOAuth refuses half a grant, and a token URL that a secret should not
// be sent to.
func validateOAuth(tokenURL, clientID, scope string) error {
	switch {
	case tokenURL == "" && clientID == "" && scope == "":
	case tokenURL == "" || clientID == "":
		return targetInvalid{"the client credentials grant needs both the token URL and the client id"}
	case !strings.HasPrefix(tokenURL, "https://"):
		return targetInvalid{"the token URL must be https: the client secret is sent to it"}
	}
	return nil
}

func validateCompatibility(kind string, names []string) error {
	if len(names) > 0 && kind != "" && kind != "scim" {
		return targetInvalid{"only a SCIM target has compatibility settings: a native target's API is the provider's"}
	}
	if err := scim.CheckCompatibility(names); err != nil {
		return targetInvalid{err.Error()}
	}
	return nil
}

// Validate refuses a target before anything is sealed or written, and fills
// in the defaults. A native target's credentials are parsed now rather than at
// the first sync, so a wrong file is a refusal here instead of a sync
// failing quietly later.
func (s *TargetSpec) Validate() error {
	if s.Slug = strings.TrimSpace(s.Slug); s.Slug == "" {
		return targetInvalid{"give a slug, a short name for the target"}
	}
	if s.Name == "" {
		s.Name = s.Slug
	}
	if s.OnDeactivate == "" {
		s.OnDeactivate = "deactivate"
	}
	switch s.OnDeactivate {
	case "deactivate", "delete", "nothing":
	default:
		return targetInvalid{fmt.Sprintf("on deactivate is deactivate, delete or nothing, not %q", s.OnDeactivate)}
	}
	if s.Kind != "" && s.Kind != "scim" && (s.OAuthTokenURL != "" || s.OAuthClientID != "" || s.OAuthScope != "") {
		return targetInvalid{"only a SCIM target takes the client credentials grant"}
	}
	if err := validateOAuth(s.OAuthTokenURL, s.OAuthClientID, s.OAuthScope); err != nil {
		return err
	}
	if err := validateCompatibility(s.Kind, s.Compatibility); err != nil {
		return err
	}
	switch s.Kind {
	case "", "scim":
		s.Kind = "scim"
		switch {
		case s.BaseURL == "":
			return targetInvalid{"give the target's SCIM base URL"}
		case !strings.HasPrefix(s.BaseURL, "https://"):
			return targetInvalid{"the base URL must be https: the token can create and delete accounts in " +
				"that system, and it is sent on every request"}
		case s.Token == "" && s.OAuthTokenURL != "":
			return targetInvalid{"give the client secret, as the token: the grant needs one"}
		case s.Token == "":
			return targetInvalid{"give the bearer token the target issued"}
		}
	case "google":
		switch {
		case s.Impersonate == "":
			return targetInvalid{"give the administrator to act as: a Google service account with " +
				"domain-wide delegation does nothing without one"}
		case s.Domain == "":
			return targetInvalid{"give the domain new accounts are created under"}
		}
		if _, err := directory.ParseGoogleCredentials(s.Credentials); err != nil {
			return targetInvalid{err.Error()}
		}
	case "entra":
		if _, err := directory.ParseEntraCredentials(s.Credentials); err != nil {
			return targetInvalid{err.Error()}
		}
	default:
		return targetInvalid{fmt.Sprintf("a target is scim, google or entra, not %q", s.Kind)}
	}
	return nil
}

// AddTarget registers a target, its token or credentials sealed with the
// root key. Nothing is sent until it is synced.
func AddTarget(ctx context.Context, q store.Execer, root *keys.RootKey, orgID string, s TargetSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if root == nil {
		return fmt.Errorf("a target's secret is sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	var err error
	if s.Kind == "scim" {
		var sealed []byte
		if sealed, err = root.Seal([]byte(s.Token), "scim_token"); err != nil {
			return fmt.Errorf("sealing the target token: %w", err)
		}
		_, err = q.Exec(ctx, `
			INSERT INTO core.scim_targets
				(org_id, slug, display_name, base_url, token, on_deactivate, dry_run, recreate_missing,
				 oauth_token_url, oauth_client_id, oauth_scope, compatibility)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), NULLIF($11, ''),
			        COALESCE($12::text[], '{}'))`,
			orgID, s.Slug, s.Name, s.BaseURL, sealed, s.OnDeactivate, s.DryRun, s.RecreateMissing,
			s.OAuthTokenURL, s.OAuthClientID, s.OAuthScope, s.Compatibility)
	} else {
		var sealed []byte
		if sealed, err = root.Seal(s.Credentials, "provision_credentials"); err != nil {
			return fmt.Errorf("sealing the credentials: %w", err)
		}
		_, err = q.Exec(ctx, `
			INSERT INTO core.scim_targets
				(org_id, slug, display_name, kind, credentials_enc, impersonate,
				 target_domain, base_url, token, on_deactivate, dry_run, recreate_missing)
			VALUES ($1::uuid, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), '', '', $8, $9, $10)`,
			orgID, s.Slug, s.Name, s.Kind, sealed, s.Impersonate, s.Domain, s.OnDeactivate, s.DryRun,
			s.RecreateMissing)
	}
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return ErrTargetExists
	}
	return err
}

// TargetChange is what changes about a registered target; nil leaves a field
// as it is. The kind is fixed once registered.
type TargetChange struct {
	Name, BaseURL, OnDeactivate, Impersonate, Domain *string
	DryRun, RecreateMissing                          *bool
	// Token is a SCIM target's, Credentials a native one's.
	Token       *string
	Credentials []byte
	// OAuth is the grant a SCIM target authenticates with, all three together
	// since half of one means nothing, and "" for a token URL ends it.
	OAuth *TargetOAuth
	// Compatibility replaces what a SCIM target needs, when not nil.
	Compatibility []string
}

// TargetOAuth is a target's client credentials grant, without the secret.
type TargetOAuth struct{ TokenURL, ClientID, Scope string }

// UpdateTarget changes a registered target as a configuration file declares
// it (6.19), checked as AddTarget checks a new one. A SCIM target's base URL
// changes only with its token: the one held was issued for the old address,
// and sent to a new one it is handed to whoever answers there.
func UpdateTarget(ctx context.Context, q store.Execer, root *keys.RootKey, orgID, slug, kind string,
	c TargetChange) error {
	switch {
	case c.OnDeactivate != nil && *c.OnDeactivate != "deactivate" && *c.OnDeactivate != "delete" &&
		*c.OnDeactivate != "nothing":
		return targetInvalid{fmt.Sprintf("on deactivate is deactivate, delete or nothing, not %q", *c.OnDeactivate)}
	case c.BaseURL != nil && kind != "scim":
		return targetInvalid{"only a SCIM target has a base URL"}
	case c.BaseURL != nil && !strings.HasPrefix(*c.BaseURL, "https://"):
		return targetInvalid{"the base URL must be https: the token can create and delete accounts in " +
			"that system, and it is sent on every request"}
	case c.BaseURL != nil && c.Token == nil:
		return targetInvalid{"a new base URL needs the token too: the one held was issued for the old " +
			"address, and would be sent to whoever answers at the new one"}
	case c.Token != nil && (kind != "scim" || *c.Token == ""):
		return targetInvalid{"only a SCIM target has a token, and it is never empty"}
	case c.Credentials != nil && kind == "scim":
		return targetInvalid{"a SCIM target has a token, not credentials"}
	case (c.Impersonate != nil || c.Domain != nil) && kind != "google":
		return targetInvalid{"only a Google target acts as an administrator in a domain"}
	case c.OAuth != nil && kind != "scim":
		return targetInvalid{"only a SCIM target takes the client credentials grant"}
	case c.OAuth != nil && c.Token == nil:
		return targetInvalid{"a change of grant needs the secret too: the one held belongs to the old " +
			"grant, and would be sent to whoever answers at the new address"}
	}
	var oauthURL, oauthClient, oauthScope *string
	if c.OAuth != nil {
		if err := validateOAuth(c.OAuth.TokenURL, c.OAuth.ClientID, c.OAuth.Scope); err != nil {
			return err
		}
		if c.OAuth.TokenURL != "" {
			if err := safedial.CheckURL(c.OAuth.TokenURL); err != nil {
				return err
			}
		}
		oauthURL, oauthClient, oauthScope = &c.OAuth.TokenURL, &c.OAuth.ClientID, &c.OAuth.Scope
	}
	if err := validateCompatibility(kind, c.Compatibility); err != nil {
		return err
	}
	if c.BaseURL != nil {
		if err := safedial.CheckURL(*c.BaseURL); err != nil {
			return err
		}
	}
	var token, creds []byte
	if c.Token != nil || c.Credentials != nil {
		if root == nil {
			return fmt.Errorf("a target's secret is sealed under SIGNARI_ROOT_KEY, which is not loaded")
		}
		var err error
		if c.Token != nil {
			if token, err = root.Seal([]byte(*c.Token), "scim_token"); err != nil {
				return fmt.Errorf("sealing the target token: %w", err)
			}
		}
		if c.Credentials != nil {
			if kind == "google" {
				_, err = directory.ParseGoogleCredentials(c.Credentials)
			} else {
				_, err = directory.ParseEntraCredentials(c.Credentials)
			}
			if err != nil {
				return targetInvalid{err.Error()}
			}
			if creds, err = root.Seal(c.Credentials, "provision_credentials"); err != nil {
				return fmt.Errorf("sealing the credentials: %w", err)
			}
		}
	}
	tag, err := q.Exec(ctx, `
		UPDATE core.scim_targets SET
			display_name    = COALESCE($3::text, display_name),
			base_url        = COALESCE($4::text, base_url),
			on_deactivate   = COALESCE($5::text, on_deactivate),
			impersonate     = COALESCE($6::text, impersonate),
			target_domain   = COALESCE($7::text, target_domain),
			dry_run         = COALESCE($8::boolean, dry_run),
			token           = COALESCE($9::bytea, token),
			credentials_enc = COALESCE($10::bytea, credentials_enc),
			recreate_missing = COALESCE($11::boolean, recreate_missing),
			oauth_token_url = CASE WHEN $12::text IS NULL THEN oauth_token_url ELSE NULLIF($12, '') END,
			oauth_client_id = CASE WHEN $13::text IS NULL THEN oauth_client_id ELSE NULLIF($13, '') END,
			oauth_scope     = CASE WHEN $14::text IS NULL THEN oauth_scope ELSE NULLIF($14, '') END,
			compatibility   = COALESCE($15::text[], compatibility)
		 WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug, c.Name, c.BaseURL, c.OnDeactivate, c.Impersonate, c.Domain, c.DryRun, token, creds,
		c.RecreateMissing, oauthURL, oauthClient, oauthScope, c.Compatibility)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTargetUnknown
	}
	return nil
}

// HTTPClient is the client every call to a target is made with: safedial,
// because a target's base URL is stored and is sent a token that can create
// and delete accounts (a target inside the network is named in
// SIGNARI_OUTBOUND_ALLOW_PRIVATE), trusting SIGNARI_SCIM_CA_BUNDLE on top of
// the general roots when it is set.
func HTTPClient() (*http.Client, error) {
	bundle := os.Getenv("SIGNARI_SCIM_CA_BUNDLE")
	if bundle == "" {
		return safedial.Client(30 * time.Second), nil
	}
	pem, err := os.ReadFile(bundle)
	if err != nil {
		return nil, fmt.Errorf("reading SIGNARI_SCIM_CA_BUNDLE: %w", err)
	}
	pool := safedial.Roots()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no certificates", bundle)
	}
	return safedial.ClientTrusting(30*time.Second, pool), nil
}

// SyncResult is what one pass did, or with apply false would do.
type SyncResult struct {
	Created, Deactivated, Deleted, Failed int
	// Recreated gave somebody back an account the target no longer had. Each
	// is one of Created too.
	Recreated int
	// Failures name each account that could not be changed, and why.
	Failures []string
	Groups   []GroupChange
}

// listPageSize is how many accounts one page of a target's list asks for.
const listPageSize = 100

// recreateFloor is how many missing accounts are taken on trust. SafetyLimit is
// a share, and one person of two is not implausible.
const recreateFloor = 5

// missingAccounts says which of the people meant to have an account are linked
// to one the target no longer lists.
//
// A list that came back wrong looks exactly like everybody having been deleted,
// and answering that by creating everybody again is a duplicate of the company at
// any target that does not refuse one. So a share past SafetyLimit is refused, as
// a mass deactivation is, and an operator looks.
func missingAccounts(ctx context.Context, client Provisioner, desired []store.SCIMDesiredUser) (map[string]bool, error) {
	linked := 0
	for _, d := range desired {
		if d.RemoteID != "" && d.Active {
			linked++
		}
	}
	if linked == 0 {
		return nil, nil
	}
	listed, err := client.ListUsers(ctx, listPageSize)
	if err != nil {
		return nil, fmt.Errorf("listing the target's accounts: %w", err)
	}
	there := make(map[string]bool, len(listed))
	for _, u := range listed {
		there[u.RemoteID] = true
	}
	missing := map[string]bool{}
	for _, d := range desired {
		if d.RemoteID != "" && d.Active && !there[d.RemoteID] {
			missing[d.UserID] = true
		}
	}
	if share := float64(len(missing)) / float64(linked); len(missing) >= recreateFloor && share > SafetyLimit {
		return nil, fmt.Errorf("the target lists no account for %d of the %d people linked to one (%.0f%%), over "+
			"the %.0f%% limit, so none were recreated: that is also what a list that came back wrong looks like",
			len(missing), linked, share*100, SafetyLimit*100)
	}
	return missing, nil
}

// gone says the target has no such account, so there is nothing left to take
// away: a deactivation that kept failing on one would fail on every sync.
func gone(err error) bool {
	var se *scim.Error
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

// GroupChange is one provisioned group's reconciliation.
type GroupChange struct {
	Name          string
	Add, Remove   int
	Unreadable    string
	MembersSynced bool
}

// Sync converges a target on the desired state (store.SCIMDesiredState):
// accounts created for people who should have one, deactivated or deleted for
// people who should not, then the members of the groups this deployment
// created there. With apply false it reports and sends nothing but the reads
// a group's members need.
func Sync(ctx context.Context, db DB, t scim.Target, hc *http.Client, apply bool) (SyncResult, error) {
	var r SyncResult
	desired, err := store.SCIMDesiredState(ctx, db, t)
	if err != nil {
		return r, err
	}
	client, err := ForTarget(t, hc)
	if err != nil {
		return r, err
	}
	var missing map[string]bool
	if t.RecreateMissing {
		if missing, err = missingAccounts(ctx, client, desired); err != nil {
			r.Failures = append(r.Failures, err.Error())
			r.Failed++
		}
	}
	for _, d := range desired {
		if missing[d.UserID] {
			d.RemoteID = ""
		}
		switch {
		case d.RemoteID == "" && d.Active:
			if !apply {
				r.Created++
				if missing[d.UserID] {
					r.Recreated++
				}
				continue
			}
			id, err := client.CreateUser(ctx, User{ExternalID: d.UserID, UserName: d.UserName,
				DisplayName: d.DisplayName, Email: d.Email, Active: true})
			if err != nil {
				// A conflict means the account is already there; find it and
				// record its id rather than creating a duplicate or giving up.
				var se *scim.Error
				if errors.As(err, &se) && se.Conflict {
					if found, ferr := client.FindByUserName(ctx, d.UserName); ferr == nil && found != nil {
						id = found.RemoteID
					}
				}
				if id == "" {
					r.Failures = append(r.Failures, fmt.Sprintf("create %s: %v", d.UserName, err))
					r.Failed++
					continue
				}
			}
			if err := store.RecordSCIMLink(ctx, db, t.ID, d.UserID, t.OrgID, id, true); err != nil {
				return r, err
			}
			r.Created++
			if missing[d.UserID] {
				r.Recreated++
			}

		case d.RemoteID != "" && !d.Active:
			if t.OnDeactivate == "nothing" {
				continue
			}
			if !apply {
				r.Deactivated++
				continue
			}
			if err := store.MarkSCIMIntent(ctx, db, t.ID, d.UserID, false); err != nil {
				return r, err
			}
			if t.OnDeactivate == "delete" {
				if err := client.DeleteUser(ctx, d.RemoteID); err != nil {
					r.Failures = append(r.Failures, fmt.Sprintf("delete %s: %v", d.UserName, err))
					r.Failed++
					continue
				}
				if err := store.DropSCIMLink(ctx, db, t.ID, d.UserID); err != nil {
					return r, err
				}
				r.Deleted++
				continue
			}
			if err := client.SetActive(ctx, d.RemoteID, false); gone(err) {
				if err := store.DropSCIMLink(ctx, db, t.ID, d.UserID); err != nil {
					return r, err
				}
				r.Deactivated++
				continue
			} else if err != nil {
				r.Failures = append(r.Failures, fmt.Sprintf("deactivate %s: %v", d.UserName, err))
				r.Failed++
				continue
			}
			if err := store.ConfirmSCIMSync(ctx, db, t.ID, d.UserID); err != nil {
				return r, err
			}
			r.Deactivated++
		}
	}
	// Groups, after the users. A membership references an account, so pushing
	// one before the account exists at the target is a request the target
	// refuses -- and refuses per member, which reads as a flaky integration
	// rather than an ordering mistake.
	groups, err := syncGroups(ctx, db, t, hc, apply)
	r.Groups = groups
	return r, err
}

// syncGroups reconciles the membership of the groups this deployment created
// at a target: driven from core.scim_group_links, never by matching a display
// name, because a target's own administrators may already keep a group of
// that name and a match would adopt it and start removing their members.
func syncGroups(ctx context.Context, db DB, t scim.Target, hc *http.Client, apply bool) ([]GroupChange, error) {
	rows, err := db.Query(ctx, `
		SELECT l.group_id::text, l.remote_id, g.display_name
		FROM core.scim_group_links l
		JOIN core.groups g ON g.id = l.group_id
		WHERE l.target_id = $1::uuid
		ORDER BY g.display_name`, t.ID)
	if err != nil {
		return nil, fmt.Errorf("reading provisioned groups for %s: %w", t.Slug, err)
	}
	type linked struct{ groupID, remoteID, name string }
	var groups []linked
	for rows.Next() {
		var l linked
		if err := rows.Scan(&l.groupID, &l.remoteID, &l.name); err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, nil
	}

	var out []GroupChange
	client, err := groupsAt(t, hc)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		// Who should be in it: our members who have an account at this
		// target. One without is provisioned by the pass above, and the next
		// run picks them up.
		want, err := remoteMembers(ctx, db, t.ID, g.groupID)
		if err != nil {
			return out, err
		}
		remote, gerr := client.GroupMembers(ctx, g.remoteID)
		if gerr != nil {
			out = append(out, GroupChange{Name: g.name, Unreadable: gerr.Error()})
			continue
		}
		have := map[string]bool{}
		for _, m := range remote {
			have[m] = true
		}
		var toAdd, toRemove []string
		for id := range want {
			if !have[id] {
				toAdd = append(toAdd, id)
			}
		}
		for id := range have {
			if !want[id] {
				toRemove = append(toRemove, id)
			}
		}
		sort.Strings(toAdd)
		sort.Strings(toRemove)
		if len(toAdd) == 0 && len(toRemove) == 0 {
			continue
		}
		change := GroupChange{Name: g.name, Add: len(toAdd), Remove: len(toRemove)}
		if !apply {
			out = append(out, change)
			continue
		}
		if err := client.AddGroupMembers(ctx, g.remoteID, toAdd); err != nil {
			return out, fmt.Errorf("adding members to %q at %s: %w", g.name, t.Slug, err)
		}
		if err := client.RemoveGroupMembers(ctx, g.remoteID, toRemove); err != nil {
			return out, fmt.Errorf("removing members from %q at %s: %w", g.name, t.Slug, err)
		}
		// Recorded only after both calls succeeded: a timestamp written on a
		// failed reconciliation says the group is in sync when it is not.
		if _, err := db.Exec(ctx, `
			UPDATE core.scim_group_links SET last_synced_at = now()
			WHERE target_id = $1::uuid AND group_id = $2::uuid`, t.ID, g.groupID); err != nil {
			return out, fmt.Errorf("recording the sync time for %q at %s: %w", g.name, t.Slug, err)
		}
		change.MembersSynced = true
		out = append(out, change)
	}
	return out, nil
}

func remoteMembers(ctx context.Context, db DB, targetID, groupID string) (map[string]bool, error) {
	rows, err := db.Query(ctx, `
		SELECT sl.remote_id
		FROM core.group_members gm
		JOIN core.scim_links sl ON sl.user_id = gm.user_id AND sl.target_id = $1::uuid
		WHERE gm.group_id = $2::uuid`, targetID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	want := map[string]bool{}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		want[rid] = true
	}
	return want, rows.Err()
}

// TargetForGroups loads the organisation's target for a group operation,
// refusing one that is unknown, disabled, or in dry-run mode: dry
// run is refused rather than honoured by doing nothing, which would report
// success for a group that was never created. Through store.LoadSCIMTargets,
// the one loader that knows the token column is sealed.
func TargetForGroups(ctx context.Context, db DB, root *keys.RootKey, orgID, slug string) (scim.Target, error) {
	var zero scim.Target
	targets, err := store.LoadSCIMTargets(ctx, db, root, orgID, slug)
	if err != nil {
		return zero, err
	}
	if len(targets) == 0 {
		// Only enabled targets load, so say which it is: "no such target" sent
		// to somebody who disabled it last week is an hour looking for a typo.
		var exists bool
		if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.scim_targets
			WHERE org_id = $1::uuid AND slug = $2)`, orgID, slug).Scan(&exists); err != nil {
			return zero, err
		}
		if exists {
			return zero, ErrTargetDisabled
		}
		return zero, ErrTargetUnknown
	}
	t := targets[0]
	if t.DryRun {
		return zero, ErrTargetDryRun
	}
	return t, nil
}

// ProvisionGroup creates an organisation's group at a target and records that
// this deployment owns it. The link is what makes every later reconciliation
// safe, and it is written after the target answered, never before: a link
// written first and a create that then failed would claim a group that does
// not exist.
func ProvisionGroup(ctx context.Context, db DB, t scim.Target, hc *http.Client, group string) (string, error) {
	var groupID, displayName string
	if err := db.QueryRow(ctx, `SELECT id::text, display_name FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		t.OrgID, group).Scan(&groupID, &displayName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrGroupUnknown
		}
		return "", err
	}
	if displayName == "" {
		displayName = group
	}
	client, err := groupsAt(t, hc)
	if err != nil {
		return "", err
	}
	var existing string
	err = db.QueryRow(ctx, `SELECT remote_id FROM core.scim_group_links
		WHERE target_id = $1::uuid AND group_id = $2::uuid`, t.ID, groupID).Scan(&existing)
	if err == nil {
		return existing, ErrGroupProvisioned
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	// externalId carries OUR group id, so somebody at the far end can tell
	// which of their groups this system owns, through a rename on either side.
	remoteID, err := client.CreateGroup(ctx, Group{Name: group, DisplayName: displayName, ExternalID: groupID})
	if err != nil {
		return "", fmt.Errorf("creating %q at %s: %w", displayName, t.Slug, err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO core.scim_group_links (target_id, group_id, org_id, remote_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`, t.ID, groupID, t.OrgID, remoteID); err != nil {
		return remoteID, fmt.Errorf("the group was created at %s as %s but the link could not be stored "+
			"(%w); delete it there and try again, or the next attempt creates a second one", t.Slug, remoteID, err)
	}
	return remoteID, nil
}

// DeprovisionGroup deletes a group this deployment created at a target and
// forgets it, in that order: the other leaves a group there that nothing here
// remembers creating, unreachable by every later command. The local group is
// untouched.
func DeprovisionGroup(ctx context.Context, db DB, t scim.Target, hc *http.Client, group string) (string, error) {
	var groupID, remoteID string
	if err := db.QueryRow(ctx, `
		SELECT g.id::text, l.remote_id
		FROM core.groups g
		JOIN core.scim_group_links l ON l.group_id = g.id AND l.target_id = $1::uuid
		WHERE g.org_id = $2::uuid AND g.name = $3`, t.ID, t.OrgID, group).Scan(&groupID, &remoteID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrGroupNotProvisioned
		}
		return "", err
	}
	client, err := groupsAt(t, hc)
	if err != nil {
		return remoteID, err
	}
	if err := client.DeleteGroup(ctx, remoteID); err != nil {
		return remoteID, fmt.Errorf("deleting %s at %s: %w; the link is kept, so nothing here has forgotten "+
			"the group -- fix the target and try again", remoteID, t.Slug, err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM core.scim_group_links WHERE target_id = $1::uuid AND group_id = $2::uuid`,
		t.ID, groupID); err != nil {
		return remoteID, err
	}
	return remoteID, nil
}
