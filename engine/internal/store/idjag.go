package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Which client may ask for an Identity Assertion JWT Authorization Grant, for which
// authorization server, and the most it may carry there (draft-ietf-oauth-identity-
// assertion-authz-grant, specs/id-jag.txt).

// ErrIDJAGAudienceUnknown is a client and server with no such entry.
var ErrIDJAGAudienceUnknown = errors.New("no such id-jag audience")

// idJAGAlgorithms is what a grant can be signed with. RS256 is mandatory to implement, and
// a server §3 says SHOULD also take ES256 is the reason for the second.
var idJAGAlgorithms = []string{"RS256", "ES256"}

// IDJAGAudience says that a client may have a grant for a server.
type IDJAGAudience struct {
	ClientID, Audience, RemoteClientID string
	// Resources and Scopes are the most a grant may name. Empty means none, since this
	// is an operator's list of what a client may reach with no person asked.
	Resources, Scopes []string
	// Alg signs the grant; empty is RS256.
	Alg string
}

// Validate refuses what could not be honoured.
func (a IDJAGAudience) Validate() error {
	u, err := url.Parse(a.Audience)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return invalidSetting("the audience is the issuer identifier of an authorization server, an https URL")
	}
	if strings.TrimSpace(a.RemoteClientID) == "" {
		return invalidSetting("name the client as that authorization server knows it")
	}
	if a.Alg != "" && !slices.Contains(idJAGAlgorithms, a.Alg) {
		return invalidSetting("a grant is signed with one of %s", strings.Join(idJAGAlgorithms, ", "))
	}
	return nil
}

// SetIDJAGAudience adds an entry or replaces what it says. It answers the client's
// organisation, and refuses an algorithm the instance holds no active key for, which
// would otherwise be a server error each time a grant was asked for.
func SetIDJAGAudience(ctx context.Context, q outpostDB, a IDJAGAudience) error {
	if err := a.Validate(); err != nil {
		return err
	}
	alg := a.Alg
	if alg == "" {
		alg = "RS256"
	}
	var orgID string
	var held bool
	err := q.QueryRow(ctx, `
		SELECT c.org_id::text,
		       EXISTS (SELECT 1 FROM core.signing_keys k JOIN core.organizations o ON o.instance_id = k.instance_id
		                WHERE o.id = c.org_id AND k.algorithm = $2 AND k.state = 'active' AND k.purpose = 'oidc')
		  FROM core.clients c WHERE c.client_id = $1`, a.ClientID, alg).Scan(&orgID, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrClientNotFound
	}
	if err != nil {
		return err
	}
	if !held {
		return invalidSetting("this instance holds no active %s key; `signari keys rotate -alg %s` publishes one", alg, alg)
	}
	_, err = q.Exec(ctx, `
		INSERT INTO core.id_jag_audiences (client_id, audience, org_id, remote_client_id, resources, scopes, signing_alg)
		VALUES ($1, $2, $3::uuid, $4, $5, $6, $7)
		ON CONFLICT (client_id, audience) DO UPDATE
		   SET remote_client_id = EXCLUDED.remote_client_id, resources = EXCLUDED.resources,
		       scopes = EXCLUDED.scopes, signing_alg = EXCLUDED.signing_alg`,
		a.ClientID, a.Audience, orgID, a.RemoteClientID, nonNil(a.Resources), nonNil(a.Scopes), alg)
	return err
}

// IDJAGAudiences is a client's list.
func IDJAGAudiences(ctx context.Context, q Querier, clientID string) ([]IDJAGAudience, error) {
	rows, err := q.Query(ctx, `SELECT client_id, audience, remote_client_id, resources, scopes, signing_alg
		FROM core.id_jag_audiences WHERE client_id = $1 ORDER BY audience`, clientID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (IDJAGAudience, error) {
		var a IDJAGAudience
		return a, row.Scan(&a.ClientID, &a.Audience, &a.RemoteClientID, &a.Resources, &a.Scopes, &a.Alg)
	})
}

// IDJAGAudienceFor is the entry a request needs, nil if there is none. known says
// whether the organisation trusts that server for anybody, which is §4.3.4.3's line
// between a server it has no relationship with and a client that may not reach it.
func IDJAGAudienceFor(ctx context.Context, q Querier, orgID, clientID, audience string) (entry *IDJAGAudience, known bool, err error) {
	rows, err := q.Query(ctx, `SELECT client_id, audience, remote_client_id, resources, scopes, signing_alg
		FROM core.id_jag_audiences WHERE org_id = $1::uuid AND audience = $2`, orgID, audience)
	if err != nil {
		return nil, false, err
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (IDJAGAudience, error) {
		var a IDJAGAudience
		return a, row.Scan(&a.ClientID, &a.Audience, &a.RemoteClientID, &a.Resources, &a.Scopes, &a.Alg)
	})
	if err != nil {
		return nil, false, err
	}
	for i := range all {
		if all[i].ClientID == clientID {
			return &all[i], true, nil
		}
	}
	return nil, len(all) > 0, nil
}

// AnyIDJAGAudience says whether an instance issues these grants at all.
func AnyIDJAGAudience(ctx context.Context, q outpostDB, instanceID string) (bool, error) {
	var any bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.id_jag_audiences a
		WHERE `+InInstance("a.org_id", "$1")+`)`, instanceID).Scan(&any)
	return any, err
}

// RemoveIDJAGAudience takes an entry away. A grant already out lasts its few minutes.
func RemoveIDJAGAudience(ctx context.Context, q Execer, clientID, audience string) error {
	tag, err := q.Exec(ctx, `DELETE FROM core.id_jag_audiences WHERE client_id = $1 AND audience = $2`, clientID, audience)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrIDJAGAudienceUnknown
	}
	return nil
}

// PersonOfLiveSession is who a session belongs to, if it is still one: live, and its
// person active in an organisation in service. What ID tokens say of a person depends
// on the client, so it is the session that names them.
func PersonOfLiveSession(ctx context.Context, q outpostDB, sid string) (string, error) {
	var userID string
	err := q.QueryRow(ctx, `
		SELECT u.id::text FROM core.sessions s JOIN core.users u ON u.id = s.user_id
		 WHERE s.sid = $1 AND s.revoked_at IS NULL AND s.not_after > now() AND u.status = 'active'
		   AND `+OrgInService("u.org_id"), sid).Scan(&userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("reading a session: %w", err)
	}
	return userID, err
}
