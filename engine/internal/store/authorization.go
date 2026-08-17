package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"signari.dev/engine/internal/authzen"
)

// Relations, the model, and the facts an authorization decision is made from.

// Relation is one (subject, relation, object) tuple.
type Relation struct {
	SubjectType string
	SubjectID   string
	Relation    string
	ObjectType  string
	ObjectID    string
	ExpiresAt   *time.Time
}

// GrantRelation records one.
func GrantRelation(ctx context.Context, e Execer, orgID string, r Relation,
	grantedBy string) error {

	var by any
	if grantedBy != "" {
		by = grantedBy
	}
	_, err := e.Exec(ctx, `
		INSERT INTO core.relations
			(org_id, subject_type, subject_id, relation, object_type, object_id,
			 granted_by, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid, $8)
		ON CONFLICT (org_id, subject_type, subject_id, relation, object_type, object_id)
		DO UPDATE SET expires_at = EXCLUDED.expires_at, granted_at = now(),
		              granted_by = EXCLUDED.granted_by`,
		orgID, r.SubjectType, r.SubjectID, r.Relation, r.ObjectType, r.ObjectID,
		by, r.ExpiresAt)
	return err
}

// RevokeRelation removes one.
func RevokeRelation(ctx context.Context, e Execer, orgID string, r Relation) error {
	_, err := e.Exec(ctx, `
		DELETE FROM core.relations
		 WHERE org_id = $1::uuid AND subject_type = $2 AND subject_id = $3
		   AND relation = $4 AND object_type = $5 AND object_id = $6`,
		orgID, r.SubjectType, r.SubjectID, r.Relation, r.ObjectType, r.ObjectID)
	return err
}

// HoldsAny reports whether the subject holds any of these relations on the
// object, directly or through a group they belong to.
//
// Group indirection is resolved HERE rather than by requiring the caller to
// expand it, because the caller does not know the groups -- we do, and taking
// their word for it is the thing this design exists to avoid.
func HoldsAny(ctx context.Context, q Querier, orgID, subjectType, subjectID string,
	relations []string, objectType, objectID string, viaGroups []string) (
	held string, err error) {

	if len(relations) == 0 {
		return "", nil
	}

	// The subject itself, plus every group it belongs to, as (type, id) pairs.
	// One query rather than one per group: a subject in forty groups must not
	// cost forty round trips on the path of an authorization decision.
	types := []string{subjectType}
	ids := []string{subjectID}
	for _, g := range viaGroups {
		types = append(types, "group")
		ids = append(ids, g)
	}

	rows, err := q.Query(ctx, `
		SELECT r.relation
		  FROM core.relations r
		  JOIN unnest($2::text[], $3::text[]) AS s(styp, sid)
		    ON r.subject_type = s.styp AND r.subject_id = s.sid
		 WHERE r.org_id = $1::uuid
		   AND r.relation = ANY ($4::text[])
		   AND r.object_type = $5 AND r.object_id = $6
		   -- An expired grant is not a grant. Checked in the query rather than
		   -- swept by a job, so a relation stops working at the moment it
		   -- expires rather than at the next janitor pass.
		   AND (r.expires_at IS NULL OR r.expires_at > now())
		 LIMIT 1`,
		orgID, types, ids, relations, objectType, objectID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&held); err != nil {
			return "", err
		}
		return held, nil
	}
	return "", rows.Err()
}

// ObjectsWith returns the objects of a type on which the subject holds any of
// these relations. For the resource-search endpoint.
func ObjectsWith(ctx context.Context, q Querier, orgID, subjectType, subjectID string,
	relations []string, objectType string, viaGroups []string, limit int) (
	[]string, error) {

	if len(relations) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	types := []string{subjectType}
	ids := []string{subjectID}
	for _, g := range viaGroups {
		types = append(types, "group")
		ids = append(ids, g)
	}

	rows, err := q.Query(ctx, `
		SELECT DISTINCT r.object_id
		  FROM core.relations r
		  JOIN unnest($2::text[], $3::text[]) AS s(styp, sid)
		    ON r.subject_type = s.styp AND r.subject_id = s.sid
		 WHERE r.org_id = $1::uuid AND r.relation = ANY ($4::text[])
		   AND r.object_type = $5
		   AND (r.expires_at IS NULL OR r.expires_at > now())
		 ORDER BY r.object_id
		 LIMIT $6`, orgID, types, ids, relations, objectType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SubjectsWith returns the subjects holding any of these relations on an
// object. For the subject-search endpoint.
//
// Groups are expanded to their members, because "who can edit this document" is
// asked about people. Answering `group:finance` would be true and useless.
func SubjectsWith(ctx context.Context, q Querier, orgID string, relations []string,
	objectType, objectID string, limit int) ([]string, error) {

	if len(relations) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := q.Query(ctx, `
		WITH direct AS (
			SELECT subject_type, subject_id FROM core.relations
			 WHERE org_id = $1::uuid AND relation = ANY ($2::text[])
			   AND object_type = $3 AND object_id = $4
			   AND (expires_at IS NULL OR expires_at > now())
		)
		SELECT DISTINCT sid FROM (
			SELECT subject_id AS sid FROM direct WHERE subject_type = 'user'
			UNION
			-- Group grants expand to their members: the question is about
			-- people, and answering "group:finance" is true and useless.
			SELECT m.user_id::text FROM direct d
			  JOIN core.groups g ON g.name = d.subject_id AND g.org_id = $1::uuid
			  JOIN core.group_members m ON m.group_id = g.id
			 WHERE d.subject_type = 'group'
		) all_subjects
		 ORDER BY sid LIMIT $5`, orgID, relations, objectType, objectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SaveModel stores and compiles an organisation's authorization model.
func SaveModel(ctx context.Context, e Execer, orgID, source string,
	m *authzen.Model, by string) error {

	compiled, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var who any
	if by != "" {
		who = by
	}
	_, err = e.Exec(ctx, `
		INSERT INTO core.authorization_models (org_id, source, compiled, updated_by)
		VALUES ($1::uuid, $2, $3, $4::uuid)
		ON CONFLICT (org_id) DO UPDATE SET
			source = EXCLUDED.source, compiled = EXCLUDED.compiled,
			updated_at = now(), updated_by = EXCLUDED.updated_by`,
		orgID, source, compiled, who)
	return err
}

// LoadModel reads the compiled model.
func LoadModel(ctx context.Context, q Querier, orgID string) (*authzen.Model, error) {
	rows, err := q.Query(ctx,
		`SELECT compiled FROM core.authorization_models WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	var raw []byte
	if err := rows.Scan(&raw); err != nil {
		return nil, err
	}
	var m authzen.Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the stored authorization model did not load: %w", err)
	}
	return &m, nil
}

// ModelSource returns the YAML as written.
func ModelSource(ctx context.Context, q Querier, orgID string) (string, error) {
	rows, err := q.Query(ctx,
		`SELECT source FROM core.authorization_models WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		return s, nil
	}
	return "", rows.Err()
}

// SubjectFacts is what we know about a subject from OUR OWN records.
//
// # The point of the whole design
//
// A standalone policy decision point is told about the subject by the calling
// application, because it has no other source. So "this user is in group
// finance" is believed, and every authorization decision is only as trustworthy
// as the least careful service that makes one.
//
// These come from the session we issued and the directory we hold. An
// application cannot inflate them, because it is not asked.
func SubjectFacts(ctx context.Context, q Querier, orgID, userID, sid string) (
	authzen.Facts, error) {

	var f authzen.Facts

	// The clock is ours, not the caller's. A time restriction an application
	// can lie about is a comment.
	f.Now = time.Now()

	rows, err := q.Query(ctx, `
		SELECT COALESCE(array_agg(g.name) FILTER (WHERE g.name IS NOT NULL), '{}')
		  FROM core.group_members m
		  JOIN core.groups g ON g.id = m.group_id
		 WHERE m.user_id = $1::uuid AND g.org_id = $2::uuid`, userID, orgID)
	if err != nil {
		return f, err
	}
	if rows.Next() {
		if err := rows.Scan(&f.Groups); err != nil {
			rows.Close()
			return f, err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return f, err
	}

	// Account state, from our directory. A deactivated user whose relations were
	// never cleaned up still holds them; this is what stops the tuples outliving
	// the account.
	rows, err = q.Query(ctx, `
		SELECT status = 'active', email_verified_at IS NOT NULL
		  FROM core.users WHERE id = $1::uuid AND org_id = $2::uuid`, userID, orgID)
	if err != nil {
		return f, err
	}
	if rows.Next() {
		if err := rows.Scan(&f.Active, &f.EmailVerified); err != nil {
			rows.Close()
			return f, err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return f, err
	}

	if sid == "" {
		// No session named, so nothing was proved in one. Facts that depend on
		// a session stay false rather than being assumed -- an unproved second
		// factor must not satisfy a rule that demands one.
		return f, nil
	}

	rows, err = q.Query(ctx, `
		SELECT amr, COALESCE(acr,'0')
		  FROM core.sessions
		 WHERE sid = $1 AND org_id = $2::uuid AND user_id = $3::uuid
		   AND revoked_at IS NULL AND not_after > now()`, sid, orgID, userID)
	if err != nil {
		return f, err
	}
	defer rows.Close()
	if rows.Next() {
		var amr []string
		var acr string
		if err := rows.Scan(&amr, &acr); err != nil {
			return f, err
		}
		f.FromSession = true
		for _, m := range amr {
			// RFC 8176 method names. `pwd` alone is not a second factor.
			switch m {
			case "otp", "hwk", "swk", "mfa", "sms", "face", "fpt", "user", "pin":
				f.MFA = true
			}
		}
		if acr == "urn:signari:mfa" || acr == "2" {
			f.MFA = true
		}
	}
	return f, rows.Err()
}

// ResolveSubject maps an AuthZEN subject to one of our users.
//
// Accepts our own user id, or an email. A subject we cannot resolve is NOT an
// error: relations can be held by things that are not users in our directory,
// and refusing would make the PDP useless for anything but our own accounts.
// What it does mean is that no session facts exist, so a condition needing one
// cannot be satisfied.
func ResolveSubject(ctx context.Context, q Querier, orgID, subjectID string) (
	userID string, err error) {

	rows, err := q.Query(ctx, `
		SELECT id::text FROM core.users
		 WHERE org_id = $1::uuid
		   AND (id::text = $2 OR lower(email) = lower($2))
		 LIMIT 1`, orgID, subjectID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&userID); err != nil {
			return "", err
		}
	}
	return userID, rows.Err()
}
