package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/authzen"
)

// Relations held through other things (11.02). A relation on an object can come from
// somewhere other than a row naming the subject: `parent->viewer` in the model has it
// come from whatever is the object's parent, and a subject written `team:eng#member`
// is everybody who holds member on team:eng. Following those is a walk over the
// data, because only the data says what is the parent of what.
//
// Level by level, one statement a level, with a statement's whole frontier in it.
// So the cost is the depth of the graph in round trips and not the number of paths
// through it, and nothing already visited is visited twice, which is what makes a
// folder that is its own parent an answer and not a hang.

const (
	// maxWalkDepth bounds the levels. Sixteen folders inside each other is a
	// deep tree, and a graph that takes more is one somebody should look at.
	maxWalkDepth = 16
	// maxWalkEdges bounds what one level may read.
	maxWalkEdges = 2000
)

// ErrWalkBound is a graph too deep or too wide to finish. It is an error and not a
// no: the question was not answered, and a caller is told so, as for any decision
// that could not be made.
var ErrWalkBound = errors.New("the relations behind this decision go further than an evaluation will follow")

type walkGoal struct {
	typ, id, relation string
	from              *walkGoal
}

func (g *walkGoal) String() string { return g.typ + ":" + g.id + "#" + g.relation }

type walkKey struct{ typ, id, relation string }

// walkFollow is a rewrite to take from a row of its Through relation.
type walkFollow struct {
	goal     *walkGoal
	relation string
}

// WalkRelations reports which of relations on the object any of subjects holds,
// following what the model and the data say a relation can be held through. held is
// the relation on the object itself, and path the way there from it, for a person
// reading why, empty when nothing was found.
func WalkRelations(ctx context.Context, q Querier, orgID string, model *authzen.Model, subjects [][2]string,
	relations []string, objectType, objectID string) (held string, path []string, err error) {

	if len(relations) == 0 || len(subjects) == 0 {
		return "", nil, nil
	}
	isSubject := make(map[[2]string]bool, len(subjects))
	subjectTypes, subjectIDs := make([]string, 0, len(subjects)), make([]string, 0, len(subjects))
	for _, s := range subjects {
		if !isSubject[s] {
			isSubject[s] = true
			subjectTypes, subjectIDs = append(subjectTypes, s[0]), append(subjectIDs, s[1])
		}
	}

	visited := map[walkKey]*walkGoal{}
	var frontier []*walkGoal
	add := func(typ, id, relation string, from *walkGoal) {
		expanded := []string{relation}
		if t, known := model.Types[typ]; known {
			expanded = t.Expand(relation)
		}
		for _, r := range expanded {
			key := walkKey{typ, id, r}
			if visited[key] == nil {
				g := &walkGoal{typ, id, r, from}
				visited[key] = g
				frontier = append(frontier, g)
			}
		}
	}
	found := func(g *walkGoal) (string, []string) {
		for ; ; g = g.from {
			path = append([]string{g.String()}, path...)
			if g.from == nil {
				return g.relation, path
			}
		}
	}
	for _, r := range relations {
		add(objectType, objectID, r, nil)
	}

	for depth := 0; len(frontier) > 0; depth++ {
		if depth == maxWalkDepth {
			return "", nil, ErrWalkBound
		}
		var typs, ids, rels []string
		var through []bool
		follow := map[walkKey][]walkFollow{}
		for _, g := range frontier {
			typs, ids, rels, through = append(typs, g.typ), append(ids, g.id), append(rels, g.relation), append(through, false)
			for _, rw := range model.Types[g.typ].RewritesOf(g.relation) {
				key := walkKey{g.typ, g.id, rw.Through}
				if follow[key] == nil {
					typs, ids, rels, through = append(typs, g.typ), append(ids, g.id), append(rels, rw.Through), append(through, true)
				}
				follow[key] = append(follow[key], walkFollow{g, rw.Relation})
			}
		}
		frontier = nil

		// Three arms, each on its own index: a row naming one of the subjects, a
		// row naming a set of them, and whatever a rewrite goes through. All of a
		// relation's rows would be simpler, and an object can have a million viewers.
		rows, err := q.Query(ctx, `
			WITH g AS (SELECT * FROM unnest($2::text[], $3::text[], $4::text[], $5::bool[]) AS g(typ, id, rel, through)),
			     s AS (SELECT * FROM unnest($6::text[], $7::text[]) AS s(typ, id))
			SELECT r.object_type, r.object_id, r.relation, r.subject_type, r.subject_id
			  FROM g JOIN core.relations r
			    ON r.org_id = $1::uuid AND r.object_type = g.typ AND r.object_id = g.id AND r.relation = g.rel
			 WHERE g.through AND (r.expires_at IS NULL OR r.expires_at > now())
			UNION ALL
			SELECT r.object_type, r.object_id, r.relation, r.subject_type, r.subject_id
			  FROM g JOIN s ON NOT g.through JOIN core.relations r
			    ON r.org_id = $1::uuid AND r.subject_type = s.typ AND r.subject_id = s.id
			   AND r.relation = g.rel AND r.object_type = g.typ AND r.object_id = g.id
			 WHERE r.expires_at IS NULL OR r.expires_at > now()
			UNION ALL
			SELECT r.object_type, r.object_id, r.relation, r.subject_type, r.subject_id
			  FROM g JOIN core.relations r
			    ON r.org_id = $1::uuid AND r.object_type = g.typ AND r.object_id = g.id AND r.relation = g.rel
			 WHERE NOT g.through AND r.subject_id LIKE '%#%' AND (r.expires_at IS NULL OR r.expires_at > now())
			 LIMIT $8`,
			orgID, typs, ids, rels, through, subjectTypes, subjectIDs, maxWalkEdges+1)
		if err != nil {
			return "", nil, fmt.Errorf("walking relations: %w", err)
		}
		edges := 0
		var hit *walkGoal
		for rows.Next() {
			var objType, objID, relation, subjectType, subjectID string
			if err := rows.Scan(&objType, &objID, &relation, &subjectType, &subjectID); err != nil {
				rows.Close()
				return "", nil, err
			}
			edges++
			key := walkKey{objType, objID, relation}
			if g := visited[key]; g != nil {
				setID, setRelation, isSet := strings.Cut(subjectID, "#")
				switch {
				case isSubject[[2]string{subjectType, subjectID}]:
					hit = g
				case isSet && subjectType == "group" && setRelation == "member" && isSubject[[2]string{"group", setID}]:
					// A directory group's members are not rows here: they are
					// the groups the person was resolved to.
					hit = g
				case isSet:
					add(subjectType, setID, setRelation, g)
				}
			}
			for _, f := range follow[key] {
				add(subjectType, subjectID, f.relation, f.goal)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", nil, fmt.Errorf("walking relations: %w", err)
		}
		if hit != nil {
			held, path = found(hit)
			return held, path, nil
		}
		if edges > maxWalkEdges {
			return "", nil, ErrWalkBound
		}
	}
	return "", nil, nil
}

// AnySubjectSets reports whether an organisation has a relation held by a set of
// subjects, which is what a search has to know before it can start from a row.
func AnySubjectSets(ctx context.Context, q rowQuerier, orgID string) (bool, error) {
	var any bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.relations
		WHERE org_id = $1::uuid AND subject_id LIKE '%#%')`, orgID).Scan(&any)
	return any, err
}

// collectPage reads one column of ids, of which one more than limit says there is
// a further page.
func collectPage(rows pgx.Rows, limit int) ([]string, bool, error) {
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// ObjectsOfType lists the objects of a type anything is recorded about, for a
// search that cannot start from the subject: a document held through its folder has
// no row naming the person, so the candidates are all of them, and each is decided.
func ObjectsOfType(ctx context.Context, q Querier, orgID, objectType string, limit int, after string) ([]string, bool, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT object_id FROM core.relations
		 WHERE org_id = $1::uuid AND object_type = $2 AND ($4 = '' OR object_id > $4)
		 ORDER BY object_id LIMIT $3`, orgID, objectType, limit+1, after)
	if err != nil {
		return nil, false, err
	}
	return collectPage(rows, limit)
}

// PeopleInRelations lists everybody a relation in the organisation names, directly or
// through a group, for a search that cannot start from the object.
func PeopleInRelations(ctx context.Context, q Querier, orgID string, limit int, after string) ([]string, bool, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT sid FROM (
			SELECT subject_id AS sid FROM core.relations WHERE org_id = $1::uuid AND subject_type = 'user'
			UNION
			SELECT m.user_id::text FROM core.relations r
			  JOIN core.groups g ON g.name = split_part(r.subject_id, '#', 1) AND g.org_id = $1::uuid
			  JOIN core.group_members m ON m.group_id = g.id
			 WHERE r.org_id = $1::uuid AND r.subject_type = 'group'
		) people
		 WHERE ($3 = '' OR sid > $3)
		 ORDER BY sid LIMIT $2`, orgID, limit+1, after)
	if err != nil {
		return nil, false, err
	}
	return collectPage(rows, limit)
}
