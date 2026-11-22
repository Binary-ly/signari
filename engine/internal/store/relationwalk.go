package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

// walkStep is one level of a walk, for a whole frontier: $2..$5 the nodes, each a
// relation on an object and whether it is a relation a rewrite goes through, $6 and $7
// the subjects. Three arms, each on its own index: a row naming one of the subjects, a
// row naming a set of them, and whatever a rewrite goes through. All of a relation's
// rows would be simpler, and an object can have a million viewers. $8 is one more than
// a level may read, so that reading it says the level was cut short. Each row says
// whether it was read as something a rewrite goes through, so that the rows of one
// node, asked once for a whole batch, can be handed to each walk that asks it.
const walkStep = `
	WITH g AS (SELECT * FROM unnest($2::text[], $3::text[], $4::text[], $5::bool[]) AS g(typ, id, rel, through)),
	     s AS (SELECT * FROM unnest($6::text[], $7::text[]) AS s(typ, id))
	SELECT r.object_type, r.object_id, r.relation, r.subject_type, r.subject_id, true
	  FROM g JOIN core.relations r
	    ON r.org_id = $1::uuid AND r.object_type = g.typ AND r.object_id = g.id AND r.relation = g.rel
	 WHERE g.through AND (r.expires_at IS NULL OR r.expires_at > now())
	UNION ALL
	SELECT r.object_type, r.object_id, r.relation, r.subject_type, r.subject_id, false
	  FROM g JOIN s ON NOT g.through JOIN core.relations r
	    ON r.org_id = $1::uuid AND r.subject_type = s.typ AND r.subject_id = s.id
	   AND r.relation = g.rel AND r.object_type = g.typ AND r.object_id = g.id
	 WHERE r.expires_at IS NULL OR r.expires_at > now()
	UNION ALL
	SELECT r.object_type, r.object_id, r.relation, r.subject_type, r.subject_id, false
	  FROM g JOIN core.relations r
	    ON r.org_id = $1::uuid AND r.object_type = g.typ AND r.object_id = g.id AND r.relation = g.rel
	 WHERE NOT g.through AND r.subject_id LIKE '%#%' AND (r.expires_at IS NULL OR r.expires_at > now())
	 LIMIT $8`

// walkRow is one row of a walk's step.
type walkRow struct {
	objType, objID, relation, subjectType, subjectID string
	through                                          bool
}

// walkAsk is one node of a step as the statement asks it: a relation on an object, and
// whether it is asked as something a rewrite goes through.
type walkAsk struct {
	key     walkKey
	through bool
}

// scanWalkStep reads a step's rows.
func scanWalkStep(rows pgx.Rows, each func(walkRow)) error {
	defer rows.Close()
	for rows.Next() {
		var r walkRow
		if err := rows.Scan(&r.objType, &r.objID, &r.relation, &r.subjectType, &r.subjectID, &r.through); err != nil {
			return err
		}
		each(r)
	}
	return rows.Err()
}

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
	return WalkRelationsWith(ctx, q, orgID, model, subjects, relations, objectType, objectID, nil)
}

// WalkMemo is what one request's walks have settled, so that the questions of a batch
// or a search that meet the same nodes walk them once (11.02, E.17): a hundred documents
// in one folder walked the nine folders above it a hundred times, a statement a folder a
// document. For one set of subjects it holds whether a relation on an object is held by
// any of them: held for each node on the path a walk found, not held for each node a walk
// visited and exhausted, nothing at all from a walk that stopped at its bounds.
//
// It also holds the rows of the first step a batch's walks took together
// (SettleUnreached), node by node, so that each walk takes its first level from them
// and does not ask it again.
//
// It lives and dies with the request, as everything an evaluation reads does (ADR-007),
// so a relation revoked is not remembered past it. One request's decisions are taken in
// turn, and it is not for use by two at once.
type WalkMemo struct {
	of map[string]*subjectsMemo
}

// subjectsMemo is what a memo holds for one set of subjects.
type subjectsMemo struct {
	settled map[walkKey]bool
	read    map[walkAsk][]walkRow
}

// NewWalkMemo is an empty one, for one request.
func NewWalkMemo() *WalkMemo { return &WalkMemo{of: map[string]*subjectsMemo{}} }

// forSubjects is what the memo holds for these subjects, keyed by them as a set: a node
// held by one set is not by another, and a row naming one of them was read for them.
// Nil without a memo.
func (m *WalkMemo) forSubjects(subjectTypes, subjectIDs []string) *subjectsMemo {
	if m == nil {
		return nil
	}
	names := make([]string, len(subjectTypes))
	for i := range subjectTypes {
		names[i] = subjectTypes[i] + "\x00" + subjectIDs[i]
	}
	slices.Sort(names)
	sig := strings.Join(names, "\x01")
	of := m.of[sig]
	if of == nil {
		of = &subjectsMemo{settled: map[walkKey]bool{}, read: map[walkAsk][]walkRow{}}
		m.of[sig] = of
	}
	return of
}

// distinctSubjects is subjects without repeats, as the walk statement's two arrays and
// as a set.
func distinctSubjects(subjects [][2]string) (subjectTypes, subjectIDs []string, isSubject map[[2]string]bool) {
	isSubject = make(map[[2]string]bool, len(subjects))
	subjectTypes, subjectIDs = make([]string, 0, len(subjects)), make([]string, 0, len(subjects))
	for _, s := range subjects {
		if !isSubject[s] {
			isSubject[s] = true
			subjectTypes, subjectIDs = append(subjectTypes, s[0]), append(subjectIDs, s[1])
		}
	}
	return subjectTypes, subjectIDs, isSubject
}

// WalkRelationsWith is WalkRelations, taking what memo has settled for these subjects and
// leaving what this walk settles in it. A nil memo is WalkRelations.
func WalkRelationsWith(ctx context.Context, q Querier, orgID string, model *authzen.Model, subjects [][2]string,
	relations []string, objectType, objectID string, memo *WalkMemo) (held string, path []string, err error) {

	if len(relations) == 0 || len(subjects) == 0 {
		return "", nil, nil
	}
	subjectTypes, subjectIDs, isSubject := distinctSubjects(subjects)
	// settled is what earlier walks of the request settled, and read the rows, node by
	// node, that a step taken for the whole batch has read already. Both nil without a
	// memo.
	var settled map[walkKey]bool
	var read map[walkAsk][]walkRow
	if of := memo.forSubjects(subjectTypes, subjectIDs); of != nil {
		settled, read = of.settled, of.read
	}

	visited := map[walkKey]*walkGoal{}
	var frontier []*walkGoal
	// settledHit is a node an earlier walk found held, met on the way here.
	var settledHit *walkGoal
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
				if isHeld, known := settled[key]; known {
					// Settled by an earlier walk of this request: held ends this one,
					// and not held needs no looking at again.
					if isHeld && settledHit == nil {
						settledHit = g
					}
					continue
				}
				frontier = append(frontier, g)
			}
		}
	}
	found := func(g *walkGoal) (string, []string) {
		if settled != nil {
			for n := g; n != nil; n = n.from {
				settled[walkKey{n.typ, n.id, n.relation}] = true
			}
		}
		for ; ; g = g.from {
			path = append([]string{g.String()}, path...)
			if g.from == nil {
				return g.relation, path
			}
		}
	}
	// exhausted is a walk that found nothing with nothing left to look at: every node it
	// visited was looked at all the way down, so none of them is held.
	exhausted := func() {
		if settled == nil {
			return
		}
		for key := range visited {
			if _, known := settled[key]; !known {
				settled[key] = false
			}
		}
	}
	for _, r := range relations {
		add(objectType, objectID, r, nil)
	}
	if settledHit != nil {
		held, path = found(settledHit)
		return held, path, nil
	}

	for depth := 0; len(frontier) > 0; depth++ {
		if depth == maxWalkDepth {
			return "", nil, ErrWalkBound
		}
		var typs, ids, rels []string
		var through []bool
		// known is the rows of this level's nodes that the batch's first step read; only
		// the rest are asked.
		var known []walkRow
		ask := func(key walkKey, isThrough bool) {
			if rows, wasRead := read[walkAsk{key, isThrough}]; wasRead {
				known = append(known, rows...)
				return
			}
			typs, ids, rels, through = append(typs, key.typ), append(ids, key.id), append(rels, key.relation), append(through, isThrough)
		}
		follow := map[walkKey][]walkFollow{}
		for _, g := range frontier {
			ask(walkKey{g.typ, g.id, g.relation}, false)
			for _, rw := range model.Types[g.typ].RewritesOf(g.relation) {
				key := walkKey{g.typ, g.id, rw.Through}
				if follow[key] == nil {
					ask(key, true)
				}
				follow[key] = append(follow[key], walkFollow{g, rw.Relation})
			}
		}
		frontier = nil

		edges := 0
		var hit *walkGoal
		take := func(r walkRow) {
			edges++
			key := walkKey{r.objType, r.objID, r.relation}
			if g := visited[key]; g != nil {
				setID, setRelation, isSet := strings.Cut(r.subjectID, "#")
				switch {
				case isSubject[[2]string{r.subjectType, r.subjectID}]:
					hit = g
				case isSet && r.subjectType == "group" && setRelation == "member" && isSubject[[2]string{"group", setID}]:
					// A directory group's members are not rows here: they are
					// the groups the person was resolved to.
					hit = g
				case isSet:
					add(r.subjectType, setID, setRelation, g)
				}
			}
			for _, f := range follow[key] {
				add(r.subjectType, r.subjectID, f.relation, f.goal)
			}
		}
		for _, r := range known {
			take(r)
		}
		if len(typs) > 0 {
			rows, err := q.Query(ctx, walkStep, orgID, typs, ids, rels, through, subjectTypes, subjectIDs, maxWalkEdges+1)
			if err != nil {
				return "", nil, fmt.Errorf("walking relations: %w", err)
			}
			if err := scanWalkStep(rows, take); err != nil {
				return "", nil, fmt.Errorf("walking relations: %w", err)
			}
		}
		if hit == nil {
			hit = settledHit
		}
		if hit != nil {
			held, path = found(hit)
			return held, path, nil
		}
		if edges > maxWalkEdges {
			return "", nil, ErrWalkBound
		}
	}
	exhausted()
	return "", nil, nil
}

// WalkRoot is where one question's walk would start: the relations an action asks for,
// on one object.
type WalkRoot struct {
	Type, ID  string
	Relations []string
}

// SettleUnreached takes the first step of many walks at once, for questions of one
// request asked for the same subjects, and settles in memo each relation that step finds
// nothing behind: no row naming one of the subjects, no set of subjects holding it, and
// no row of anything a rewrite of it goes through. Its own walk would have looked at such
// a relation once and stopped, and a batch of a hundred documents with a rewrite, half of
// them held by nobody asking, spent a statement on each of that half (E.17). A relation
// the step does find something behind is left to its walk, which takes its first level
// from the rows the step read, node by node, and asks only what lies beyond: a hundred
// documents in one deep folder asked their own first step each before, and paid for the
// shared one on top. The first step is the walk's own: the relations as Expand gives
// them, the rewrites of each, the same statement. Nothing at all is settled or kept when
// the step reads to the edge bound, since an answer cut short cannot say a relation has
// nothing behind it, nor hand a walk all of a node's rows.
func SettleUnreached(ctx context.Context, q Querier, orgID string, model *authzen.Model,
	subjects [][2]string, roots []WalkRoot, memo *WalkMemo) error {

	if memo == nil || len(subjects) == 0 || len(roots) == 0 {
		return nil
	}
	subjectTypes, subjectIDs, _ := distinctSubjects(subjects)
	of := memo.forSubjects(subjectTypes, subjectIDs)
	settled := of.settled

	// Each relation to settle, with the relations its rewrites go through.
	type unsettled struct {
		key      walkKey
		throughs []string
	}
	var pending []unsettled
	var queued []walkAsk
	isQueued := map[walkAsk]bool{}
	var typs, ids, rels []string
	var through []bool
	queue := func(key walkKey, isThrough bool) {
		if a := (walkAsk{key, isThrough}); !isQueued[a] {
			isQueued[a] = true
			queued = append(queued, a)
			typs, ids, rels, through = append(typs, key.typ), append(ids, key.id),
				append(rels, key.relation), append(through, isThrough)
		}
	}
	seen := map[walkKey]bool{}
	for _, root := range roots {
		t, known := model.Types[root.Type]
		for _, relation := range root.Relations {
			expanded := []string{relation}
			if known {
				expanded = t.Expand(relation)
			}
			for _, r := range expanded {
				key := walkKey{root.Type, root.ID, r}
				if seen[key] {
					continue
				}
				seen[key] = true
				if _, done := settled[key]; done {
					continue
				}
				u := unsettled{key: key}
				queue(key, false)
				for _, rw := range t.RewritesOf(r) {
					u.throughs = append(u.throughs, rw.Through)
					queue(walkKey{root.Type, root.ID, rw.Through}, true)
				}
				pending = append(pending, u)
			}
		}
	}
	if len(pending) == 0 {
		return nil
	}

	rows, err := q.Query(ctx, walkStep, orgID, typs, ids, rels, through, subjectTypes, subjectIDs, maxWalkEdges+1)
	if err != nil {
		return fmt.Errorf("settling relations: %w", err)
	}
	behind := map[walkKey]bool{}
	byAsk := map[walkAsk][]walkRow{}
	read := 0
	if err := scanWalkStep(rows, func(r walkRow) {
		key := walkKey{r.objType, r.objID, r.relation}
		behind[key] = true
		// Each node is asked once in the statement, as a rewrite's or not, so the row is
		// that ask's.
		byAsk[walkAsk{key, r.through}] = append(byAsk[walkAsk{key, r.through}], r)
		read++
	}); err != nil {
		return fmt.Errorf("settling relations: %w", err)
	}
	if read > maxWalkEdges {
		return nil
	}
	for _, a := range queued {
		// Asked and read to the end, so no rows is an answer too, and is kept as one.
		of.read[a] = append([]walkRow{}, byAsk[a]...)
	}
	for _, u := range pending {
		reached := behind[u.key]
		for _, th := range u.throughs {
			reached = reached || behind[walkKey{u.key.typ, u.key.id, th}]
		}
		if !reached {
			settled[u.key] = false
		}
	}
	return nil
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
			  CROSS JOIN LATERAL core.groups_below(g.id) b
			  JOIN core.group_members m ON m.group_id = b.group_id
			 WHERE r.org_id = $1::uuid AND r.subject_type = 'group'
		) people
		 WHERE ($3 = '' OR sid > $3)
		 ORDER BY sid LIMIT $2`, orgID, limit+1, after)
	if err != nil {
		return nil, false, err
	}
	return collectPage(rows, limit)
}
