package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Deciding the UMA requests waiting for a resource owner, behind `signari uma
// approve|deny` and the Admin API (6.07), one implementation for both.

var (
	// ErrUMADecided is a request decided already.
	ErrUMADecided = errors.New("the request was already decided")
	// ErrUMANoModel is an approval in an organisation with no authorization
	// model, so no relation to grant.
	ErrUMANoModel = errors.New("the organisation has no authorization model, so there is no relation to grant")
)

// UMARelationError is an approval naming a relation that would not let the
// request through, with the ones that would.
type UMARelationError struct {
	Relation   string
	Candidates []string
}

func (e UMARelationError) Error() string {
	if len(e.Candidates) == 0 {
		return "no relation in the model grants every scope the request asks for; the model has to change " +
			"before it can be approved"
	}
	if e.Relation == "" {
		return "name the relation to grant; these would satisfy the whole request: " +
			strings.Join(e.Candidates, ", ")
	}
	return fmt.Sprintf("granting %q would not satisfy every scope the request asks for; these would: %s",
		e.Relation, strings.Join(e.Candidates, ", "))
}

// UMACandidateRelations are the relations that, granted on every resource the
// request names, satisfy every scope it asks for on each.
//
// Every, not any. Granting a relation that covers three of four scopes leaves
// the client polling forever against a decision somebody believes they made.
func UMACandidateRelations(model interface {
	RelationsFor(objectType, action string) ([]string, bool)
}, p *PendingRequest) []string {
	var common map[string]bool
	for _, perm := range p.Permissions {
		for _, scope := range perm.ResourceScopes {
			rels, ok := model.RelationsFor(perm.ResourceType, scope)
			if !ok {
				return nil
			}
			this := map[string]bool{}
			for _, r := range rels {
				this[r] = true
			}
			if common == nil {
				common = this
				continue
			}
			for r := range common {
				if !this[r] {
					delete(common, r)
				}
			}
		}
	}
	out := make([]string, 0, len(common))
	for r := range common {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// pendingIn reads a waiting request of orgID, or of any organisation when it
// is empty, as the command (which names none) asks.
func pendingIn(ctx context.Context, tx pgx.Tx, orgID, requestID string) (*PendingRequest, error) {
	p, err := PendingRequestByID(ctx, tx, requestID)
	if err != nil {
		return nil, err
	}
	if orgID != "" && p.OrgID != orgID {
		return nil, ErrPendingUnknown
	}
	if p.State != "pending" {
		return nil, ErrUMADecided
	}
	return p, nil
}

// ApproveUMARequest grants the relation on every resource the request names
// and records the approval, together: separately, a failure between them
// leaves access nobody approved, or an approval that granted nothing and a
// client polling against it. Refused, rather than granted and warned about,
// when the relation would not let the whole request through.
func ApproveUMARequest(ctx context.Context, tx pgx.Tx, orgID, requestID, relation, decidedBy string) (*PendingRequest, error) {
	p, err := pendingIn(ctx, tx, orgID, requestID)
	if err != nil {
		return nil, err
	}
	model, err := LoadModel(ctx, tx, p.OrgID)
	if err != nil {
		return nil, err
	}
	if model == nil {
		return nil, ErrUMANoModel
	}
	cands := UMACandidateRelations(model, p)
	if relation == "" || !slices.Contains(cands, relation) {
		return nil, UMARelationError{Relation: relation, Candidates: cands}
	}
	who := p.RequestingPartyEmail
	if who == "" {
		who = p.RequestingParty
	}
	for _, perm := range p.Permissions {
		if err := GrantRelation(ctx, tx, p.OrgID, Relation{
			SubjectType: "user", SubjectID: who, Relation: relation,
			ObjectType: perm.ResourceType, ObjectID: perm.ResourceID,
		}, ""); err != nil {
			return nil, fmt.Errorf("granting %s on %s:%s: %w", relation, perm.ResourceType, perm.ResourceID, err)
		}
	}
	if err := DecidePendingRequest(ctx, tx, requestID, "approved", decidedBy, relation); err != nil {
		return nil, err
	}
	p.State, p.GrantedRelation = "approved", relation
	return p, nil
}

// DenyUMARequest closes a waiting request without granting anything. The
// client learns it on its next poll, as request_denied: the ticket flow is
// the only channel.
func DenyUMARequest(ctx context.Context, tx pgx.Tx, orgID, requestID, decidedBy string) error {
	if _, err := pendingIn(ctx, tx, orgID, requestID); err != nil {
		return err
	}
	return DecidePendingRequest(ctx, tx, requestID, "denied", decidedBy, "")
}
