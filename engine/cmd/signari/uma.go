package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// `signari uma ...` -- UMA 2.0 claims gathering and resource-owner intervention.
//
// # Why approval grants a relation rather than approving a request
//
// §3.3.6's request_submitted exists so a resource owner can be asked. The
// obvious implementation records "request 7 is approved" and lets the next poll
// find it. That produces a second, parallel authorization store: access that is
// invisible to `signari authz check`, that no policy graph shows, and that
// nobody can revoke through the mechanism they revoke everything else through.
//
// So approving GRANTS A RELATION in the authorization model, and the next poll
// then passes policy on its own with no special case anywhere. The pending row
// records that a decision was made and what was granted; the access itself lives
// where all the other access lives.

// umaSettings turns resource-owner intervention on or off.
func umaSettings(ctx context.Context, conn *pgx.Conn, orgID string,
	intervention bool, pollInterval time.Duration) error {

	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}
	if pollInterval < 5*time.Second || pollInterval > time.Hour {
		return fmt.Errorf("-poll-interval must be between 5s and 1h: below that a " +
			"polling client is a load generator against the token endpoint, and " +
			"above it the client has almost certainly given up")
	}
	if err := store.SetUMASettings(ctx, conn, orgID, store.UMASettings{
		OwnerIntervention: intervention, PollInterval: pollInterval,
	}); err != nil {
		return err
	}
	if !intervention {
		fmt.Println("resource-owner intervention is OFF for this organisation")
		fmt.Println("\nA refused UMA request now answers request_denied, which is " +
			"final. That is the honest answer while nobody is being asked: telling a " +
			"client to poll for a decision that will never be made is worse than a " +
			"refusal it can act on.")
		return nil
	}
	fmt.Printf("resource-owner intervention is ON, polling every %s\n", pollInterval)
	fmt.Println("\nA refused request from an identified requesting party is now " +
		"recorded for somebody to decide, and the client is told request_submitted. " +
		"Run `signari uma requests` to see them -- nothing else will.")
	return nil
}

// umaRequests lists the requests awaiting a decision.
func umaRequests(ctx context.Context, conn *pgx.Conn, orgID, format string) error {
	out, err := newOutput(format)
	if err != nil {
		return err
	}
	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	pending, err := store.ListPendingRequests(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if len(pending) == 0 && out.text() {
		fmt.Println("nothing is waiting for a decision")
		return nil
	}
	model, err := store.LoadModel(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if !out.text() {
		for _, p := range pending {
			perms := make([]map[string]any, 0, len(p.Permissions))
			for _, perm := range p.Permissions {
				perms = append(perms, map[string]any{"resource_type": perm.ResourceType,
					"resource_id": perm.ResourceID, "scopes": perm.ResourceScopes})
			}
			out.add(map[string]any{"id": p.ID, "requesting_party": p.RequestingParty,
				"requesting_party_email": p.RequestingPartyEmail, "client_id": p.ClientID,
				"resource_server": p.ResourceServer, "created_at": p.CreatedAt.UTC(), "permissions": perms,
				"candidate_relations": nonNilList(store.UMACandidateRelations(model, p))})
		}
		return out.flush()
	}
	for _, p := range pending {
		who := p.RequestingPartyEmail
		if who == "" {
			who = p.RequestingParty
		}
		fmt.Printf("%s\n  who     %s\n  client  %s\n  holder  %s\n  asked   %s\n",
			p.ID, who, p.ClientID, p.ResourceServer,
			p.CreatedAt.UTC().Format(time.RFC3339))
		for _, perm := range p.Permissions {
			fmt.Printf("  wants   %s on %s:%s\n",
				strings.Join(perm.ResourceScopes, ", "), perm.ResourceType, perm.ResourceID)
		}
		// Which relations would actually satisfy it. Printed here because the
		// operator has to choose one and the model is the only place that answer
		// exists -- and reading a compiled authorization model to find out is not
		// a reasonable thing to ask of somebody approving a request.
		if cands := store.UMACandidateRelations(model, p); len(cands) > 0 {
			fmt.Printf("  grant   signari uma approve -uma-request %s -relation %s\n",
				p.ID, strings.Join(cands, " | "))
		} else {
			fmt.Println("  grant   NO relation in this model grants every scope asked " +
				"for; the model has to change before this can be approved")
		}
		fmt.Println()
	}
	return nil
}

// umaApprove grants a relation and closes the request.
func umaApprove(ctx context.Context, conn *pgx.Conn, requestID, relation string) error {
	if requestID == "" {
		return fmt.Errorf("-uma-request is required; run `signari uma requests` for the list")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The grant and the decision, in one transaction, refused rather than
	// granted-and-warned when the relation would not let the whole request
	// through: the approval the Admin API shares.
	p, err := store.ApproveUMARequest(ctx, tx, "", requestID, relation, "")
	var rel store.UMARelationError
	switch {
	case errors.Is(err, store.ErrPendingUnknown):
		return fmt.Errorf("no such pending request")
	case errors.Is(err, store.ErrUMADecided):
		return fmt.Errorf("this request was already decided")
	case errors.Is(err, store.ErrUMANoModel):
		return fmt.Errorf("%w; run `signari authz set-model` first", err)
	case errors.As(err, &rel) && rel.Relation == "" && len(rel.Candidates) > 0:
		return fmt.Errorf("-relation is required. These would satisfy the whole request: %s",
			strings.Join(rel.Candidates, ", "))
	case err != nil:
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	who := p.RequestingPartyEmail
	if who == "" {
		who = p.RequestingParty
	}
	fmt.Printf("approved: %s is now %s of\n", who, relation)
	for _, perm := range p.Permissions {
		fmt.Printf("  %s:%s\n", perm.ResourceType, perm.ResourceID)
	}
	fmt.Println("\nThe grant lives in the authorization model, so `signari authz " +
		"check` sees it and `signari authz revoke` undoes it. The client's next " +
		"poll will pass policy with no special case anywhere.")
	return nil
}

// umaDeny closes a request without granting anything.
func umaDeny(ctx context.Context, conn *pgx.Conn, requestID string) error {
	if requestID == "" {
		return fmt.Errorf("-uma-request is required")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.DenyUMARequest(ctx, tx, "", requestID, ""); err != nil {
		if errors.Is(err, store.ErrPendingUnknown) || errors.Is(err, store.ErrUMADecided) {
			return fmt.Errorf("no such pending request, or it was already decided")
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("denied")
	// The client is not told. There is no channel to tell it: §3.3.6's
	// request_submitted invites polling, and a poll after this finds no pending
	// request and gets request_denied -- which is the answer, arriving the only
	// way the protocol has of delivering it.
	fmt.Println("\nThe client learns this on its next poll, as request_denied. " +
		"There is no way to tell it sooner: the ticket flow is the only channel.")
	return nil
}

// clientSetClaimsRedirects registers UMA claims redirection URIs.
func clientSetClaimsRedirects(ctx context.Context, conn *pgx.Conn, clientID, uris string) error {
	if clientID == "" {
		return fmt.Errorf("-client-id is required")
	}
	// The rules, and the empty-not-NULL clear, are store.SetClientClaimsRedirects',
	// which the Admin API shares (6.03).
	list := splitList(uris)
	if err := store.SetClientClaimsRedirects(ctx, conn, clientID, list); err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			return fmt.Errorf("no client %q", clientID)
		}
		return err
	}
	if len(list) == 0 {
		fmt.Printf("%s has no claims redirection URIs\n", clientID)
		fmt.Println("\nIt can no longer send a requesting party to the claims " +
			"interaction endpoint. This server requires pre-registration for every " +
			"client, which UMA 2.0 section 3.3.2 makes a SHOULD and makes a MUST for " +
			"public ones -- an unregistered URI here is an open redirect whose " +
			"payload is a live permission ticket.")
		return nil
	}
	fmt.Printf("%s may send requesting parties back to:\n", clientID)
	for _, u := range list {
		fmt.Printf("  %s\n", u)
	}
	if len(list) > 1 {
		// §3.3.2 makes the parameter REQUIRED once there is more than one, and a
		// client that was working with a single registered URI and omitting the
		// parameter breaks the moment a second is added.
		fmt.Println("\nWith more than one registered, the client MUST now send " +
			"claims_redirect_uri explicitly (section 3.3.2). A client that was " +
			"relying on the single-URI default will start being refused.")
	}
	return nil
}
