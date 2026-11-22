package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// clientIDJAGAllow lets a client that signed somebody in here have a grant for another
// authorization server. Nobody is asked when one is issued, so this is what stands in.
func clientIDJAGAllow(ctx context.Context, conn *pgx.Conn, clientID, audience, remote, resources, scopes, alg string) error {
	if clientID == "" || audience == "" || remote == "" {
		return fmt.Errorf("-client-id, -audience and -remote-client-id are required")
	}
	entry := store.IDJAGAudience{ClientID: clientID, Audience: audience, RemoteClientID: remote,
		Resources: splitList(resources), Scopes: splitList(scopes), Alg: alg}
	if err := store.SetIDJAGAudience(ctx, conn, entry); errors.Is(err, store.ErrClientNotFound) {
		return fmt.Errorf("no client %q", clientID)
	} else if err != nil {
		return err
	}
	fmt.Printf("%s may have a grant for %s, where it is %s\n", clientID, audience, remote)
	return nil
}

func clientIDJAGAudiences(ctx context.Context, conn *pgx.Conn, clientID, format string) error {
	if clientID == "" {
		return fmt.Errorf("-client-id is required")
	}
	out, err := newOutput(format)
	if err != nil {
		return err
	}
	rows, err := store.IDJAGAudiences(ctx, conn, clientID)
	if err != nil {
		return err
	}
	if len(rows) == 0 && out.text() {
		fmt.Printf("%s may have no grants\n", clientID)
		return nil
	}
	for _, a := range rows {
		out.add(map[string]any{"audience": a.Audience, "remote_client_id": a.RemoteClientID,
			"resources": nonNilList(a.Resources), "scopes": nonNilList(a.Scopes), "alg": a.Alg})
		if out.text() {
			fmt.Printf("%s  as %s  resources %v  scopes %v  %s\n", a.Audience, a.RemoteClientID, a.Resources, a.Scopes, a.Alg)
		}
	}
	return out.flush()
}

// clientIDJAGForget stops issuing grants for a server. One already out lasts its minutes.
func clientIDJAGForget(ctx context.Context, conn *pgx.Conn, clientID, audience string) error {
	if clientID == "" || audience == "" {
		return fmt.Errorf("-client-id and -audience are required")
	}
	if err := store.RemoveIDJAGAudience(ctx, conn, clientID, audience); errors.Is(err, store.ErrIDJAGAudienceUnknown) {
		return fmt.Errorf("%s has no entry for %s", clientID, audience)
	} else if err != nil {
		return err
	}
	fmt.Printf("%s may no longer have a grant for %s\n", clientID, audience)
	return nil
}
