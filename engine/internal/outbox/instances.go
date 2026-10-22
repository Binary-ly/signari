package outbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// signer is the key set and issuer a message to a relying party is signed as.
type signer struct {
	keys   *keys.Set
	issuer string
}

// AddInstance names an instance this process serves and what it signs with
// (6.12). A logout token or a security event goes out as the issuer of the
// instance its client belongs to: a relying party verifies it against that
// issuer's keys, and one signed by another instance's would be refused there
// and recorded here as delivered.
//
// A worker told no instances signs everything with the set it was built
// with, as every worker did when a process served one instance. Told any, it
// signs only for those, and a message for a client of another waits, retried,
// for a process that serves it.
func (w *Worker) AddInstance(instanceID string, set *keys.Set, issuer string) {
	if w.instances == nil {
		w.instances = map[string]signer{}
	}
	w.instances[instanceID] = signer{keys: set, issuer: issuer}
}

// signerFor is what a message to clientID is signed as.
func (w *Worker) signerFor(ctx context.Context, clientID string) (signer, error) {
	if len(w.instances) == 0 {
		return signer{keys: w.keys, issuer: w.issuer}, nil
	}
	var instanceID string
	err := w.db.QueryRow(ctx, `
		SELECT o.instance_id::text FROM core.clients c
		  JOIN core.organizations o ON o.id = c.org_id
		 WHERE c.client_id = $1`, clientID).Scan(&instanceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return signer{}, &droppedError{reason: fmt.Sprintf("client %q no longer exists", clientID)}
	}
	if err != nil {
		return signer{}, fmt.Errorf("reading which instance client %q belongs to: %w", clientID, err)
	}
	s, ok := w.instances[instanceID]
	if !ok {
		return signer{}, fmt.Errorf("client %q belongs to an instance this process does not serve", clientID)
	}
	return s, nil
}
