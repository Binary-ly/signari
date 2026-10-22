package adminapi

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"

	"github.com/jackc/pgx/v5"
)

// Before-and-after records for a change (6.05). The record of an update said
// what the request set, so an investigation could not tell what a setting had
// been before somebody changed it, nor that a request had changed nothing.

// clientValueless are the client columns a diff reports as changed and never
// values: the certificate subject and address can name a person, which this
// table must not (audit rule 1), and a key set or thumbprint is material whose
// fact of changing is the useful part. The secret hashes are left out entirely.
var clientValueless = map[string]bool{
	"tls_subject_dn": true, "tls_san_email": true, "jwks": true, "tls_thumbprint": true,
}

// clientState is a client's configuration as its diff compares it: every
// column but the secret hashes and the two times every write or none moves,
// and its redirect URIs.
func clientState(ctx context.Context, tx pgx.Tx, clientID string) (map[string]any, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `
		SELECT (to_jsonb(c) - ARRAY['client_secret_hash', 'registration_token_hash',
		                            'created_at', 'updated_at'])
		       || jsonb_build_object('redirect_uris', COALESCE(
		            (SELECT jsonb_agg(u.redirect_uri ORDER BY u.redirect_uri)
		               FROM core.client_redirect_uris u WHERE u.client_id = c.client_id), '[]'::jsonb))
		  FROM core.clients c WHERE c.client_id = $1`, clientID).Scan(&raw); err != nil {
		return nil, err
	}
	state := map[string]any{}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	return state, nil
}

// stateChanges is what moved between two states, as {field: {from, to}}, or
// {field: {changed: true}} for a valueless one. Empty when nothing did.
func stateChanges(before, after map[string]any, valueless map[string]bool) map[string]any {
	fields := map[string]bool{}
	for k := range before {
		fields[k] = true
	}
	for k := range after {
		fields[k] = true
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	out := map[string]any{}
	for _, k := range names {
		if reflect.DeepEqual(before[k], after[k]) {
			continue
		}
		if valueless[k] {
			out[k] = map[string]any{"changed": true}
			continue
		}
		out[k] = map[string]any{"from": before[k], "to": after[k]}
	}
	return out
}
