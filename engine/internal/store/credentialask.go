package store

import (
	"context"
	"fmt"
)

// Who may ask for a credential at the authorization endpoint (12.06). An offer
// decides that before anybody asks. Here the wallet asks first, so each
// configuration asked for has to be open to anybody signed in, or be in a live
// offer to this person through this client.

// CredentialAsk is a request for credentials, by a person through a client.
type CredentialAsk struct {
	OrgID, UserID, ClientID string
	// IssuerState is what the wallet handed back from an offer. OID4VCI §5.1.3
	// warns it may have been injected, so it counts only for the person the offer
	// names, and for anybody else it is as good as absent.
	IssuerState    string
	Configurations []string
}

// issuerStateHash is how a state is kept, in the column a pre-authorized code is
// kept in. Under a prefix, so that no state is ever the hash of a code: a code is
// a bearer secret, and a state presented as one would hand over a token with no
// sign-in, which is the one thing the authorization code grant is there to have.
func issuerStateHash(state string) []byte { return HashToken("issuer_state:" + state) }

// closed is what the ask names that is not open to anybody.
func (a CredentialAsk) closed(ctx context.Context, q rowQuerier) ([]string, error) {
	var ids []string
	err := q.QueryRow(ctx, `
		SELECT COALESCE(array_agg(w.id), '{}') FROM unnest($2::text[]) AS w(id)
		 WHERE NOT EXISTS (SELECT 1 FROM core.credential_configurations c
		                    WHERE c.org_id = $1::uuid AND c.config_id = w.id AND c.wallet_initiated)`,
		a.OrgID, a.Configurations).Scan(&ids)
	if err != nil {
		return nil, fmt.Errorf("reading which credentials are open: %w", err)
	}
	return ids, nil
}

// CredentialOpenTo answers whether this person may have what the ask names,
// spending nothing: there is a consent screen between this and the code.
func CredentialOpenTo(ctx context.Context, q rowQuerier, a CredentialAsk) (bool, error) {
	closed, err := a.closed(ctx, q)
	if err != nil || len(closed) == 0 {
		return err == nil, err
	}
	var offered bool
	err = q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.preauthorized_codes
		                WHERE code_hash = $1 AND org_id = $2::uuid AND user_id = $3::uuid AND client_id = $4
		                  AND redeemed_at IS NULL AND expires_at > now() AND configuration_ids @> $5::text[])`,
		issuerStateHash(a.IssuerState), a.OrgID, a.UserID, a.ClientID, closed).Scan(&offered)
	return offered, err
}

// SpendCredentialOffer answers the same question as the code is issued, and takes
// the offer out of use if it is what the answer rests on. In the code's
// transaction, so of two racing for one offer one has none, and a code that was
// not issued leaves it good.
func SpendCredentialOffer(ctx context.Context, tx interface {
	rowQuerier
	Execer
}, a CredentialAsk) (bool, error) {
	closed, err := a.closed(ctx, tx)
	if err != nil || len(closed) == 0 {
		return err == nil, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.preauthorized_codes SET redeemed_at = now()
		 WHERE code_hash = $1 AND org_id = $2::uuid AND user_id = $3::uuid AND client_id = $4
		   AND redeemed_at IS NULL AND expires_at > now() AND configuration_ids @> $5::text[]`,
		issuerStateHash(a.IssuerState), a.OrgID, a.UserID, a.ClientID, closed)
	if err != nil {
		return false, fmt.Errorf("spending a credential offer: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
