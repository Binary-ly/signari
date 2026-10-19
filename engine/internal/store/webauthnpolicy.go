package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Which authenticators an organisation accepts.
//
// See migration 0116 for the reasoning. The load-bearing part: an AAGUID from a
// registration that conveyed no attestation is SELF-ASSERTED, so filtering on it
// would be filtering a value chosen by the party being filtered.

// WebAuthnPolicy is one organisation's authenticator rules.
type WebAuthnPolicy struct {
	// Conveyance is the WebAuthn attestation conveyance preference: none,
	// indirect, direct or enterprise. Defaults to none, which is the
	// privacy-preserving choice and the browser default.
	Conveyance string
	// AllowedAAGUIDs is empty when any authenticator is acceptable.
	AllowedAAGUIDs []string
	// RefuseCloned refuses a sign-in whose signature counter did not advance,
	// the sign of a copied authenticator. On unless the organisation turned it
	// off (migration 0143).
	RefuseCloned bool
}

// DefaultWebAuthnPolicy is what an organisation with no row gets.
func DefaultWebAuthnPolicy() WebAuthnPolicy {
	return WebAuthnPolicy{Conveyance: "none", RefuseCloned: true}
}

// ErrInvalidWebAuthnPolicy wraps every reason a policy is refused.
var ErrInvalidWebAuthnPolicy = errors.New("invalid WebAuthn policy")

// SetWebAuthnPolicy validates and stores an organisation's authenticator
// policy. The one writer, behind `signari webauthn policy` and the Admin API.
func SetWebAuthnPolicy(ctx context.Context, tx pgx.Tx, orgID string, p WebAuthnPolicy) (WebAuthnPolicy, error) {
	switch p.Conveyance {
	case "none", "indirect", "direct", "enterprise":
	default:
		return p, fmt.Errorf("%w: attestation must be none, indirect, direct or enterprise, not %q",
			ErrInvalidWebAuthnPolicy, p.Conveyance)
	}
	ids := []string{}
	for _, a := range p.AllowedAAGUIDs {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		u, ok := CanonicalUUID(a)
		if !ok {
			return p, fmt.Errorf("%w: an AAGUID must be a uuid, e.g. "+
				"ee882879-721c-4913-9775-3dfcce97072a, not %q; stored as uuids so a malformed "+
				"one is refused here rather than silently never matching", ErrInvalidWebAuthnPolicy, a)
		}
		ids = append(ids, u)
	}
	if len(ids) > 0 && p.Conveyance == "none" {
		return p, fmt.Errorf("%w: an allow-list needs attestation. With none the "+
			"authenticator states its own model identifier and nothing vouches for it, "+
			"so the list would admit any device claiming an approved one; ask for direct",
			ErrInvalidWebAuthnPolicy)
	}
	p.AllowedAAGUIDs = ids
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.webauthn_policy (org_id, attestation_conveyance, allowed_aaguids, refuse_cloned)
		VALUES ($1::uuid, $2, $3::uuid[], $4)
		ON CONFLICT (org_id) DO UPDATE
		   SET attestation_conveyance = EXCLUDED.attestation_conveyance,
		       allowed_aaguids        = EXCLUDED.allowed_aaguids,
		       refuse_cloned          = EXCLUDED.refuse_cloned,
		       updated_at             = now()`, orgID, p.Conveyance, ids, p.RefuseCloned); err != nil {
		return p, err
	}
	return p, nil
}

// LoadWebAuthnPolicy reads an organisation's policy.
//
// A missing row is the default rather than an error: an organisation that has
// never expressed a preference has one, and it is "behave like the browser
// default".
func LoadWebAuthnPolicy(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (WebAuthnPolicy, error) {
	p := DefaultWebAuthnPolicy()
	if orgID == "" {
		return p, nil
	}
	var aaguids []string
	err := q.QueryRow(ctx, `
		SELECT attestation_conveyance, refuse_cloned,
		       COALESCE(array_agg(a::text) FILTER (WHERE a IS NOT NULL), '{}')
		FROM core.webauthn_policy
		LEFT JOIN LATERAL unnest(allowed_aaguids) AS a ON true
		WHERE org_id = $1::uuid
		GROUP BY attestation_conveyance, refuse_cloned`, orgID).Scan(&p.Conveyance, &p.RefuseCloned, &aaguids)
	switch {
	case err == pgx.ErrNoRows:
		return DefaultWebAuthnPolicy(), nil
	case err != nil:
		return DefaultWebAuthnPolicy(), fmt.Errorf("loading the WebAuthn policy: %w", err)
	}
	p.AllowedAAGUIDs = aaguids
	return p, nil
}

// RequiresAttestation reports whether the policy asks for more than `none`.
func (p WebAuthnPolicy) RequiresAttestation() bool {
	return p.Conveyance != "" && p.Conveyance != "none"
}

// PermitsAuthenticator reports whether a registration may be accepted.
//
// `verified` says whether attestation was actually conveyed and checked. It is
// the parameter that makes the allow-list mean anything: with it false the
// AAGUID is self-asserted, so a policy that names an allow-list must refuse
// rather than compare — comparing would let a software authenticator pass by
// claiming a hardware vendor's identifier.
func (p WebAuthnPolicy) PermitsAuthenticator(aaguid []byte, verified bool) (bool, string) {
	if len(p.AllowedAAGUIDs) == 0 {
		return true, ""
	}
	if !verified {
		return false, "this organisation accepts only approved authenticators, " +
			"and this registration carried no verifiable attestation"
	}
	got := formatAAGUID(aaguid)
	if got == "" {
		return false, "the authenticator did not identify its model"
	}
	for _, allowed := range p.AllowedAAGUIDs {
		if allowed == got {
			return true, ""
		}
	}
	return false, "this authenticator model is not on the organisation's approved list"
}

// formatAAGUID renders 16 raw bytes as a canonical UUID.
//
// Returns "" for anything that is not 16 bytes, and for the all-zero AAGUID.
// All-zero is what an authenticator sends when it declines to identify itself,
// so treating it as a value would let every such device match one allow-list
// entry of zeroes.
func formatAAGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	h := hex.EncodeToString(raw)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
