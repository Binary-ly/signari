package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
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

	// The ceremony (migration 0170). UserVerification is required or
	// preferred at a passkey sign-in; ResidentKey is required, preferred or
	// discouraged at registration; Attachment is empty (any), platform or
	// cross-platform; Algorithms are COSE identifiers in preference order;
	// Timeout is in seconds; Hints are WebAuthn's security-key, client-device
	// and hybrid.
	UserVerification string
	ResidentKey      string
	Attachment       string
	Algorithms       []int
	TimeoutSeconds   int
	Hints            []string
}

// WebAuthnAlgorithms are the COSE algorithms a policy may offer, in the order
// registration offered them before there was a policy (go-webauthn's
// CredentialParametersDefault): ES256, ES384, ES512, RS256, RS384, RS512,
// PS256, PS384, PS512, EdDSA. Asymmetric only, as everywhere, and not RS1.
var WebAuthnAlgorithms = []int{-7, -35, -36, -257, -258, -259, -37, -38, -39, -8}

// DefaultWebAuthnPolicy is what an organisation with no row gets.
func DefaultWebAuthnPolicy() WebAuthnPolicy {
	return WebAuthnPolicy{Conveyance: "none", RefuseCloned: true,
		UserVerification: "required", ResidentKey: "required", Attachment: "",
		Algorithms: slices.Clone(WebAuthnAlgorithms), TimeoutSeconds: 300, Hints: []string{}}
}

// checkCeremony refuses ceremony settings outside what the schema holds,
// filling empty ones with the defaults.
func (p *WebAuthnPolicy) checkCeremony() error {
	d := DefaultWebAuthnPolicy()
	if p.UserVerification == "" {
		p.UserVerification = d.UserVerification
	}
	if p.ResidentKey == "" {
		p.ResidentKey = d.ResidentKey
	}
	if len(p.Algorithms) == 0 {
		p.Algorithms = d.Algorithms
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = d.TimeoutSeconds
	}
	if p.Hints == nil {
		p.Hints = []string{}
	}
	switch {
	case p.UserVerification != "required" && p.UserVerification != "preferred":
		return fmt.Errorf("%w: user verification must be required or preferred, not %q",
			ErrInvalidWebAuthnPolicy, p.UserVerification)
	case p.ResidentKey != "required" && p.ResidentKey != "preferred" && p.ResidentKey != "discouraged":
		return fmt.Errorf("%w: resident key must be required, preferred or discouraged, not %q",
			ErrInvalidWebAuthnPolicy, p.ResidentKey)
	case p.Attachment != "" && p.Attachment != "platform" && p.Attachment != "cross-platform":
		return fmt.Errorf("%w: attachment must be platform, cross-platform or empty for any, not %q",
			ErrInvalidWebAuthnPolicy, p.Attachment)
	case p.TimeoutSeconds < 30 || p.TimeoutSeconds > 300:
		return fmt.Errorf("%w: the timeout must be 30 to 300 seconds, not %d",
			ErrInvalidWebAuthnPolicy, p.TimeoutSeconds)
	}
	for _, a := range p.Algorithms {
		if !slices.Contains(WebAuthnAlgorithms, a) {
			return fmt.Errorf("%w: COSE algorithm %d is not one a policy may offer (%v)",
				ErrInvalidWebAuthnPolicy, a, WebAuthnAlgorithms)
		}
	}
	for _, h := range p.Hints {
		if h != "security-key" && h != "client-device" && h != "hybrid" {
			return fmt.Errorf("%w: hint %q is not security-key, client-device or hybrid",
				ErrInvalidWebAuthnPolicy, h)
		}
	}
	return nil
}

// ErrInvalidWebAuthnPolicy wraps every reason a policy is refused.
var ErrInvalidWebAuthnPolicy = errors.New("invalid WebAuthn policy")

// SetWebAuthnPolicy validates and stores an organisation's authenticator
// policy. The one writer, behind `signari webauthn policy`, the Admin API and
// a configuration file.
func SetWebAuthnPolicy(ctx context.Context, tx pgx.Tx, orgID string, p WebAuthnPolicy) (WebAuthnPolicy, error) {
	p, err := CheckWebAuthnPolicy(p)
	if err != nil {
		return p, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.webauthn_policy (org_id, attestation_conveyance, allowed_aaguids, refuse_cloned,
		                                  user_verification, resident_key, attachment, algorithms,
		                                  timeout_s, hints)
		VALUES ($1::uuid, $2, $3::uuid[], $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id) DO UPDATE
		   SET attestation_conveyance = EXCLUDED.attestation_conveyance,
		       allowed_aaguids        = EXCLUDED.allowed_aaguids,
		       refuse_cloned          = EXCLUDED.refuse_cloned,
		       user_verification      = EXCLUDED.user_verification,
		       resident_key           = EXCLUDED.resident_key,
		       attachment             = EXCLUDED.attachment,
		       algorithms             = EXCLUDED.algorithms,
		       timeout_s              = EXCLUDED.timeout_s,
		       hints                  = EXCLUDED.hints,
		       updated_at             = now()`, orgID, p.Conveyance, p.AllowedAAGUIDs, p.RefuseCloned,
		p.UserVerification, p.ResidentKey, p.Attachment, p.Algorithms, p.TimeoutSeconds,
		p.Hints); err != nil {
		return p, err
	}
	return p, nil
}

// CheckWebAuthnPolicy is what SetWebAuthnPolicy refuses, answering the policy
// as it would be stored: its AAGUIDs canonical and its defaults filled, so a
// plan compares what would be written rather than what was typed.
func CheckWebAuthnPolicy(p WebAuthnPolicy) (WebAuthnPolicy, error) {
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
	if err := p.checkCeremony(); err != nil {
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
		       COALESCE((SELECT array_agg(a::text) FROM unnest(allowed_aaguids) AS a), '{}'),
		       user_verification, resident_key, attachment, algorithms, timeout_s, hints
		FROM core.webauthn_policy
		WHERE org_id = $1::uuid`, orgID).Scan(&p.Conveyance, &p.RefuseCloned, &aaguids,
		&p.UserVerification, &p.ResidentKey, &p.Attachment, &p.Algorithms, &p.TimeoutSeconds, &p.Hints)
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
