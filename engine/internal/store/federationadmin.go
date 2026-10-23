package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/tokens"
)

// Federation membership and Trust Marks as `signari federation enable`,
// `signari trust-mark` and the Admin API write them (6.07). An instance is the
// federation entity; its Entity Identifier is its issuer.

// ErrFederationRefused is a federation request the specification or this
// engine refuses: an Entity Identifier that is not one, a Trust Mark that is
// not this entity's to publish. Its message says which.
var ErrFederationRefused = errors.New("refused by the federation rules")

type federationRefused struct{ err error }

func (e federationRefused) Error() string        { return e.err.Error() }
func (e federationRefused) Unwrap() error        { return e.err }
func (e federationRefused) Is(target error) bool { return target == ErrFederationRefused }

func refuse(format string, args ...any) error { return federationRefused{fmt.Errorf(format, args...)} }

// ErrNoFederationKey is an instance with no active federation signing key:
// federation was never enabled for it.
var ErrNoFederationKey = errors.New("this instance has no active federation signing key; enable federation first")

// FederationChange is what `federation enable` sets. AuthorityHints are
// required: with none this entity would be a Trust Anchor, which MUST publish
// a federation_fetch_endpoint (specs/oidfed.html:3451-3462), and this engine
// serves none. A nil pointer keeps what is set; an empty list clears it.
type FederationChange struct {
	AuthorityHints   []string
	OrganizationName string
	HomepageURI      string
	TrustAnchorHints *[]string
	Contacts         *[]string
	Lifetime         *time.Duration
}

// Validate refuses a change before anything is loaded or written.
func (c FederationChange) Validate() error {
	if len(c.AuthorityHints) == 0 {
		return refuse("give the authority hints, the Trust Anchor or Intermediate above this " +
			"entity: with none it would be a Trust Anchor, which MUST publish a " +
			"federation_fetch_endpoint, and this engine does not serve one")
	}
	for _, h := range c.AuthorityHints {
		if err := oidfed.ValidateEntityID(h); err != nil {
			return refuse("authority hint %q: %w", h, err)
		}
	}
	if c.TrustAnchorHints != nil {
		for _, h := range *c.TrustAnchorHints {
			if err := oidfed.ValidateEntityID(h); err != nil {
				return refuse("trust anchor hint %q: %w", h, err)
			}
		}
	}
	if c.Lifetime != nil && (*c.Lifetime < MinEntityLifetime || *c.Lifetime > MaxEntityLifetime) {
		return refuse("%w", ErrEntityLifetime)
	}
	return nil
}

// The bounds of an Entity Statement's lifetime: a statement a federation
// keeps trusting for longer outlives a change of mind, and a shorter one is
// refetched constantly.
const (
	MinEntityLifetime = 5 * time.Minute
	MaxEntityLifetime = 7 * 24 * time.Hour
)

// ErrEntityLifetime is a lifetime outside those bounds.
var ErrEntityLifetime = errors.New("the entity statement lifetime is between 5m and 168h; a statement a " +
	"federation keeps trusting for longer outlives a change of mind, and a shorter one is refetched constantly")

// EnableFederation makes an instance a federation entity, generating its
// federation key the first time; generated is that key's id, empty when it
// already had one.
func EnableFederation(ctx context.Context, tx pgx.Tx, root *keys.RootKey, instanceID, issuer string,
	c FederationChange) (generated string, err error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if err := oidfed.ValidateEntityID(issuer); err != nil {
		return "", refuse("this instance cannot be a federation entity: %w", err)
	}

	var existing int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM core.signing_keys
		WHERE instance_id = $1::uuid AND purpose = 'federation' AND state = 'active'`,
		instanceID).Scan(&existing); err != nil {
		return "", err
	}
	if existing == 0 {
		if root == nil {
			return "", fmt.Errorf("a federation key is sealed under SIGNARI_ROOT_KEY, which is not loaded")
		}
		k, err := keys.Generate(keys.NewKID(), keys.ES256)
		if err != nil {
			return "", fmt.Errorf("generating the federation key: %w", err)
		}
		// Active immediately, not `next`: the first Entity Configuration is
		// signed by this key, and a `next` key signs nothing, so staging it
		// published an endpoint that answered 500.
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			return "", err
		}
		if err := keys.SaveFor(ctx, tx, instanceID, keys.PurposeFederation, active, root); err != nil {
			return "", err
		}
		generated = active.KID()
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.federation_config
			(instance_id, authority_hints, organization_name, homepage_uri)
		VALUES ($1::uuid, $2, NULLIF($3,''), NULLIF($4,''))
		ON CONFLICT (instance_id) DO UPDATE SET
			authority_hints   = EXCLUDED.authority_hints,
			organization_name = EXCLUDED.organization_name,
			homepage_uri      = EXCLUDED.homepage_uri,
			updated_at        = now()`,
		instanceID, c.AuthorityHints, c.OrganizationName, c.HomepageURI); err != nil {
		return "", fmt.Errorf("saving the federation configuration: %w", err)
	}
	// An empty list is written as NULL: the schema refuses `[]` for the hints,
	// which §3.1.2 forbids, and an absent claim is what "none" means.
	if c.TrustAnchorHints != nil {
		if _, err := tx.Exec(ctx, `UPDATE core.federation_config SET trust_anchor_hints = $2, updated_at = now()
			WHERE instance_id = $1::uuid`, instanceID, nilIfNone(*c.TrustAnchorHints)); err != nil {
			return "", err
		}
	}
	if c.Contacts != nil {
		if _, err := tx.Exec(ctx, `UPDATE core.federation_config SET contacts = $2, updated_at = now()
			WHERE instance_id = $1::uuid`, instanceID, nilIfNone(*c.Contacts)); err != nil {
			return "", err
		}
	}
	if c.Lifetime != nil {
		if _, err := tx.Exec(ctx, `UPDATE core.federation_config SET lifetime_seconds = $2, updated_at = now()
			WHERE instance_id = $1::uuid`, instanceID, int(c.Lifetime.Seconds())); err != nil {
			return "", err
		}
	}
	return generated, nil
}

func nilIfNone(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	return l
}

// SignAsFederationEntity signs claims with the instance's active federation
// key. §7: "The key used by the Trust Mark issuer to sign its Trust Marks MUST
// be one of the private keys in its set of Federation Entity Keys"; the OIDC
// key would work, and would tie the federation's accreditation decisions to
// the key that asserts who users are.
func SignAsFederationEntity(ctx context.Context, q keys.Querier, root *keys.RootKey, instanceID string,
	claims any, typ string) (string, error) {
	set, err := keys.LoadSetFor(ctx, q, instanceID, keys.PurposeFederation, root)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoFederationKey, err)
	}
	key, err := set.Active(keys.ES256)
	if err != nil {
		key = nil
		for _, alg := range set.Algorithms() {
			if k, aerr := set.Active(alg); aerr == nil {
				key = k
				break
			}
		}
	}
	if key == nil {
		return "", ErrNoFederationKey
	}
	return tokens.NewSigner(key).SignJSON(claims, typ)
}

// IssueSignedTrustMark mints, signs and records a Trust Mark this instance
// issues, superseding an active one of the same type for the subject.
func IssueSignedTrustMark(ctx context.Context, db TrustMarkDB, root *keys.RootKey, instanceID, issuer string,
	p oidfed.TrustMarkParams, now time.Time) (string, *oidfed.TrustMark, error) {
	p.Issuer = issuer
	tm, err := oidfed.BuildTrustMark(p, now)
	if err != nil {
		return "", nil, federationRefused{err}
	}
	signed, err := SignAsFederationEntity(ctx, db, root, instanceID, tm, oidfed.TrustMarkTyp)
	if err != nil {
		return "", nil, err
	}
	var expires time.Time
	if tm.Expiry != 0 {
		expires = time.Unix(tm.Expiry, 0)
	}
	if err := IssueTrustMark(ctx, db, instanceID, IssuedTrustMark{Type: tm.Type, Subject: tm.Subject,
		JWT: signed, ExpiresAt: expires}); err != nil {
		return "", nil, err
	}
	return signed, tm, nil
}

// AcceptTrustMark records a Trust Mark somebody granted this entity, to
// publish in its Entity Configuration.
//
// The signature is NOT checked: we hold no key for the issuer, and §7.3 puts
// that check on the reader. What is checked is whatever would damage our own
// Entity Configuration: a mark issued to another entity, or an expired one,
// makes a conformant reader reject the mark and, depending on the reader, the
// whole document.
func AcceptTrustMark(ctx context.Context, db TrustMarkDB, instanceID, entityID, raw string,
	now time.Time) (*oidfed.TrustMark, error) {
	tm, err := oidfed.ParseTrustMarkUnverified(raw)
	if err != nil {
		return nil, refuse("this is not a Trust Mark: %w", err)
	}
	if tm.Subject != entityID {
		return nil, refuse("this Trust Mark was issued to %q and this entity is %q; publishing "+
			"somebody else's mark makes every conformant reader reject it (section 7.3)", tm.Subject, entityID)
	}
	if tm.Expiry != 0 && !time.Unix(tm.Expiry, 0).After(now) {
		return nil, refuse("this Trust Mark expired at %s; publishing it would put a claim in our "+
			"signed configuration that every reader is required to discard",
			time.Unix(tm.Expiry, 0).UTC().Format(time.RFC3339))
	}
	var expires time.Time
	if tm.Expiry != 0 {
		expires = time.Unix(tm.Expiry, 0)
	}
	if err := AddHeldTrustMark(ctx, db, instanceID, HeldTrustMark{Type: tm.Type, JWT: raw, Issuer: tm.Issuer,
		ExpiresAt: expires}); err != nil {
		return nil, err
	}
	return tm, nil
}

// SignDelegation mints a Trust Mark Delegation, §7.2.1: this entity, the
// owner of a type identifier, authorising another to issue marks of it.
// Nothing is stored; the delegate presents it with the marks it issues.
func SignDelegation(ctx context.Context, q keys.Querier, root *keys.RootKey, instanceID, owner string,
	p oidfed.DelegationParams, now time.Time) (string, error) {
	p.Owner = owner
	d, err := oidfed.BuildDelegation(p, now)
	if err != nil {
		return "", federationRefused{err}
	}
	return SignAsFederationEntity(ctx, q, root, instanceID, d, oidfed.DelegationTyp)
}

// InstanceIssuer returns an instance's issuer, its Entity Identifier in a
// federation, or found false for no such instance.
func InstanceIssuer(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, instanceID string) (issuer string, found bool, err error) {
	err = q.QueryRow(ctx, `SELECT issuer FROM core.instances WHERE id::text = $1`, instanceID).Scan(&issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return issuer, err == nil, err
}
