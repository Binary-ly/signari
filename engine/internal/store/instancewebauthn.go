package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The Relying Party identity an instance's passkeys are bound to, behind
// `signari instance webauthn|related-origins` and the Admin API (6.07).

// ErrInvalidRPID is a Relying Party ID a browser would refuse a ceremony for.
var ErrInvalidRPID = errors.New("invalid WebAuthn RP ID")

// ErrNoRPID is related origins asked for before the instance has an RP ID
// they would relate to.
var ErrNoRPID = errors.New("the instance has no RP ID yet; set it first")

// CheckRPID refuses an RP ID that is not a bare registrable domain.
func CheckRPID(id string) error {
	switch {
	case strings.Contains(id, "://") || strings.ContainsAny(id, ":/?#"):
		return fmt.Errorf("%w: %q has a scheme, port or path; use example.com, not "+
			"https://example.com:8443/", ErrInvalidRPID, id)
	// An IP address contains dots, and browsers refuse a ceremony scoped to
	// one: the first version of the command accepted 192.168.1.1 happily.
	case net.ParseIP(id) != nil:
		return fmt.Errorf("%w: %q is an IP address; WebAuthn binds a credential to a "+
			"registrable domain", ErrInvalidRPID, id)
	case !strings.Contains(id, ".") && id != "localhost":
		return fmt.Errorf("%w: %q is not a domain; WebAuthn allows localhost for local "+
			"testing and requires a registrable domain otherwise", ErrInvalidRPID, id)
	}
	return nil
}

// InstanceWebAuthn is an instance's Relying Party identity.
type InstanceWebAuthn struct {
	RPID           string
	DisplayName    string
	RelatedOrigins []string
}

// InstanceWebAuthnOf reads it; no RP ID is passkeys unavailable.
func InstanceWebAuthnOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, instanceID string) (InstanceWebAuthn, error) {
	var w InstanceWebAuthn
	err := q.QueryRow(ctx, `SELECT COALESCE(rp_id, ''), COALESCE(rp_display_name, ''),
		COALESCE(webauthn_related_origins, '{}') FROM core.instances WHERE id::text = $1`, instanceID).
		Scan(&w.RPID, &w.DisplayName, &w.RelatedOrigins)
	if errors.Is(err, pgx.ErrNoRows) {
		return InstanceWebAuthn{}, ErrInstanceUnknown
	}
	return w, err
}

// ErrInstanceUnknown is an instance id that names none.
var ErrInstanceUnknown = errors.New("no instance with that id")

// SetInstanceRPID binds the instance's passkeys to rpID, shown to people as
// displayName (the RP ID when empty). A different one makes every passkey
// registered under the old unusable.
func SetInstanceRPID(ctx context.Context, tx Execer, instanceID, rpID, displayName string) error {
	if err := CheckRPID(rpID); err != nil {
		return err
	}
	name := strings.TrimSpace(displayName)
	if name == "" {
		// Shown by the authenticator when somebody is asked to confirm; an
		// empty prompt reads as an unidentified site asking for their key.
		name = rpID
	}
	tag, err := tx.Exec(ctx, `UPDATE core.instances SET rp_id = $2, rp_display_name = $3 WHERE id::text = $1`,
		instanceID, rpID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceUnknown
	}
	return nil
}

// SetRelatedOrigins sets the further origins a passkey made under the
// instance's RP ID may be used from; empty clears them. check is
// passkeys.CheckRelatedOrigin, taken as a parameter because passkeys reads
// this package: a caller cannot store an origin without naming the check.
func SetRelatedOrigins(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Execer
}, instanceID string, origins []string, check func(string) error) error {
	for _, o := range origins {
		if err := check(o); err != nil {
			return err
		}
	}
	cur, err := InstanceWebAuthnOf(ctx, tx, instanceID)
	if err != nil {
		return err
	}
	if cur.RPID == "" && len(origins) > 0 {
		return ErrNoRPID
	}
	if origins == nil {
		origins = []string{}
	}
	_, err = tx.Exec(ctx, `UPDATE core.instances SET webauthn_related_origins = $2 WHERE id::text = $1`,
		instanceID, origins)
	return err
}
