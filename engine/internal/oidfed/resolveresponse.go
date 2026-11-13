package oidfed

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// What a resolve response (§8.3.2) carries besides the chain: the Trust Anchor's own
// Entity Configuration, with which a chain "logically always ends" (specs/oidfed.txt:983),
// and the subject's Trust Marks, of which "Only valid Trust Marks that have been issued
// by Trust Mark issuers trusted by the Trust Anchor to issue such Trust Marks MAY
// appear" (:3918-3924).

// AnchorConfiguration is the Entity Configuration of one of r's anchors, verified with
// the keys r holds for it: the anchor is what answers at its address only if it signs
// with those.
func (r *Resolver) AnchorConfiguration(ctx context.Context, anchorID string) (Statement, error) {
	at := slices.IndexFunc(r.Anchors, func(a TrustAnchor) bool { return a.EntityID == anchorID })
	if at < 0 {
		return Statement{}, fmt.Errorf("%s is not an anchor here", anchorID)
	}
	anchor, err := r.Fetcher.EntityConfigurationOf(ctx, anchorID)
	if err != nil {
		return Statement{}, err
	}
	if err := verifyWith(anchor, r.Anchors[at].JWKS); err != nil {
		return Statement{}, fmt.Errorf("the trust anchor's own configuration: %w", err)
	}
	return anchor, nil
}

// VerifiedTrustMarks is what of the leaf's Trust Marks holds under §7.3 against the
// anchor, as RequireTrustMarks holds a registering client to them, and the earliest
// any of those expires, zero when none does. A mark that does not hold is left out,
// not refused: the subject resolved, and a resolve response says only what it can
// stand behind.
func (r *Resolver) VerifiedTrustMarks(ctx context.Context, leaf, anchor Statement,
	now time.Time) ([]TrustMarkEntry, time.Time) {
	at := slices.IndexFunc(r.Anchors, func(a TrustAnchor) bool { return a.EntityID == anchor.Subject })
	if at < 0 {
		return nil, time.Time{}
	}
	var held []TrustMarkEntry
	var earliest time.Time
	for _, entry := range leaf.TrustMarks {
		if !r.trustMarkHolds(ctx, entry, entry.Type, leaf, anchor, r.Anchors[at].JWKS, now) {
			continue
		}
		held = append(held, entry)
		if mark, err := ParseTrustMarkUnverified(entry.JWT); err == nil && mark.Expiry > 0 {
			if exp := time.Unix(mark.Expiry, 0); earliest.IsZero() || exp.Before(earliest) {
				earliest = exp
			}
		}
	}
	return held, earliest
}
