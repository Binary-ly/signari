package keys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// Rotation and retirement by hand, behind `signari keys rotate|retire` and the
// Admin API (6.07), one implementation for both. The unattended Rotator takes
// the same steps on a period and never forces one.

// ErrNotRotatable is a rotation of an algorithm nothing signs with.
var ErrNotRotatable = errors.New("nothing to rotate")

// Step is what one rotation did for one algorithm: a key published as next,
// or a next key promoted and the active one demoted, or nothing yet, with how
// long until it can be.
type Step struct {
	Algorithm Algorithm
	Published string
	Promoted  string
	Demoted   string
	// Forced is a promotion before the publication wait was over.
	Forced bool
	// Wait is how long until the next key may be promoted, when nothing was.
	Wait time.Duration
}

// Rotate takes the next step for each algorithm in use, or only for one:
// publishes a next key where there is none, and promotes a published one once
// it has been published for MinPublishBeforeActive, or at once with
// promoteNow, which is right for a compromised key and wrong for anything
// else. The outgoing key is demoted, never deleted: tokens it signed are live,
// and a passive key stays published so they keep verifying. Each step is
// audited with via.
//
// Under the unattended Rotator's lock, waited for rather than tried, and the
// keys read once it is held, so a pass cannot run between the read and the
// write.
func Rotate(ctx context.Context, tx pgx.Tx, instanceID string, root *RootKey, only Algorithm,
	promoteNow bool, via string) ([]Step, error) {
	set, err := lockedSet(ctx, tx, instanceID, root)
	if err != nil {
		return nil, err
	}
	algs := set.Algorithms()
	if only != "" {
		// Rotation replaces an algorithm in use; it is not the place to
		// introduce one.
		if !slices.Contains(algs, only) {
			return nil, fmt.Errorf("%w: %s signs nothing here", ErrNotRotatable, only)
		}
		algs = []Algorithm{only}
	}
	if len(algs) == 0 {
		return nil, fmt.Errorf("%w: there are no active signing keys", ErrNotRotatable)
	}
	var steps []Step
	for _, a := range algs {
		var next Key
		for _, k := range set.Keys() {
			if k.Algorithm() == a && k.State() == StateNext {
				next = k
				break
			}
		}
		if next == nil {
			generated, err := Generate(NewKID(), a)
			if err != nil {
				return nil, fmt.Errorf("generating %s key: %w", a, err)
			}
			if err := Save(ctx, tx, instanceID, generated, root); err != nil {
				return nil, err
			}
			if err := audit.Write(ctx, tx, audit.Event{Type: audit.EventKeyRotated,
				Detail: map[string]any{"algorithm": string(a), "published": generated.KID(), "via": via}}); err != nil {
				return nil, err
			}
			steps = append(steps, Step{Algorithm: a, Published: generated.KID()})
			continue
		}
		ok, wait := set.CanPromote(next)
		if !ok && !promoteNow {
			steps = append(steps, Step{Algorithm: a, Wait: wait})
			continue
		}
		step := Step{Algorithm: a, Promoted: next.KID(), Forced: !ok}
		// "Which key signed, from when, and was it forced" is the question
		// after a compromise.
		detail := map[string]any{"algorithm": string(a), "promoted": next.KID(), "via": via}
		if step.Forced {
			detail["forced"] = true
		}
		if current, err := set.Active(a); err == nil {
			step.Demoted = current.KID()
			detail["demoted"] = current.KID()
			demoted, err := WithState(current, StatePassive)
			if err != nil {
				return nil, err
			}
			if err := Save(ctx, tx, instanceID, demoted, root); err != nil {
				return nil, err
			}
		}
		promoted, err := WithState(next, StateActive)
		if err != nil {
			return nil, err
		}
		if err := Save(ctx, tx, instanceID, promoted, root); err != nil {
			return nil, err
		}
		if err := audit.Write(ctx, tx, audit.Event{Type: audit.EventKeyRotated, Detail: detail}); err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// lockedSet takes the rotation lock, waiting for a pass holding it, and reads
// the instance's keys.
func lockedSet(ctx context.Context, tx pgx.Tx, instanceID string, root *RootKey) (*Set, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, rotationLock); err != nil {
		return nil, fmt.Errorf("taking the rotation lock: %w", err)
	}
	set, err := LoadSet(ctx, tx, instanceID, root)
	if err != nil {
		return nil, fmt.Errorf("loading signing keys: %w", err)
	}
	return set, nil
}

// Retirable is a passive key and whether it may leave the published set.
type Retirable struct {
	Key Key
	// Wait is how long until it may; zero once it may.
	Wait time.Duration
	// Undated is a passive key with no demotion time recorded, which is not
	// retired: a missing stamp must not read as demoted at the zero time.
	Undated bool
}

// PassiveKeys says of each passive key whether it may be retired yet, after
// dwell.
func PassiveKeys(set *Set, dwell time.Duration) []Retirable {
	var out []Retirable
	for _, k := range set.Keys() {
		if k.State() != StatePassive {
			continue
		}
		ok, wait := set.CanRetire(k, dwell)
		switch {
		case ok:
			out = append(out, Retirable{Key: k})
		case k.DemotedAt().IsZero():
			out = append(out, Retirable{Key: k, Undated: true})
		default:
			out = append(out, Retirable{Key: k, Wait: wait})
		}
	}
	return out
}

// RetireDue retires every passive key whose dwell is over, audited with via,
// and returns them, under the Rotator's lock as Rotate is. There is no early
// retirement: it would not stop a compromised key being used, which demotion
// already did, and the damage would land on tokens already in the field, at
// verifiers this deployment does not run.
func RetireDue(ctx context.Context, tx pgx.Tx, instanceID string, root *RootKey, via string) ([]Key, error) {
	set, err := lockedSet(ctx, tx, instanceID, root)
	if err != nil {
		return nil, err
	}
	dwell, _, err := RequiredPassiveDwell(ctx, tx, instanceID)
	if err != nil {
		return nil, err
	}
	var retired []Key
	for _, r := range PassiveKeys(set, dwell) {
		if r.Wait > 0 || r.Undated {
			continue
		}
		if err := Retire(ctx, tx, instanceID, r.Key.KID(), dwell); err != nil {
			return nil, err
		}
		if err := audit.Write(ctx, tx, audit.Event{Type: audit.EventKeyRotated, Detail: map[string]any{
			"algorithm": string(r.Key.Algorithm()), "retired": r.Key.KID(), "via": via}}); err != nil {
			return nil, err
		}
		retired = append(retired, r.Key)
	}
	return retired, nil
}
