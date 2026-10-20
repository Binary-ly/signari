package keys

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
)

// rotationLock is the transaction-scoped advisory lock one rotation pass
// holds, so a deployment of several nodes rotates once rather than once per
// node.
const rotationLock int64 = 0x7369676e726f7461 // "signrota"

// Rotator advances signing-key rotation unattended (3.16): it publishes a
// `next` key once the active one is older than Every, promotes it once it has
// been published for MinPublishBeforeActive, and retires a passive key once
// nothing can still be verifying against it. The same three steps
// `signari keys rotate` and `keys retire` take by hand, decided by the same
// CanPromote and CanRetire; rotation happened only when somebody remembered.
type Rotator struct {
	DB         *pgxpool.Pool
	InstanceID string
	Root       *RootKey
	// Every is the age at which an active key is replaced. Zero turns the
	// rotator off.
	Every    time.Duration
	Interval time.Duration
	Log      *slog.Logger
}

// Run takes a pass at once and then every Interval until ctx ends. At once,
// because a node that restarts more often than Interval -- scaled down and up
// again, rescheduled -- would otherwise never take one.
func (r *Rotator) Run(ctx context.Context) {
	if r.Every <= 0 {
		return
	}
	r.pass(ctx)
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.pass(ctx)
		}
	}
}

func (r *Rotator) pass(ctx context.Context) {
	steps, err := r.Once(ctx)
	if err != nil {
		r.Log.Error("signing-key rotation pass failed", "err", err)
		return
	}
	for _, s := range steps {
		r.Log.Info("signing-key rotation", "step", s)
	}
}

// Once takes one pass and says what it did. Another node holding the lock
// means this one does nothing.
func (r *Rotator) Once(ctx context.Context) ([]string, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var mine bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, rotationLock).Scan(&mine); err != nil {
		return nil, fmt.Errorf("taking the rotation lock: %w", err)
	}
	if !mine {
		return nil, nil
	}
	set, err := LoadSet(ctx, tx, r.InstanceID, r.Root)
	if err != nil {
		return nil, fmt.Errorf("loading signing keys: %w", err)
	}
	dwell, _, err := RequiredPassiveDwell(ctx, tx, r.InstanceID)
	if err != nil {
		return nil, err
	}

	var steps []string
	record := func(detail map[string]any, step string) error {
		detail["automatic"] = true
		if err := audit.Write(ctx, tx, audit.Event{Type: audit.EventKeyRotated, Detail: detail}); err != nil {
			return err
		}
		steps = append(steps, step)
		return nil
	}
	for _, a := range set.Algorithms() {
		var next Key
		for _, k := range set.Keys() {
			if k.Algorithm() == a && k.State() == StateNext {
				next = k
			}
		}
		active, err := set.Active(a)
		if err != nil {
			continue
		}
		switch {
		case next != nil:
			if ok, _ := set.CanPromote(next); !ok {
				continue
			}
			demoted, err := WithState(active, StatePassive)
			if err != nil {
				return nil, err
			}
			promoted, err := WithState(next, StateActive)
			if err != nil {
				return nil, err
			}
			if err := Save(ctx, tx, r.InstanceID, demoted, r.Root); err != nil {
				return nil, err
			}
			if err := Save(ctx, tx, r.InstanceID, promoted, r.Root); err != nil {
				return nil, err
			}
			if err := record(map[string]any{"algorithm": string(a), "promoted": next.KID(),
				"demoted": active.KID()}, fmt.Sprintf("%s: promoted %s, demoted %s", a, next.KID(), active.KID())); err != nil {
				return nil, err
			}
		case time.Since(active.PublishedAt()) >= r.Every:
			generated, err := Generate(NewKID(), a)
			if err != nil {
				return nil, err
			}
			if err := Save(ctx, tx, r.InstanceID, generated, r.Root); err != nil {
				return nil, err
			}
			if err := record(map[string]any{"algorithm": string(a), "published": generated.KID()},
				fmt.Sprintf("%s: published %s as next", a, generated.KID())); err != nil {
				return nil, err
			}
		}
	}
	for _, k := range set.Keys() {
		if k.State() != StatePassive {
			continue
		}
		if ok, _ := set.CanRetire(k, dwell); !ok {
			continue
		}
		if err := Retire(ctx, tx, r.InstanceID, k.KID(), dwell); err != nil {
			return nil, err
		}
		if err := record(map[string]any{"algorithm": string(k.Algorithm()), "retired": k.KID()},
			fmt.Sprintf("%s: retired %s", k.Algorithm(), k.KID())); err != nil {
			return nil, err
		}
	}
	return steps, tx.Commit(ctx)
}
