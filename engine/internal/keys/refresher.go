package keys

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// MaxMissedRefreshes is how many refreshes in a row may fail before the
// instance reports itself not ready. Five minutes at the default interval:
// long past a transient fault, short enough that an instance that can no
// longer see a rotation leaves the load balancer before it starts signing
// with a key the rest of the fleet has retired.
const MaxMissedRefreshes = 5

// Refresher re-reads an instance's signing keys on an interval and counts the
// refreshes that failed in a row.
//
// It reads through whatever it is given, which in `serve` is the pool. It used
// the one connection the process opened at startup: after a database failover
// that connection was gone for good, every refresh failed from then on, and
// the only sign was a log line a minute, while the instance went on serving
// the last keys it had seen.
type Refresher struct {
	DB         Querier
	InstanceID string
	Root       *RootKey
	Live       *Set
	Interval   time.Duration
	Log        *slog.Logger

	missed atomic.Int64
}

// Run refreshes until ctx is done.
func (r *Refresher) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Once(ctx)
		}
	}
}

// Once refreshes now. A failure keeps the current set, which is the one known
// to work, and is counted.
func (r *Refresher) Once(ctx context.Context) {
	if err := Refresh(ctx, r.DB, r.InstanceID, r.Root, r.Live); err != nil {
		n := r.missed.Add(1)
		r.Log.Error("refreshing signing keys", "err", err, "missed_in_a_row", n)
		return
	}
	r.missed.Store(0)
}

// Missed is how many refreshes in a row have failed.
func (r *Refresher) Missed() int64 { return r.missed.Load() }

// Healthy reports an error once more than MaxMissedRefreshes in a row failed.
func (r *Refresher) Healthy() error {
	if n := r.Missed(); n >= MaxMissedRefreshes {
		return fmt.Errorf("the last %d signing-key refreshes failed", n)
	}
	return nil
}
