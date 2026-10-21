package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"signari.dev/engine/internal/store"
)

// AccountNotifier tells an account's holder what happened to it, through the
// server's own channels (httpapi.Server.DeliverAccountNotice). ErrNoSuchAccount
// closes the row: a person deleted since has nobody left to tell.
type AccountNotifier func(ctx context.Context, n store.AccountNotice) error

// ErrNoSuchAccount is a notice for an account that no longer exists.
var ErrNoSuchAccount = errors.New("the account no longer exists")

// SetAccountNotifier installs the delivery for account notices. Without one
// they wait in the outbox, for a process that has it.
func (w *Worker) SetAccountNotifier(f AccountNotifier) { w.notify = f }

// DrainAccountNotices delivers queued notices to account holders.
func (w *Worker) DrainAccountNotices(ctx context.Context) (int, error) {
	if w.notify == nil {
		return 0, nil
	}
	return w.drainTopic(ctx, drainSpec{
		topic: store.AccountNoticeTopic,
		batch: w.batch,
		deliver: func(ctx context.Context, raw []byte) error {
			var n store.AccountNotice
			if err := json.Unmarshal(raw, &n); err != nil {
				return &droppedError{reason: fmt.Sprintf("an account notice that does not decode: %v", err)}
			}
			err := w.notify(ctx, n)
			if errors.Is(err, ErrNoSuchAccount) {
				return &droppedError{reason: err.Error()}
			}
			return err
		},
		backoff: backoffFor,
		onFailure: func(raw []byte, attempts int, err error) {
			w.log.Warn("telling an account holder failed", "attempts", attempts+1, "err", err)
		},
	})
}
