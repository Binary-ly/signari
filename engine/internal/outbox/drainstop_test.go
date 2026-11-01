package outbox

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// A shutdown cancels what is in flight, and that is not a failure worth an operator's
// attention. A real one still is, or a broken receiver would go unreported.
func TestStoppingMidBatchIsNotAnError(t *testing.T) {
	var logged bytes.Buffer
	w := &Worker{log: slog.New(slog.NewTextHandler(&logged, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	w.drainAll(ctx, drainer{what: "things", batch: 1, drain: func(context.Context) (int, error) {
		cancel()
		return 0, context.Canceled
	}})
	if logged.Len() != 0 {
		t.Errorf("a shutdown logged %s", logged.String())
	}

	w.drainAll(context.Background(), drainer{what: "things", batch: 1, drain: func(context.Context) (int, error) {
		return 0, errors.New("the database went away")
	}})
	if !strings.Contains(logged.String(), "the database went away") {
		t.Errorf("a real failure logged %q", logged.String())
	}
}
