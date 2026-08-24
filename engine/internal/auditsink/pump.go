package auditsink

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
)

// Pump forwards new audit events to a Sink, on a timer.
//
// The delivery contract is at-least-once, and deliberately so: it emits a batch,
// and only when the Sink accepts it does it advance the cursor. A crash between
// the two replays the last batch, which a receiver deduplicates on the record id
// -- the safe direction. The alternative, advancing before delivery, would drop
// events on a crash, and a dropped audit event is the one an investigation needs.
type Pump struct {
	db    *pgxpool.Pool
	sink  Sink
	log   *slog.Logger
	batch int
}

func NewPump(db *pgxpool.Pool, sink Sink, log *slog.Logger) *Pump {
	return &Pump{db: db, sink: sink, log: log, batch: 500}
}

// Run pumps until the context is cancelled. interval is how often it checks for
// new events; a batch is drained fully before the next sleep, so a burst is not
// paced at one batch per tick.
func (p *Pump) Run(ctx context.Context, interval time.Duration) {
	p.log.Info("audit streaming started", "sink", p.sink.Describe(), "interval", interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for {
				sent, err := p.once(ctx)
				if err != nil {
					// Left for the next tick. Not advancing the cursor is the retry;
					// there is nothing to do here but record why the copy is behind.
					p.log.Error("audit streaming batch failed", "err", err,
						"sink", p.sink.Describe())
					break
				}
				if sent < p.batch {
					break // drained
				}
			}
		}
	}
}

// once forwards one batch and returns how many were sent.
func (p *Pump) once(ctx context.Context) (int, error) {
	from, err := audit.StreamCursor(ctx, p.db)
	if err != nil {
		return 0, err
	}
	records, err := audit.FetchAfter(ctx, p.db, from, p.batch)
	if err != nil {
		return 0, err
	}
	if len(records) == 0 {
		return 0, nil
	}
	if err := p.sink.Emit(ctx, records); err != nil {
		return 0, err
	}
	// The batch is ordered by id ascending, so the last one is the high-water mark.
	last := records[len(records)-1].ID
	if err := audit.AdvanceStreamCursor(ctx, p.db, last); err != nil {
		// Delivered but not recorded: the next batch will re-send from the old
		// cursor, which the receiver dedupes. Reported so the double-send is not a
		// mystery in the collector.
		return len(records), err
	}
	return len(records), nil
}

// NewFromEnv builds the configured sink, or nil when audit streaming is off.
//
// Off by default: forwarding authentication events off the box is a decision
// about where sensitive data goes, and it must be one an operator makes, not one
// that happens because a default pointed somewhere. A webhook takes precedence
// over syslog when both are set, and that is logged so the ignored one is not a
// silent surprise.
func NewFromEnv(getenv func(string) string, log *slog.Logger) (Sink, error) {
	if url := getenv("SIGNARI_AUDIT_WEBHOOK_URL"); url != "" {
		if syslog := getenv("SIGNARI_AUDIT_SYSLOG_ADDR"); syslog != "" {
			log.Warn("both SIGNARI_AUDIT_WEBHOOK_URL and SIGNARI_AUDIT_SYSLOG_ADDR are set; " +
				"streaming to the webhook and ignoring syslog")
		}
		return NewWebhookSink(url, getenv("SIGNARI_AUDIT_WEBHOOK_TOKEN"))
	}
	if addr := getenv("SIGNARI_AUDIT_SYSLOG_ADDR"); addr != "" {
		return NewSyslogSink(addr, getenv("SIGNARI_AUDIT_SYSLOG_TLS") == "1",
			getenv("SIGNARI_AUDIT_SYSLOG_HOSTNAME")), nil
	}
	return nil, nil
}
