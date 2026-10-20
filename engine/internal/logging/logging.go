// Package logging builds the engine's diagnostic logger: its format and level
// from the environment, and a handler that names the request every line
// logged with its context belongs to (3.07).
//
// The diagnostic log is for operating the server, not evidence of what
// happened to a person; that is the audit trail. So a line carries the subject
// id when it must say whose request it was, never a username or an address
// somebody would recognise. A test in this package holds every log call in the
// engine to that.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

type correlationKey struct{}

// WithCorrelation returns ctx carrying a request's correlation id.
func WithCorrelation(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// Correlation returns the correlation id on ctx, or "" outside a request.
func Correlation(ctx context.Context) string {
	if v, ok := ctx.Value(correlationKey{}).(string); ok {
		return v
	}
	return ""
}

// New builds the logger SIGNARI_LOG_FORMAT and SIGNARI_LOG_LEVEL ask for:
// `text` (logfmt, the default) or `json`, at `debug`, `info` (the default),
// `warn` or `error`. A value it does not know refuses to start, because a
// typo that fell back to the default would look like a setting that took.
func New(w io.Writer, getenv func(string) string) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	switch v := strings.ToLower(getenv("SIGNARI_LOG_LEVEL")); v {
	case "", "info":
	case "debug":
		opts.Level = slog.LevelDebug
	case "warn", "warning":
		opts.Level = slog.LevelWarn
	case "error":
		opts.Level = slog.LevelError
	default:
		return nil, fmt.Errorf("SIGNARI_LOG_LEVEL=%q: want debug, info, warn or error", v)
	}
	var h slog.Handler
	switch v := strings.ToLower(getenv("SIGNARI_LOG_FORMAT")); v {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("SIGNARI_LOG_FORMAT=%q: want text or json", v)
	}
	return slog.New(correlating{h}), nil
}

// correlating adds correlation_id to every record logged with a request's
// context, unless the call named one itself. The id was added by hand at each
// call site that remembered to, so most lines a request produced could not be
// tied to it.
type correlating struct{ slog.Handler }

func (h correlating) Handle(ctx context.Context, r slog.Record) error {
	if id := Correlation(ctx); id != "" {
		named := false
		r.Attrs(func(a slog.Attr) bool {
			named = a.Key == "correlation_id"
			return !named
		})
		if !named {
			r.AddAttrs(slog.String("correlation_id", id))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h correlating) WithAttrs(attrs []slog.Attr) slog.Handler {
	return correlating{h.Handler.WithAttrs(attrs)}
}

func (h correlating) WithGroup(name string) slog.Handler {
	return correlating{h.Handler.WithGroup(name)}
}
