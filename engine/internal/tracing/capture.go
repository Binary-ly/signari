package tracing

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Span is a finished span as a test reads it, so that a test elsewhere can
// look at what was recorded without importing OpenTelemetry, which only this
// package may.
type Span struct {
	Name, Kind              string
	TraceID, SpanID, Parent string // Parent is "" for a root
	Attributes              map[string]string
	Links                   []Link
	Events                  int
	Error                   bool
	StatusDescription       string
}

// Link is a span's link as a test reads it.
type Link struct {
	TraceID, SpanID, TraceState string
	Remote                      bool
	Attributes                  int
}

// Captured is the spans recorded since Capture.
type Captured struct {
	mu    sync.Mutex
	spans []Span
}

// Capture records every span, synchronously, until stop is called. For tests:
// the server under test must be built after it, because Middleware is only
// installed while tracing is on.
func Capture() (c *Captured, stop func()) {
	c = &Captured{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(c), sdktrace.WithResource(resource("test")),
		sdktrace.WithoutPanicRecording())
	install(tp, "test")
	return c, func() {
		uninstall()
		_ = tp.Shutdown(context.Background())
	}
}

// Spans are the spans finished so far, in the order they finished.
func (c *Captured) Spans() []Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Span(nil), c.spans...)
}

func (c *Captured) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (c *Captured) OnEnd(s sdktrace.ReadOnlySpan) {
	out := Span{
		Name:              s.Name(),
		Kind:              s.SpanKind().String(),
		TraceID:           s.SpanContext().TraceID().String(),
		SpanID:            s.SpanContext().SpanID().String(),
		Attributes:        attributes(s.Attributes()),
		Events:            len(s.Events()),
		Error:             s.Status().Code == codes.Error,
		StatusDescription: s.Status().Description,
	}
	if p := s.Parent(); p.IsValid() {
		out.Parent = p.SpanID().String()
	}
	for _, l := range s.Links() {
		out.Links = append(out.Links, Link{
			TraceID: l.SpanContext.TraceID().String(), SpanID: l.SpanContext.SpanID().String(),
			TraceState: l.SpanContext.TraceState().String(), Remote: l.SpanContext.IsRemote(),
			Attributes: len(l.Attributes),
		})
	}
	c.mu.Lock()
	c.spans = append(c.spans, out)
	c.mu.Unlock()
}

func (c *Captured) Shutdown(context.Context) error   { return nil }
func (c *Captured) ForceFlush(context.Context) error { return nil }

func attributes(kvs []attribute.KeyValue) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.Emit()
	}
	return m
}

var _ sdktrace.SpanProcessor = (*Captured)(nil)

// Kinds, as Span.Kind spells them.
var (
	KindServer = trace.SpanKindServer.String()
	KindClient = trace.SpanKindClient.String()
)
