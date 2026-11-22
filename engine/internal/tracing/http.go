package tracing

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// routeSlot carries the matched pattern from NoteRoute, next to the mux, out to
// Middleware, around everything.
type routeSlot struct{ pattern string }

type routeKey struct{}

// Middleware records each request as a server span, named by its method and
// route. It goes outermost, so the span covers every wrapper's work, including a
// recovered panic's 500. The route is filled in by NoteRoute, because only the
// request the mux was handed carries the pattern: every wrapper that changes the
// context hands on a copy (see httpapi.Routes).
//
// The route is Go's ServeMux `Request.Pattern` with its method taken off, such
// as `/oauth2/token` or `/admin/users/{userID}`. When no route matched there is
// no route attribute, and the span is named by its method alone: the path of a
// 404 is whatever a scanner probed for.
func Middleware(next http.Handler) http.Handler {
	if !Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slot := &routeSlot{}
		method := methodOf(r.Method)
		ctx, span := tracer().Start(context.WithValue(r.Context(), routeKey{}, slot), method,
			trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindServer),
			trace.WithLinks(inbound(r.Header)...))
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		defer func() {
			span.SetAttributes(semconv.HTTPRequestMethodKey.String(method),
				semconv.HTTPResponseStatusCodeKey.Int(rec.code))
			if route := routeOf(slot.pattern); route != "" {
				span.SetName(method + " " + route)
				span.SetAttributes(semconv.HTTPRouteKey.String(route))
			}
			if rec.code >= 500 {
				span.SetStatus(codes.Error, "")
			}
			span.End()
		}()
		next.ServeHTTP(rec, r.WithContext(ctx))
	})
}

// NoteRoute wraps the mux itself, and hands the pattern it matched to the
// Middleware around it.
func NoteRoute(mux http.Handler) http.Handler {
	if !Enabled() {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if s, ok := r.Context().Value(routeKey{}).(*routeSlot); ok {
				s.pattern = r.Pattern
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

// inbound is the caller's span context as a link, without its tracestate.
func inbound(h http.Header) []trace.Link {
	sc := trace.SpanContextFromContext(propagation.TraceContext{}.Extract(context.Background(), propagation.HeaderCarrier(h)))
	if !sc.IsValid() {
		return nil
	}
	return []trace.Link{{SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: sc.TraceID(), SpanID: sc.SpanID(), TraceFlags: sc.TraceFlags(), Remote: true,
	})}}
}

// routeOf is a pattern without its method, or "" for none.
func routeOf(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}
	return pattern
}

// methodOf is the method, if it is one the semantic conventions call known, or
// `_OTHER`, which they say an unknown one MUST be recorded as
// (semconv/v1.43.0/attribute_group.go:7222-7229 in go.opentelemetry.io/otel
// v1.47.0). Known is RFC 9110's methods, PATCH and QUERY, all of them, so no
// valid method becomes `_OTHER` and the override that would then be required is
// not.
func methodOf(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "QUERY":
		return m
	}
	return "_OTHER"
}

type recorder struct {
	http.ResponseWriter
	code    int
	written bool
}

func (s *recorder) WriteHeader(code int) {
	if !s.written {
		s.code, s.written = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *recorder) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets a websocket upgrade reach the connection through the recorder.
func (s *recorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush lets the recorder sit in front of a streaming handler.
func (s *recorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Transport records each outbound request as a client span, from the moment it
// is sent until its response headers arrive. A request made while serving one
// is a child of that request's span, and one made by a background worker is a
// root of its own.
//
// It sends no traceparent: the destinations are relying parties, providers and
// subscribers, and a trace id handed to them would tie their logs to this one.
type Transport struct{ Base http.RoundTripper }

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !Enabled() {
		return t.Base.RoundTrip(r)
	}
	method := methodOf(r.Method)
	_, span := tracer().Start(r.Context(), method, trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.HTTPRequestMethodKey.String(method)))
	resp, err := t.Base.RoundTrip(r)
	if err != nil {
		span.SetAttributes(semconv.ErrorTypeKey.String(errorType(err)))
		span.SetStatus(codes.Error, "")
	} else {
		span.SetAttributes(semconv.HTTPResponseStatusCodeKey.Int(resp.StatusCode))
		if resp.StatusCode >= 400 {
			span.SetStatus(codes.Error, "")
		}
	}
	span.End()
	return resp, err
}

// CloseIdleConnections reaches the transport underneath, which is what
// http.Client.CloseIdleConnections looks for.
func (t *Transport) CloseIdleConnections() {
	if c, ok := t.Base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// errorType is one of a closed set: timeout, canceled or _OTHER.
func errorType(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "_OTHER"
}
