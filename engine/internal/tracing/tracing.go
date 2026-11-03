// Package tracing records what a request did as OpenTelemetry spans and sends
// them to a collector over OTLP/HTTP (3.09). It is off unless
// SIGNARI_OTLP_TRACES_ENDPOINT names a collector.
//
// # No identifiers
//
// A span goes where a metric goes: into a store this system cannot reach, kept
// for as long as somebody else decides, outside the boundary that
// `subjects/{id}/erase` works on. So the rule is the metrics package's rule, and
// it is held the same way, by structure. This is the only package that imports
// OpenTelemetry (TestOnlyTracingImportsOpenTelemetry), and every span name and
// attribute value it writes comes from a closed set: a route pattern, a method,
// a status code, an SQL keyword and SQLSTATE, and the name of the Go function
// that ran a query. Nothing it writes is taken from a request.
//
// Left out on purpose: URLs and query strings, client and user identifiers,
// addresses, the hosts of outbound calls, SQL text (the function that ran it is
// named instead), error messages (a PostgreSQL DETAIL quotes the row), and the
// SDK's panic event (its message is whatever was panicked with).
//
// # Inbound trace context is a link, never a parent
//
// A caller's traceparent is recorded as a link on a new root span. If it were
// taken as the parent, anybody on the internet could choose this server's trace
// ids and its sampling decision, and file its spans under a trace of their own.
// The caller's tracestate is dropped, because it is the caller's free text.
package tracing

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// The settings, documented in docs/configuration.md and docs/tracing.md.
const (
	// EnvEndpoint is the collector's OTLP/HTTP traces URL, such as
	// http://localhost:4318/v1/traces. Unset, nothing is traced.
	EnvEndpoint = "SIGNARI_OTLP_TRACES_ENDPOINT"
	// EnvHeaders are headers sent with every export, as name=value pairs
	// separated by commas: a collector's API key, usually.
	EnvHeaders = "SIGNARI_OTLP_HEADERS"
	// EnvRatio is the share of requests traced, from 0 to 1. The default is 1.
	EnvRatio = "SIGNARI_TRACES_SAMPLE_RATIO"
)

// scopeName names the instrumentation in every export.
const scopeName = "signari.dev/engine"

// Config is what the environment asks for.
type Config struct {
	Endpoint *url.URL
	Headers  http.Header
	Ratio    float64
}

// ConfigFrom reads the settings. on is false when no endpoint is named. A
// malformed value is an error, because this is read at startup, and a typo
// that quietly turned tracing off would be found when somebody needed a trace.
func ConfigFrom(getenv func(string) string) (cfg Config, on bool, err error) {
	raw := strings.TrimSpace(getenv(EnvEndpoint))
	if raw == "" {
		if getenv(EnvHeaders) != "" || getenv(EnvRatio) != "" {
			return Config{}, false, fmt.Errorf("%s and %s do nothing without %s", EnvHeaders, EnvRatio, EnvEndpoint)
		}
		return Config{}, false, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return Config{}, false, fmt.Errorf("%s=%q: want an http or https URL with no user information, such as http://localhost:4318/v1/traces", EnvEndpoint, raw)
	}
	cfg = Config{Endpoint: u, Headers: http.Header{}, Ratio: 1}

	if h := strings.TrimSpace(getenv(EnvHeaders)); h != "" {
		for _, pair := range strings.Split(h, ",") {
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if !ok || !token(name) || strings.ContainsAny(value, "\r\n") {
				return Config{}, false, fmt.Errorf("%s: want name=value pairs separated by commas, and %q is not one", EnvHeaders, pair)
			}
			cfg.Headers.Add(name, value)
		}
		// Refused, not warned about: a collector's API key sent in clear across a
		// network is disclosed on every export.
		if u.Scheme == "http" && !loopback(u.Hostname()) {
			return Config{}, false, fmt.Errorf("%s would be sent in clear to %s: use https, or a collector on loopback", EnvHeaders, u.Host)
		}
	}

	if r := strings.TrimSpace(getenv(EnvRatio)); r != "" {
		f, err := strconv.ParseFloat(r, 64)
		if err != nil || f < 0 || f > 1 {
			return Config{}, false, fmt.Errorf("%s=%q: want a number from 0 to 1", EnvRatio, r)
		}
		cfg.Ratio = f
	}
	return cfg, true, nil
}

// token reports whether s is an HTTP field name: "field-name = token", and
// token is 1*tchar (specs/rfc9110.txt:1466, 1733-1737).
func token(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", c):
		default:
			return false
		}
	}
	return true
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Setup starts tracing as the environment asks, and returns what flushes the
// spans still queued when the server stops. roots are the certificates an https
// collector is verified against.
func Setup(getenv func(string) string, release string, roots *x509.CertPool, log *slog.Logger) (stop func(), err error) {
	cfg, on, err := ConfigFrom(getenv)
	if err != nil || !on {
		return func() {}, err
	}
	exp := newExporter(cfg, roots, log)
	// Every option is given explicitly. The SDK reads OTEL_BSP_* and
	// OTEL_TRACES_SAMPLER first and lets an option override them, so with every
	// option given, the settings this page documents are the ones that apply.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.Ratio))),
		sdktrace.WithBatcher(exp,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithExportTimeout(10*time.Second),
			sdktrace.WithMaxQueueSize(2048),
			sdktrace.WithMaxExportBatchSize(512)),
		sdktrace.WithResource(resource(release)),
		// The event it records carries the panic's message and a stack trace.
		sdktrace.WithoutPanicRecording(),
	)
	// The SDK hands every export error here as well as returning it, and by
	// default prints each one. The exporter logs a failure once and its
	// recovery once, so this is for the SDK's other complaints, at debug.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { log.Debug("tracing", "err", err) }))
	install(tp, release)
	log.Info("tracing", "collector", cfg.Endpoint.Scheme+"://"+cfg.Endpoint.Host+cfg.Endpoint.Path,
		"sample_ratio", cfg.Ratio)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		uninstall()
		if err := tp.Shutdown(ctx); err != nil {
			log.Warn("tracing: spans still queued at shutdown were not sent", "err", err)
		}
	}, nil
}

// resource names the service and its release, and nothing about the host it
// runs on. A build with no release stamped in says nothing, rather than "".
func resource(release string) *sdkresource.Resource {
	if release == "" {
		return sdkresource.NewSchemaless(semconv.ServiceName("signari"))
	}
	return sdkresource.NewSchemaless(semconv.ServiceName("signari"), semconv.ServiceVersion(release))
}

type holder struct{ tracer trace.Tracer }

var (
	enabled atomic.Bool
	current atomic.Pointer[holder]
	nothing = noop.NewTracerProvider().Tracer(scopeName)
)

func install(tp trace.TracerProvider, release string) {
	current.Store(&holder{tracer: tp.Tracer(scopeName, trace.WithInstrumentationVersion(release))})
	enabled.Store(true)
}

func uninstall() {
	enabled.Store(false)
	current.Store(nil)
}

// Enabled reports whether spans are being recorded. The middleware is not
// installed when they are not, so a deployment that does not trace pays nothing.
func Enabled() bool { return enabled.Load() }

func tracer() trace.Tracer {
	if h := current.Load(); h != nil {
		return h.tracer
	}
	return nothing
}
