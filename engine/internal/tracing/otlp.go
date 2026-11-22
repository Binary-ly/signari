package tracing

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// exporter sends spans to a collector as OTLP over HTTP: a POST of one
// ExportTraceServiceRequest, protobuf-encoded, as application/x-protobuf
// (go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.46.0,
// client.go:35 and 319).
//
// Written here rather than taken from that module, which brings grpc,
// grpc-gateway, genproto and protobuf into the module graph to send one
// message over HTTP: 66 packages of grpc alone, measured by linking it. The
// messages are small and fixed, and a dependency is a party that can change
// what this binary does (docs/dependencies.md).
//
// The layout is the generated code's in go.opentelemetry.io/proto/otlp v1.11.0,
// and each field number below names the file and line it was read from.
type exporter struct {
	endpoint string
	headers  http.Header
	client   *http.Client
	log      *slog.Logger
	failing  atomic.Bool
}

func newExporter(cfg Config, roots *x509.CertPool, log *slog.Logger) *exporter {
	return &exporter{
		endpoint: cfg.Endpoint.String(),
		headers:  cfg.Headers,
		log:      log,
		// Not a safedial client. The collector is the operator's own, usually on
		// loopback or on the cluster network that safedial exists to keep
		// relying parties out of. And not wrapped in Transport, whose spans
		// would be exported, and the export traced, without end.
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConnsPerHost:   2,
				ForceAttemptHTTP2:     true,
			},
			// A collector that redirects is misconfigured, and following it would
			// carry the headers somewhere nobody named.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// ExportSpans sends one batch. A batch the collector does not take is dropped:
// a trace is a diagnostic, not a record, and the outbox is where delivery is
// guaranteed. The first failure is logged and so is the recovery, and the
// failures in between are not, since a collector that is down would otherwise
// write a line every five seconds.
func (e *exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(encode(spans)))
	if err != nil {
		return err
	}
	req.Header = e.headers.Clone()
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := e.client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = fmt.Errorf("the collector answered %d", resp.StatusCode)
		}
	}
	if err != nil {
		if !e.failing.Swap(true) {
			e.log.Warn("tracing: the collector is not taking spans, and batches are dropped until it does",
				"err", err, "spans", len(spans))
		}
		return err
	}
	if e.failing.Swap(false) {
		e.log.Info("tracing: the collector is taking spans again")
	}
	return nil
}

func (e *exporter) Shutdown(context.Context) error {
	e.client.CloseIdleConnections()
	return nil
}

// Protobuf wire types.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// pb is a protobuf message being written. A field at its zero value is left
// out, as proto3 does, except a oneof member, which is written whatever its
// value so a reader can tell which member is set.
type pb []byte

func (b *pb) varint(v uint64) { *b = binary.AppendUvarint(*b, v) }

func (b *pb) key(field, wire int) { b.varint(uint64(field)<<3 | uint64(wire)) }

func (b *pb) bytes(field int, v []byte) {
	if len(v) == 0 {
		return
	}
	b.key(field, wireBytes)
	b.varint(uint64(len(v)))
	*b = append(*b, v...)
}

func (b *pb) string(field int, v string) { b.bytes(field, []byte(v)) }

func (b *pb) uint(field int, v uint64) {
	if v == 0 {
		return
	}
	b.key(field, wireVarint)
	b.varint(v)
}

func (b *pb) fixed64(field int, v uint64) {
	if v == 0 {
		return
	}
	b.key(field, wireFixed64)
	*b = binary.LittleEndian.AppendUint64(*b, v)
}

func (b *pb) fixed32(field int, v uint32) {
	if v == 0 {
		return
	}
	b.key(field, wireFixed32)
	*b = binary.LittleEndian.AppendUint32(*b, v)
}

func (b *pb) message(field int, fill func(*pb)) {
	var m pb
	fill(&m)
	b.key(field, wireBytes)
	b.varint(uint64(len(m)))
	*b = append(*b, m...)
}

// encode is the ExportTraceServiceRequest for spans, which all come from one
// provider and so share one resource.
func encode(spans []sdktrace.ReadOnlySpan) []byte {
	var req pb
	if len(spans) == 0 {
		return req
	}
	type scope struct {
		name, version, schema string
		spans                 []sdktrace.ReadOnlySpan
	}
	var scopes []*scope
	index := map[string]*scope{}
	for _, s := range spans {
		is := s.InstrumentationScope()
		k := is.Name + "\x00" + is.Version + "\x00" + is.SchemaURL
		if index[k] == nil {
			index[k] = &scope{name: is.Name, version: is.Version, schema: is.SchemaURL}
			scopes = append(scopes, index[k])
		}
		index[k].spans = append(index[k].spans, s)
	}
	res := spans[0].Resource()

	// ExportTraceServiceRequest.resource_spans = 1 (collector/trace/v1/trace_service.pb.go:48).
	req.message(1, func(rs *pb) {
		// ResourceSpans.resource = 1 (trace/v1/trace.pb.go:310); Resource.attributes = 1
		// (resource/v1/resource.pb.go:48).
		rs.message(1, func(r *pb) {
			for _, kv := range res.Attributes() {
				r.message(1, func(k *pb) { keyValue(k, kv) })
			}
		})
		for _, sc := range scopes {
			// ResourceSpans.scope_spans = 2 (trace.pb.go:312).
			rs.message(2, func(ss *pb) {
				// ScopeSpans.scope = 1 (trace.pb.go:384); InstrumentationScope.name = 1,
				// version = 2 (common/v1/common.pb.go:413, 416).
				ss.message(1, func(is *pb) {
					is.string(1, sc.name)
					is.string(2, sc.version)
				})
				// ScopeSpans.spans = 2, schema_url = 3 (trace.pb.go:386, 393).
				for _, s := range sc.spans {
					ss.message(2, func(m *pb) { span(m, s) })
				}
				ss.string(3, sc.schema)
			})
		}
		// ResourceSpans.schema_url = 3 (trace.pb.go:319).
		rs.string(3, res.SchemaURL())
	})
	return req
}

// span writes one Span (trace.pb.go:452-559).
//
// trace_state (3) is never written: this server's is always empty. Events (11)
// are counted as dropped (12) rather than written, because nothing here
// records one, and the one the SDK can record, a panic's, carries its message.
// The status's message (Status.message = 2) is never written either.
func span(m *pb, s sdktrace.ReadOnlySpan) {
	sc := s.SpanContext()
	tid, sid := sc.TraceID(), sc.SpanID()
	m.bytes(1, tid[:]) // trace_id (463)
	m.bytes(2, sid[:]) // span_id (470)
	if p := s.Parent(); p.IsValid() {
		psid := p.SpanID()
		m.bytes(4, psid[:]) // parent_span_id (477)
	}
	m.string(5, s.Name())                                  // name (511)
	m.uint(6, kind(s.SpanKind()))                          // kind (515)
	m.fixed64(7, uint64(max(s.StartTime().UnixNano(), 0))) // start_time_unix_nano (522)
	m.fixed64(8, uint64(max(s.EndTime().UnixNano(), 0)))   // end_time_unix_nano (529)
	for _, kv := range s.Attributes() {
		m.message(9, func(k *pb) { keyValue(k, kv) }) // attributes (541)
	}
	m.uint(10, uint64(s.DroppedAttributes()))             // dropped_attributes_count (545)
	m.uint(12, uint64(s.DroppedEvents()+len(s.Events()))) // dropped_events_count (550)
	for _, l := range s.Links() {
		m.message(13, func(k *pb) { link(k, l) }) // links (553)
	}
	m.uint(14, uint64(s.DroppedLinks())) // dropped_links_count (556)
	if code := status(s.Status().Code); code != 0 {
		// status (559); Status.code = 3 (714-716).
		m.message(15, func(st *pb) { st.uint(3, code) })
	}
	// flags (499): the trace flags in bits 0-7, and in bits 8 and 9 whether the
	// parent is remote, which here it never is: the masks are 256 and 512
	// (trace.pb.go:60-65).
	m.fixed32(16, uint32(sc.TraceFlags())|0x100)
}

// link writes one Span.Link (trace.pb.go:851-888): the caller's span context
// and nothing else. Attributes are counted as dropped, and none are set.
func link(m *pb, l sdktrace.Link) {
	tid, sid := l.SpanContext.TraceID(), l.SpanContext.SpanID()
	m.bytes(1, tid[:])                                           // trace_id (858)
	m.bytes(2, sid[:])                                           // span_id (860)
	m.uint(5, uint64(len(l.Attributes)+l.DroppedAttributeCount)) // dropped_attributes_count (870)
	flags := uint32(l.SpanContext.TraceFlags()) | 0x100          // flags (888), as for a span
	if l.SpanContext.IsRemote() {
		flags |= 0x200
	}
	m.fixed32(6, flags)
}

// keyValue writes one KeyValue: key = 1, value = 2 (common.pb.go:334, 336). The
// value is an AnyValue, whose members are string_value = 1, bool_value = 2,
// int_value = 3 and double_value = 4 (common.pb.go:160-172).
func keyValue(k *pb, kv attribute.KeyValue) {
	k.string(1, string(kv.Key))
	k.message(2, func(v *pb) {
		switch kv.Value.Type() {
		case attribute.BOOL:
			v.key(2, wireVarint)
			if kv.Value.AsBool() {
				v.varint(1)
			} else {
				v.varint(0)
			}
		case attribute.INT64:
			// As its two's complement, which is how protobuf-go writes an int64
			// (google.golang.org/protobuf v1.36.12, internal/impl/codec_gen.go:1851):
			// not zigzag, which is sint64's (2266).
			v.key(3, wireVarint)
			v.varint(uint64(kv.Value.AsInt64()))
		case attribute.FLOAT64:
			v.key(4, wireFixed64)
			*v = binary.LittleEndian.AppendUint64(*v, math.Float64bits(kv.Value.AsFloat64()))
		default:
			s := kv.Value.Emit()
			v.key(1, wireBytes)
			v.varint(uint64(len(s)))
			*v = append(*v, s...)
		}
	})
}

// kind is Span.SpanKind's number (trace.pb.go:118-135).
func kind(k trace.SpanKind) uint64 {
	switch k {
	case trace.SpanKindInternal:
		return 1
	case trace.SpanKindServer:
		return 2
	case trace.SpanKindClient:
		return 3
	case trace.SpanKindProducer:
		return 4
	case trace.SpanKindConsumer:
		return 5
	}
	return 0
}

// status is Status.StatusCode's number (trace.pb.go:191-196), which is not the
// SDK's: there Error is 1 and Ok is 2 (go.opentelemetry.io/otel v1.47.0,
// codes/codes.go:22, 30), and OTLP has them the other way round.
func status(c codes.Code) uint64 {
	switch c {
	case codes.Ok:
		return 1
	case codes.Error:
		return 2
	}
	return 0
}
