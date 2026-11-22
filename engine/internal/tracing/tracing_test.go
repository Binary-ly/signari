package tracing_test

import (
	"context"
	"encoding/binary"
	"flag"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/tracing"
)

var otlpOut = flag.String("otlp-out", "", "write the request TestSpansReachTheCollectorAsOTLP sent here, to decode with the generated OTLP types")

// Only this package may import OpenTelemetry, test files included. Everything
// a span says therefore passes through the constructors here, whose values are
// closed sets, and a handler that reached for span.SetAttributes with a client
// id would have to import the SDK to do it and fail here first.
func TestOnlyTracingImportsOpenTelemetry(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(root, "internal", "tracing")
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		files++
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(p, "go.opentelemetry.io/") && filepath.Dir(path) != own {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s imports %s: only internal/tracing may, so that nothing else can write an attribute", rel, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 500 {
		t.Fatalf("walked %d files from %s, which is not the engine", files, root)
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestTheSettingsAreReadOrRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		on   bool
		bad  string
	}{
		{name: "nothing set is off", env: nil},
		{name: "headers alone do nothing, and say so", env: map[string]string{tracing.EnvHeaders: "a=b"}, bad: tracing.EnvEndpoint},
		{name: "a ratio alone likewise", env: map[string]string{tracing.EnvRatio: "0.5"}, bad: tracing.EnvEndpoint},
		{name: "a collector on loopback", env: map[string]string{tracing.EnvEndpoint: "http://127.0.0.1:4318/v1/traces"}, on: true},
		{name: "not a URL", env: map[string]string{tracing.EnvEndpoint: "collector:4318"}, bad: "want an http or https URL"},
		{name: "user information", env: map[string]string{tracing.EnvEndpoint: "https://u:p@collector/v1/traces"}, bad: "no user information"},
		{name: "a key in clear across a network", env: map[string]string{
			tracing.EnvEndpoint: "http://collector.internal:4318/v1/traces", tracing.EnvHeaders: "x-api-key=k"}, bad: "in clear"},
		{name: "a key in clear on loopback", env: map[string]string{
			tracing.EnvEndpoint: "http://localhost:4318/v1/traces", tracing.EnvHeaders: "x-api-key=k"}, on: true},
		{name: "a key over https", env: map[string]string{
			tracing.EnvEndpoint: "https://collector.example/v1/traces", tracing.EnvHeaders: "x-api-key=k, x-team = t"}, on: true},
		{name: "a header that is not a pair", env: map[string]string{
			tracing.EnvEndpoint: "https://collector.example/v1/traces", tracing.EnvHeaders: "x-api-key"}, bad: "name=value"},
		{name: "a header name that is not a token", env: map[string]string{
			tracing.EnvEndpoint: "https://collector.example/v1/traces", tracing.EnvHeaders: "x api=k"}, bad: "name=value"},
		{name: "a ratio above one", env: map[string]string{
			tracing.EnvEndpoint: "https://collector.example/v1/traces", tracing.EnvRatio: "1.5"}, bad: "from 0 to 1"},
		{name: "a ratio that is not a number", env: map[string]string{
			tracing.EnvEndpoint: "https://collector.example/v1/traces", tracing.EnvRatio: "half"}, bad: "from 0 to 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, on, err := tracing.ConfigFrom(env(c.env))
			if c.bad != "" {
				if err == nil || !strings.Contains(err.Error(), c.bad) {
					t.Fatalf("got %v, want an error saying %q", err, c.bad)
				}
				return
			}
			if err != nil || on != c.on {
				t.Fatalf("on %v, err %v", on, err)
			}
			if c.name == "a key over https" && (cfg.Headers.Get("X-Team") != "t" || cfg.Headers.Get("X-Api-Key") != "k") {
				t.Errorf("headers %v", cfg.Headers)
			}
		})
	}
}

// Nothing is installed when nothing is configured.
func TestOffByDefault(t *testing.T) {
	stop, err := tracing.Setup(env(nil), "v", nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if tracing.Enabled() {
		t.Fatal("tracing is on with no collector named")
	}
	mux := http.NewServeMux()
	if h := tracing.Middleware(mux); h != http.Handler(mux) {
		t.Error("the middleware wrapped a handler with tracing off")
	}
}

const (
	inboundTrace = "0af7651916cd43dd8448eb211c80319c"
	inboundSpan  = "b7ad6b7169203331"
)

// The whole path, as serve runs it: Setup, a request through the middleware,
// the batch flushed at stop, and the body the collector received, read field by
// field against the numbers in the generated OTLP code.
func TestSpansReachTheCollectorAsOTLP(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies [][]byte
		header http.Header
	)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, header = append(bodies, b), r.Header.Clone()
		mu.Unlock()
	}))
	defer collector.Close()

	stop, err := tracing.Setup(env(map[string]string{
		tracing.EnvEndpoint: collector.URL + "/v1/traces",
		tracing.EnvHeaders:  "X-Api-Key=k1",
	}), "1.2.3", nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /things/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	req := httptest.NewRequest(http.MethodGet, "/things/person@example.test", nil)
	req.Header.Set("traceparent", "00-"+inboundTrace+"-"+inboundSpan+"-01")
	tracing.Middleware(tracing.NoteRoute(mux)).ServeHTTP(httptest.NewRecorder(), req)
	stop()

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("the collector received %d requests", len(bodies))
	}
	if header.Get("Content-Type") != "application/x-protobuf" || header.Get("X-Api-Key") != "k1" {
		t.Errorf("sent with %v", header)
	}
	if *otlpOut != "" {
		if err := os.WriteFile(*otlpOut, bodies[0], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(string(bodies[0]), "person@example.test") {
		t.Error("the path reached the export")
	}

	rs := one(t, decode(t, bodies[0]), 1, "ExportTraceServiceRequest.resource_spans")
	resource := one(t, decode(t, rs.b), 1, "ResourceSpans.resource")
	if attrs := keyValues(t, decode(t, resource.b), 1); attrs["service.name"] != "signari" || attrs["service.version"] != "1.2.3" {
		t.Errorf("resource %v", attrs)
	}
	ss := one(t, decode(t, rs.b), 2, "ResourceSpans.scope_spans")
	scope := decode(t, one(t, decode(t, ss.b), 1, "ScopeSpans.scope").b)
	if string(one(t, scope, 1, "name").b) != "signari.dev/engine" || string(one(t, scope, 2, "version").b) != "1.2.3" {
		t.Errorf("scope %v", scope)
	}
	sp := decode(t, one(t, decode(t, ss.b), 2, "ScopeSpans.spans").b)

	if len(one(t, sp, 1, "trace_id").b) != 16 || len(one(t, sp, 2, "span_id").b) != 8 {
		t.Error("ids of the wrong length")
	}
	if hexOf(one(t, sp, 1, "trace_id").b) == inboundTrace {
		t.Error("the span joined the caller's trace")
	}
	if len(all(sp, 4)) != 0 {
		t.Error("a parent_span_id on a root span")
	}
	if name := string(one(t, sp, 5, "name").b); name != "GET /things/{id}" {
		t.Errorf("name %q", name)
	}
	if k := one(t, sp, 6, "kind"); k.v != 2 {
		t.Errorf("kind %d, want 2 (SERVER)", k.v)
	}
	start, end := one(t, sp, 7, "start_time_unix_nano"), one(t, sp, 8, "end_time_unix_nano")
	if start.wire != 1 || end.wire != 1 || start.v == 0 || end.v < start.v {
		t.Errorf("times %+v %+v", start, end)
	}
	attrs := keyValues(t, sp, 9)
	want := map[string]string{"http.request.method": "GET", "http.route": "/things/{id}", "http.response.status_code": "503"}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("%s = %q, want %q", k, attrs[k], v)
		}
	}
	if len(attrs) != len(want) {
		t.Errorf("attributes %v", attrs)
	}
	link := decode(t, one(t, sp, 13, "links").b)
	if hexOf(one(t, link, 1, "link trace_id").b) != inboundTrace || hexOf(one(t, link, 2, "link span_id").b) != inboundSpan {
		t.Error("the link does not name the caller's span")
	}
	if f := one(t, link, 6, "link flags"); f.wire != 5 || f.v != 0x301 {
		t.Errorf("link flags %#x, want sampled, remote known, remote", f.v)
	}
	status := decode(t, one(t, sp, 15, "status").b)
	if c := one(t, status, 3, "Status.code"); c.v != 2 {
		t.Errorf("status code %d, want 2 (ERROR)", c.v)
	}
	if len(all(status, 2)) != 0 {
		t.Error("a status message was written")
	}
	if f := one(t, sp, 16, "flags"); f.wire != 5 || f.v != 0x101 {
		t.Errorf("flags %#x, want sampled and a parent known not to be remote", f.v)
	}
}

// A collector that refuses is reported once, not once a batch.
func TestARefusingCollectorIsLoggedOnce(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer collector.Close()
	var log strings.Builder
	stop, err := tracing.Setup(env(map[string]string{tracing.EnvEndpoint: collector.URL}), "v", nil,
		slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err != nil {
		t.Fatal(err)
	}
	h := tracing.Middleware(tracing.NoteRoute(http.NewServeMux()))
	for range 600 { // two batches of 512
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	stop()
	if n := strings.Count(log.String(), "not taking spans"); n != 1 {
		t.Errorf("the refusal was logged %d times:\n%s", n, log.String())
	}
}

// The caller's trace context is a link on a new root, and its tracestate does
// not come with it.
func TestAnInboundTraceparentIsALinkAndNotAParent(t *testing.T) {
	spans, stop := tracing.Capture()
	defer stop()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("traceparent", "00-"+inboundTrace+"-"+inboundSpan+"-00")
	req.Header.Set("tracestate", "vendor=person@example.test")
	tracing.Middleware(http.NewServeMux()).ServeHTTP(httptest.NewRecorder(), req)

	got := spans.Spans()
	if len(got) != 1 {
		t.Fatalf("%d spans", len(got))
	}
	s := got[0]
	if s.Parent != "" || s.TraceID == inboundTrace {
		t.Errorf("parent %q, trace %s: the caller chose this span's trace", s.Parent, s.TraceID)
	}
	if len(s.Links) != 1 || s.Links[0].TraceID != inboundTrace || s.Links[0].SpanID != inboundSpan || !s.Links[0].Remote {
		t.Fatalf("links %+v", s.Links)
	}
	if s.Links[0].TraceState != "" {
		t.Errorf("the caller's tracestate came along: %q", s.Links[0].TraceState)
	}
	// Unmatched, so no route, and named by the method alone.
	if s.Name != "POST" || s.Attributes["http.route"] != "" || s.Attributes["http.response.status_code"] != "404" {
		t.Errorf("%q %v", s.Name, s.Attributes)
	}
}

// A query is a child of the span it ran under, named by the function that ran
// it, and its error is its SQLSTATE and nothing the server said about the row.
func TestAQueryIsRecordedUnderItsRequest(t *testing.T) {
	spans, stop := tracing.Capture()
	defer stop()
	db := tracing.DB{}

	// Outside a request: nothing.
	ctx := db.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "SELECT 1"})
	db.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
	if n := len(spans.Spans()); n != 0 {
		t.Fatalf("%d spans from a query outside any request", n)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /q", func(w http.ResponseWriter, r *http.Request) {
		ctx := db.TraceQueryStart(r.Context(), nil, pgx.TraceQueryStartData{SQL: "\n\t insert into core.users (email) values ($1)", Args: []any{"person@example.test"}})
		db.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: &pgconn.PgError{
			Code: "23505", Message: "duplicate key value", Detail: "Key (email)=(person@example.test) already exists."}})
		ctx = db.TraceQueryStart(r.Context(), nil, pgx.TraceQueryStartData{SQL: "-- no keyword\nSELECT 1"})
		db.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: context.Canceled})
	})
	tracing.Middleware(tracing.NoteRoute(mux)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/q", nil))

	got := spans.Spans()
	if len(got) != 3 {
		t.Fatalf("%d spans: %+v", len(got), got)
	}
	insert, other, server := got[0], got[1], got[2]
	if insert.Parent != server.SpanID || other.Parent != server.SpanID || insert.TraceID != server.TraceID {
		t.Error("the queries are not children of the request")
	}
	fn := "tracing_test.TestAQueryIsRecordedUnderItsRequest.func1"
	if insert.Name != "INSERT "+fn || insert.Kind != tracing.KindClient {
		t.Errorf("%q %s", insert.Name, insert.Kind)
	}
	want := map[string]string{"db.system.name": "postgresql", "db.operation.name": "INSERT",
		"code.function.name": fn, "db.response.status_code": "23505", "error.type": "23505"}
	for k, v := range want {
		if insert.Attributes[k] != v {
			t.Errorf("%s = %q, want %q", k, insert.Attributes[k], v)
		}
	}
	if !insert.Error || insert.StatusDescription != "" || len(insert.Attributes) != len(want) {
		t.Errorf("%+v", insert)
	}
	if other.Name != "OTHER "+fn || other.Attributes["error.type"] != "canceled" || other.Attributes["db.response.status_code"] != "" {
		t.Errorf("%q %v", other.Name, other.Attributes)
	}
	for _, s := range got {
		for k, v := range s.Attributes {
			if strings.Contains(v, "example.test") {
				t.Errorf("%s carries %s = %q", s.Name, k, v)
			}
		}
	}
}

// An outbound call is a child of the request that made it, or a root of its own.
func TestAnOutboundCallIsRecorded(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("traceparent") != "" {
			t.Error("a traceparent was sent to a destination")
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer dest.Close()
	client := &http.Client{Transport: &tracing.Transport{Base: http.DefaultTransport}}

	// Off: straight through, and nothing recorded anywhere.
	if resp, err := client.Get(dest.URL + "/off"); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
	}

	spans, stop := tracing.Capture()
	defer stop()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /call", func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, dest.URL+"/hook?user=person@example.test", nil)
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	})
	tracing.Middleware(tracing.NoteRoute(mux)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/call", nil))
	dest.Close()
	if _, err := client.Get(dest.URL); err == nil {
		t.Fatal("a closed server answered")
	}

	got := spans.Spans()
	if len(got) != 3 {
		t.Fatalf("%d spans: %+v", len(got), got)
	}
	call, server, root := got[0], got[1], got[2]
	if call.Parent != server.SpanID || call.Kind != tracing.KindClient || call.Name != "POST" ||
		call.Attributes["http.response.status_code"] != "418" || !call.Error || len(call.Attributes) != 2 {
		t.Errorf("the call: %+v", call)
	}
	if root.Parent != "" || root.Attributes["error.type"] != "_OTHER" || !root.Error {
		t.Errorf("the failed call: %+v", root)
	}
}

// The protobuf reader the export test reads with.

type field struct {
	num, wire int
	v         uint64
	b         []byte
}

func decode(t *testing.T, b []byte) []field {
	t.Helper()
	var out []field
	for len(b) > 0 {
		k, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatalf("a bad key at %x", b)
		}
		b = b[n:]
		f := field{num: int(k >> 3), wire: int(k & 7)}
		switch f.wire {
		case 0:
			f.v, n = binary.Uvarint(b)
			if n <= 0 {
				t.Fatal("a bad varint")
			}
			b = b[n:]
		case 1:
			f.v, b = binary.LittleEndian.Uint64(b), b[8:]
		case 5:
			f.v, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || int(l) > len(b)-n {
				t.Fatal("a bad length")
			}
			f.b, b = b[n:n+int(l)], b[n+int(l):]
		default:
			t.Fatalf("wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out
}

func all(fs []field, num int) []field {
	var out []field
	for _, f := range fs {
		if f.num == num {
			out = append(out, f)
		}
	}
	return out
}

func one(t *testing.T, fs []field, num int, what string) field {
	t.Helper()
	got := all(fs, num)
	if len(got) != 1 {
		t.Fatalf("%s (field %d) appears %d times", what, num, len(got))
	}
	return got[0]
}

// keyValues reads repeated KeyValue at num: key 1, AnyValue 2, whose string is
// 1, bool 2, int 3.
func keyValues(t *testing.T, fs []field, num int) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, kv := range all(fs, num) {
		f := decode(t, kv.b)
		key := string(one(t, f, 1, "KeyValue.key").b)
		value := decode(t, one(t, f, 2, "KeyValue.value").b)
		if len(value) != 1 {
			t.Fatalf("%s has %d values", key, len(value))
		}
		switch v := value[0]; {
		case v.num == 1 && v.wire == 2:
			m[key] = string(v.b)
		case v.num == 2 && v.wire == 0:
			m[key] = strconv.FormatBool(v.v != 0)
		case v.num == 3 && v.wire == 0:
			m[key] = strconv.FormatInt(int64(v.v), 10)
		default:
			t.Fatalf("%s is AnyValue field %d, wire type %d", key, v.num, v.wire)
		}
	}
	return m
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
