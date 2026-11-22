package tracing

import (
	"context"
	"errors"
	"runtime"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// DB is a pgx tracer recording each query, and each batch, as a client span.
//
// Only under a span already being recorded: a query run while serving a traced
// request is a child of it, and the background workers' queries, which have no
// request to belong to, are not recorded at all.
//
// A span is named by the statement's first keyword and the Go function that ran
// it, such as `SELECT store.(*Store).ActiveClient`. Not the SQL: that names the
// query no better than the function does, and it is the one place a value could
// have been written into a statement instead of passed as an argument.
type DB struct{}

var (
	_ pgx.QueryTracer = DB{}
	_ pgx.BatchTracer = DB{}
)

type dbSpanKey struct{}

func (DB) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return startDB(ctx, operation(data.SQL))
}

func (DB) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	endDB(ctx, data.Err)
}

func (DB) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return startDB(ctx, "BATCH")
}

func (DB) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {}

func (DB) TraceBatchEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchEndData) {
	endDB(ctx, data.Err)
}

func startDB(ctx context.Context, op string) context.Context {
	if !trace.SpanFromContext(ctx).IsRecording() {
		return ctx
	}
	fn := caller()
	ctx, span := tracer().Start(ctx, op+" "+fn, trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemNamePostgreSQL, semconv.DBOperationNameKey.String(op),
			semconv.CodeFunctionNameKey.String(fn)))
	// Under a key of its own, so the end of a query that was not recorded finds
	// nothing, rather than the request's span, which it would end.
	return context.WithValue(ctx, dbSpanKey{}, span)
}

func endDB(ctx context.Context, err error) {
	span, ok := ctx.Value(dbSpanKey{}).(trace.Span)
	if !ok {
		return
	}
	if err != nil {
		kind := errorType(err)
		var pg *pgconn.PgError
		if errors.As(err, &pg) && sqlstate(pg.Code) {
			kind = pg.Code
			span.SetAttributes(semconv.DBResponseStatusCodeKey.String(pg.Code))
		}
		span.SetAttributes(semconv.ErrorTypeKey.String(kind))
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

// operations are the statement keywords a span may be named by. Anything else
// is OTHER.
var operations = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true,
	"WITH": true, "VALUES": true, "BEGIN": true, "COMMIT": true, "ROLLBACK": true,
	"SAVEPOINT": true, "RELEASE": true, "SET": true, "LOCK": true, "COPY": true,
	"CALL": true, "DO": true, "NOTIFY": true, "LISTEN": true, "UNLISTEN": true,
	"TRUNCATE": true, "ANALYZE": true, "EXPLAIN": true,
}

func operation(sql string) string {
	s := strings.TrimLeft(sql, " \t\r\n(")
	end := strings.IndexFunc(s, func(c rune) bool { return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') })
	if end < 0 {
		end = len(s)
	}
	if op := strings.ToUpper(s[:end]); operations[op] {
		return op
	}
	return "OTHER"
}

// sqlstate reports whether code is five digits and capital letters, the shape
// of an SQLSTATE. A code of any other shape is not recorded.
func sqlstate(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, c := range code {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// caller is the first function in this module, outside this package, on the
// stack: the one that ran the query, with its package path shortened to the
// package's name. Function names are fixed when the binary is built, which is
// what makes them a closed set.
func caller() string {
	var pcs [32]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs[:])])
	for {
		f, more := frames.Next()
		if strings.HasPrefix(f.Function, "signari.dev/engine/") &&
			!strings.HasPrefix(f.Function, "signari.dev/engine/internal/tracing.") {
			return f.Function[strings.LastIndexByte(f.Function, '/')+1:]
		}
		if !more {
			return "other"
		}
	}
}
