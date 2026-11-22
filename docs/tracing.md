# Tracing

The engine can send OpenTelemetry spans to a collector over OTLP/HTTP: one for
each request, one for each query that request runs, and one for each call it
makes to another server. It is off unless a collector is named, and when it is
off nothing is installed: no middleware, and no span is started.

## Turning it on

| | |
|---|---|
| `SIGNARI_OTLP_TRACES_ENDPOINT` | The collector's OTLP/HTTP traces URL, such as `http://localhost:4318/v1/traces`. The whole URL: no path is added to it |
| `SIGNARI_OTLP_HEADERS` | Headers sent with every export, as `name=value` pairs separated by commas, usually a collector's API key. Refused with a plain `http://` collector anywhere but loopback |
| `SIGNARI_TRACES_SAMPLE_RATIO` | The share of requests traced, from `0` to `1`, default `1` |

A malformed value stops the engine from starting, and so does either of the last
two without an endpoint. An `https://` collector is verified against the system
roots plus `SIGNARI_CA_BUNDLE`. The export does not go through the guard that keeps
outbound calls off private addresses, because a collector is usually on loopback
or the cluster network.

Any collector that accepts OTLP over HTTP works. To look at traces locally:

```sh
docker run -d --name jaeger -e COLLECTOR_OTLP_ENABLED=true \
  -p 127.0.0.1:4318:4318 -p 127.0.0.1:16686:16686 jaegertracing/all-in-one:1.62.0
SIGNARI_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces signari serve
# then http://127.0.0.1:16686, service "signari"
```

## What is traced

| Span | Kind | Named | Covers |
|---|---|---|---|
| A request to the public listener or the admin API | server | `POST /oauth2/token`: the method and the route | from arrival to the last byte of the response, every middleware included |
| A query run while a traced request is being served, or a batch | client | `SELECT store.PeekCode`: the statement's first keyword and the Go function that ran it | the query, as the pool ran it |
| A call to another server | client | `POST`: the method | until the response headers arrive |

The route is the pattern Go's `http.ServeMux` matched, from `http.Request.Pattern`,
with its method taken off: `/admin/users/{userID}`, never the path that was asked
for. A request that matched no route has no route, and its span is named by its
method alone, because the path of a 404 is whatever a scanner probed for.

Calls to other servers are traced for every client `internal/safedial` builds,
which is every call to an address somebody else chose: extension providers,
webhooks, logout and security-event delivery, audit streaming, SCIM, CAPTCHA and
Duo verification, the FIDO metadata service, the SMS gateway, federation and
metadata documents, and the Google directory. They are traced too for the
breached-password check, device posture, and the Entra directory and provisioning. A call made while serving a request is
a child of that request's span. One made by a background worker, such as the
outbox delivering a logout notice, is a root of its own.

The background workers' queries are not traced. They have no request to belong
to, and a span per janitor query would bury the requests. Neither are LDAP and
RADIUS, which are not HTTP.

## The attributes, all of them

Keys are the OpenTelemetry semantic conventions' (`go.opentelemetry.io/otel/semconv/v1.43.0`).

| Key | On | Value |
|---|---|---|
| `http.request.method` | requests and calls | the method, or `_OTHER` for one that is not GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH or QUERY |
| `http.route` | requests that matched a route | the pattern, as above |
| `http.response.status_code` | requests, and calls that were answered | the status code |
| `db.system.name` | queries | `postgresql` |
| `db.operation.name` | queries | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `WITH`, `VALUES`, `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`, `SET`, `LOCK`, `COPY`, `CALL`, `DO`, `NOTIFY`, `LISTEN`, `UNLISTEN`, `TRUNCATE`, `ANALYZE`, `EXPLAIN`, `BATCH`, or `OTHER` |
| `code.function.name` | queries | the function that ran it, such as `store.ConsumeCode` |
| `db.response.status_code` | queries that failed with a PostgreSQL error | its SQLSTATE |
| `error.type` | anything that failed | a query's SQLSTATE, or `timeout`, `canceled` or `_OTHER` |

A request is marked as an error when it is answered 5xx, a call when it is
answered 4xx or 5xx or not at all, and a query when it fails. No status carries a
message.

## What no span carries

A span goes where a metric goes: into a store this system cannot reach, kept for
as long as somebody else decides, outside the boundary that
`subjects/{id}/erase` works on. So no span carries:

- a URL, a path or a query string;
- a client id, a user id, an organisation id, an email address or a session;
- an address, the caller's or the destination's;
- SQL text (the function that ran it is named instead) or a query's arguments;
- an error message (a PostgreSQL `DETAIL` quotes the row that clashed);
- an event: the SDK's panic event, which carries the panic's message and a stack
  trace, is turned off, and the exporter writes any event as dropped.

This is held by structure and by test, not by care.
`TestOnlyTracingImportsOpenTelemetry` fails if any package but `internal/tracing`
imports OpenTelemetry, so a handler cannot set an attribute of its own.
`TestTheSignInIsTracedWithoutAnIdentifier` signs a person in to an application,
redeems the code, and fails if any span names the person, the client, the code,
a token, the redirect URI or the address, if any value looks like an identifier,
or if any key is one not in the table above.

## Trace context

A caller's `traceparent` is recorded as a link on a new root span, never taken as
its parent. Taken as the parent, it would let anybody choose this server's trace
ids and its sampling decision, and file its spans under a trace of their own. The
caller's `tracestate` is dropped, because it is the caller's free text.

No `traceparent` is sent on a call to another server. The destinations are relying
parties, providers and subscribers, and a trace id handed to them would tie their
logs to this one.

## Sampling and delivery

`SIGNARI_TRACES_SAMPLE_RATIO` decides per request, and a request's queries and calls
go with it. Spans are sent in batches, every five seconds or every 512 spans, and
up to 2,048 wait in memory; past that, new spans are dropped. A batch the collector
does not take is dropped, not retried: a trace is a diagnostic, not a record. The
first failure is logged and so is the recovery, and the failures in between are
not. At shutdown, what is queued is sent, for up to five seconds.

The SDK reads `OTEL_BSP_*` and `OTEL_TRACES_SAMPLER` itself, and the engine sets
every one of those settings explicitly, so they have no effect. The settings on this
page are the ones in force.

The exporter is written in `internal/tracing/otlp.go` rather than taken from the
OpenTelemetry exporter module, which would bring grpc into the dependency graph to
send one message over HTTP. See [dependencies](dependencies.md).

## Seen in a collector

A sign-in and code redemption against the real binary, as Jaeger 1.62.0 assembled
it on 2026-11-03, shortened. The authorization request carried a `traceparent`.
Nothing from the request, the person or the client appears anywhere in what the
collector holds.

```
GET /oauth2/authorize   [server] 200  links=[0af7651916cd43dd8448eb211c80319c/b7ad6b7169203331]
  SELECT clients.Lookup
  SELECT store.LoadBrandByIssuer
  SELECT store.LoadSignupRule
  SELECT store.OrgWords
  ...                                      (20 spans)
POST /login             [server] 303
  SELECT store.CountRates
  SELECT httpapi.(*Server).lookupCredentials
  WITH   store.ReserveLoginAttempt
  BEGIN  httpapi.(*Server).handleLoginPost
  INSERT httpapi.(*Server).completeSignIn
  SELECT audit.write
  COMMIT httpapi.(*Server).completeSignIn
  ...                                      (22 spans)
GET /oauth2/authorize   [server] 303
  WITH   store.ResolveBrowserSession
  INSERT store.IssueCode
  COMMIT httpapi.(*Server).issueCodeAndRedirect
POST /oauth2/token      [server] 200
  SELECT store.PeekCode
  UPDATE store.ConsumeCode
  SELECT httpapi.(*Server).mintSet
  COMMIT httpapi.(*Server).handleToken
```
