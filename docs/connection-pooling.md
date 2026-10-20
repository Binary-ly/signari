# Connection pooling

```sh
# serve, behind a transaction-mode pooler such as PgBouncer:
SIGNARI_DSN="postgres://signari_engine@pgbouncer:6432/signari?default_query_exec_mode=cache_describe"

# migrate and every other command: straight to PostgreSQL
SIGNARI_DSN="postgres://signari_engine@postgres:5432/signari" signari migrate up
```

## What a node opens

Two pools per engine node:

| Pool | Holds | Size |
|---|---|---|
| Requests | every request handler | `SIGNARI_DB_MAX_CONNS`, default the larger of 4 and the number of CPUs |
| Workers | the outbox, the janitor, the audit-sink pump, the key refresher | `SIGNARI_DB_WORKER_MAX_CONNS`, default 3, none kept idle |

A node opens up to the sum. Multiply by the number of nodes, and keep the
result below the server's `max_connections`, less its reserved connections,
when nothing sits in between.

The workers used to share the request pool. A burst of sign-ins then left the
outbox waiting for a connection to deliver the logout notices that end sessions
at other applications, and a long janitor pass held connections that requests
were waiting for. Since October 2026 the workers have their own pool, so neither
can starve the other.

## Behind a transaction-mode pooler

`serve` holds no state on a connection between transactions. The organisation
a request acts for is set per transaction (`set_config(…, true)`), and its
advisory locks are transaction-scoped. So it runs behind a pooler that hands
each transaction a different server connection, with one setting:
**`default_query_exec_mode=cache_describe`** in `SIGNARI_DSN`.

pgx's default prepares every query as a named statement and reuses it on the
same connection (`QueryExecModeCacheStatement`, pgx v5.10.0 `conn.go:537-550`).
Behind a transaction pooler the next transaction may reach a server connection
where that statement was never prepared. The four other modes:

| Mode | Behind a transaction pooler | The engine in it |
|---|---|---|
| `cache_describe` | **safe**: it asks for a query's parameter types once, then runs each query in one round trip that parses, binds and executes it (`conn.go:551-562`) | the whole suite passes |
| `describe_exec` | not safe: it prepares an unnamed statement and binds to it in a second round trip, which a pooler may send to another connection (`conn.go:565-569`; pgx says so at `conn.go:660-664`) | the whole suite passes |
| `exec` | safe | **fails**: JSON the engine writes as bytes is refused as invalid JSON |
| `simple_protocol` | safe | **fails**: the same, and an empty identifier sent for a uuid is refused |

`exec` and `simple_protocol` are what pgx's own comment suggests for PgBouncer
(`conn.go:38-41`). `signari doctor` reports either as critical.

`cache_describe` remembers each query's types. pgx says a query whose result
changes shape after a schema change may fail once (`conn.go:654-657`), and it
forgets a cached query on any error (`conn.go:520-529`), so the next run
succeeds. No engine query selects `*`, and a migration declared compatible with
the release before only adds (see [upgrading.md](upgrading.md)), so an existing
query's result does not change shape under it.

## What must not go through one

**`signari migrate up`** and `migrate all` hold a session-level advisory lock while they run, so
two runs take turns, and build some indexes concurrently outside a
transaction. Through a transaction pooler the lock would be taken on one server
connection and released on another.

**Every other command** marks its connection as the operator's
(`signari.cli_write`) for the whole session, so that its writes move the
configuration version and are audited once. Through a transaction pooler that
mark would stay on a server connection that `serve` later receives, and request
traffic would be recorded as operator edits. Connect the CLI to PostgreSQL
directly, or through a pooler in session mode.

## What has not been measured

The suite was run with each mode against PostgreSQL directly, and that is what
the table reports. No engine has yet been run behind a real PgBouncer here.
