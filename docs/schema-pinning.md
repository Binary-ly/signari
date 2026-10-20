# Pinning a build to its schema

```sh
scripts/build-release.sh                 # builds ./engine/signari, pinned
docker build --build-arg \
    SIGNARI_SCHEMA_FINGERPRINT="$(scripts/schema-fingerprint.sh)" engine/
```

Signari gates its own startup twice: on the schema **version**, always, and on the
schema **fingerprint**. A pinned binary compares the fingerprint with the one it
was built with, and an unpinned one with the one the ledger recorded when the
latest migration was applied.

The version counter catches the ordinary case: a binary ahead of its database.
The fingerprint catches the case a counter cannot see, which the package comment
states plainly: *"two databases can both claim version 7 and disagree, if someone
hand-patched one of them."*

## What the fingerprint covers

Every column, constraint and unique index in `core`, and the tenant boundary
those tables rest on:

- whether each table has row-level security, and whether it is forced
- every policy, with its roles and expressions
- every view in `core_v1`, its options and its owner, since a view runs with its
  owner's privileges
- the owner of every table, view and sequence, and every grant on them, on
  their columns and on the two schemas
- every function, `core.is_engine()` among them, which every policy calls, and
  every trigger, with whether it is enabled
- the attributes of `signari_engine`, `signari_admin` and `signari_maintenance`,
  BYPASSRLS among them, and the roles each is a member of

Until October 2026 it covered only columns and constraints, so a policy dropped
by hand, FORCE ROW LEVEL SECURITY turned off, a view given to a role that
bypasses it, or a table granted to the console all left the digest as it was:
every hand change that opens one tenant's rows to another passed the check that
exists to notice hand changes. An index added for speed is left out on purpose,
because refusing to start over one would punish an operator for tuning.

Names are read with only `pg_catalog` on the search path, so they render
schema-qualified whatever the session's search path is. The migrations set
`search_path = core, public` for their session, and until October 2026 the
fingerprint the ledger recorded under it never matched a read made anywhere
else.

## An unpinned binary compares with the ledger

The ledger, `core.schema_migrations`, records the fingerprint after each
migration. From migration 0159 it also records the PostgreSQL version that
computed it. An unpinned binary refuses to start when the live schema is not
what the latest row recorded:

```
signari: schema drift: the live schema (972190dfe14c) is not what migration 159
         recorded (5ed071dc8c1b) -- it has been changed by hand since
```

That catches a hand change, and not one made together with a rewrite of the
ledger row, which the database being checked cannot be trusted to report. Only a
pinned binary refuses that. Until October 2026 an unpinned binary compared
nothing.

A row recorded under another PostgreSQL major version is not compared, because
the catalogue may render the same schema differently, and refusing to start
after a PostgreSQL upgrade would be wrong. The comparison resumes with the next
migration. Rows recorded before 0159 are never compared.
`signari migrate status` says which of these applies:

```
ledger           : matches what migration 159 recorded
```

`signari doctor` reports drift as critical, and says which check a binary
performs:

```
[warning ] schema   this binary has no pinned schema fingerprint, so it compares
                    the schema only with the ledger in the same database, and
                    accepts a hand-patched database whose ledger row was
                    rewritten along with it
```

## What the difference actually looks like

One database at version 101, with one column added by hand — same version,
different shape:

```
$ signari-pinned serve
signari: schema fingerprint mismatch: live 3bee84def117, expected c42946694e7a
         -- the database has drifted from what this binary was built against

$ signari-unpinned serve
(serves)
```

That was before the ledger comparison. An unpinned binary now refuses with
`schema drift` instead, unless the ledger row was rewritten too.

## Why the build needs a PostgreSQL

The fingerprint is read from a live schema, because that is what the engine
compares against at boot. Deriving it by parsing the migration SQL instead would
mean two implementations of "what this schema is", and the one that mattered would
be the one nobody tested.

`scripts/schema-fingerprint.sh` therefore migrates into a throwaway database and
reads the digest back. It uses `SIGNARI_FINGERPRINT_DSN` if you set one, and
otherwise starts and removes a `postgres:17-alpine` container.

It cannot run inside `docker build` — there is no database there — which is why
the Dockerfile takes the value as a build argument rather than computing it.

## Why `migrate fingerprint` exists separately from `migrate status`

`migrate status` prints the version, the pending list and the fingerprint in a
layout meant for a person. A build script capturing the digest from that would be
one cosmetic change away from pinning a binary to the string `pending` — and the
failure would be a fingerprint mismatch at every boot, which reads as schema drift
rather than as a broken build.

`migrate fingerprint` prints one value and nothing else. `$(signari migrate
fingerprint)` is the whole contract.
