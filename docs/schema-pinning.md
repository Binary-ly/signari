# Pinning a build to its schema

## Introduction

Someone with access to the database can change it by hand: drop a policy, add a
column, grant a table to another role. The schema's version number stays the
same. So a check on the version alone cannot see the change, and a hand change
can open one organisation's rows to another.

Signari gates its own startup twice: on the schema **version**, always, and on
the schema **fingerprint**, a digest of the schema it relies on. A release can be
"pinned": built with the fingerprint of the schema it expects, so that it refuses
to start on any other.

You build a pinned release with `scripts/build-release.sh`. `signari version`
shows what a binary is pinned to.

## Building a pinned release

Build a pinned binary, or a pinned image and a tag as well, and check what a
binary is pinned to:

```sh
scripts/build-release.sh                                 # ./engine/signari, pinned
scripts/build-release.sh -image signari:1.2.0 -tag v1.2.0  # and the image, then the tag
signari version                                          # what a binary is pinned to
```

`build-release.sh` reads the pin back from `signari version` in the binary, and in
the image when it builds one. It stops if either does not report it.

With `-tag`, it refuses a working tree with uncommitted changes, since the tag
would name a commit the release was not built from. It records the fingerprint in
the tag's message. It does not push.

Until October 2026 it built only the binary. Nothing built a pinned image, and
nothing refused to tag an unpinned one.

`signari version` shows the pin on its last line:

```
$ signari version
version  v1.2.0
commit   59b4d89cd35531244004f398333b35fa9e699b0e
go       go1.26.9
fips140  disabled, module none
schema   159
pinned   5ed071dc8c1beaf5f9d11a3571ec652820be36d786ca3b48124156982f5987d5
```

## Two checks at startup

A pinned binary compares the fingerprint with the one it was built with. An
unpinned one compares it with the one the ledger recorded when the latest
migration was applied.

The version counter catches the ordinary case: a binary ahead of its database. The
fingerprint catches the case a counter cannot see, which the package comment
states plainly: *"two databases can both claim version 7 and disagree, if someone
hand-patched one of them."*

## What the fingerprint covers

It covers every column, constraint and unique index in `core`, and the
organisation boundary those tables rest on:

- Whether each table has row-level security, and whether it is forced.
- Every policy, with its roles and expressions.
- Every view in `core_v1`, its options and its owner, since a view runs with its
  owner's privileges.
- The owner of every table, view and sequence, and every grant on them, on their
  columns and on the two schemas.
- Every function, `core.is_engine()` among them, which every policy calls, and
  every trigger, with whether it is enabled.
- The attributes of `signari_engine`, `signari_admin` and `signari_maintenance`,
  BYPASSRLS among them, and the roles each is a member of.

Until October 2026 it covered only columns and constraints. So a policy dropped
by hand left the digest as it was. So did FORCE ROW LEVEL SECURITY turned off, a
view given to a role that bypasses it, or a table granted to the console. Every
hand change that opens one organisation's rows to another passed the check that
exists to notice hand changes.

An index added for speed is left out on purpose. Refusing to start over one would
punish an administrator for tuning.

Names are read with only `pg_catalog` on the search path. So they render
schema-qualified, whatever the session's search path is. The migrations set
`search_path = core, public` for their session. Until October 2026, the
fingerprint the ledger recorded under it never matched a read made anywhere else.

A table owner's own `MAINTAIN` is left out. PostgreSQL 17 added the privilege and
lists it among what an owner holds, and 16 has none. So until November 2026 the
same schema fingerprinted differently on the two, and a release pinned on 17 would
have refused a 16 database. `MAINTAIN` granted to anybody else still counts, since
it would let them lock and vacuum the engine's tables.

15 renders view definitions differently again, and is below the supported range
([which PostgreSQL](upgrading.md#which-postgresql)). The change is fingerprint
scheme 3. A ledger row computed by scheme 2 is not compared until the next
migration records one, as for an upgrade of PostgreSQL.

## An unpinned binary compares with the ledger

The ledger, `core.schema_migrations`, records the fingerprint after each
migration. From migration 0159 it also records the PostgreSQL version that
computed it. An unpinned binary refuses to start when the live schema is not what
the latest row recorded:

```
signari: schema drift: the live schema (972190dfe14c) is not what migration 159
         recorded (5ed071dc8c1b) -- it has been changed by hand since
```

That catches a hand change. It does not catch one made together with a rewrite
of the ledger row, which the database being checked cannot be trusted to report.
Only a pinned binary refuses that. Until October 2026 an unpinned binary compared
nothing.

A row recorded under another PostgreSQL major version is not compared. The
catalogue may render the same schema differently, and refusing to start after a
PostgreSQL upgrade would be wrong. The comparison resumes with the next
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

Take one database at version 101, with one column added by hand. It has the same
version, and a different shape:

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
mean two implementations of "what this schema is". The one that mattered would be
the one nobody tested.

`scripts/schema-fingerprint.sh` therefore migrates into a throwaway database, and
reads the digest back. It uses `SIGNARI_FINGERPRINT_DSN` if you set one. Otherwise
it starts and removes a `postgres:17-alpine` container.

It cannot run inside `docker build`, because there is no database there. That is
why the Dockerfile takes the value as a build argument, rather than computing it.

## Why `migrate fingerprint` exists separately from `migrate status`

`migrate status` prints the version, the pending list and the fingerprint in a
layout meant for a person. A build script capturing the digest from that would be
one cosmetic change away from pinning a binary to the string `pending`. The
failure would be a fingerprint mismatch at every boot, which reads as schema drift
rather than as a broken build.

`migrate fingerprint` prints one value and nothing else. `$(signari migrate
fingerprint)` is the whole contract.
