# Pinning a build to its schema

```sh
scripts/build-release.sh                 # builds ./engine/signari, pinned
docker build --build-arg \
    SIGNARI_SCHEMA_FINGERPRINT="$(scripts/schema-fingerprint.sh)" engine/
```

Signari gates its own startup twice: on the schema **version**, always, and on the
schema **fingerprint** — a digest of every column and every constraint in `core` —
when the binary was built with one.

The version counter catches the ordinary case: a binary ahead of its database.
The fingerprint catches the case a counter cannot see, which the package comment
states plainly: *"two databases can both claim version 7 and disagree, if someone
hand-patched one of them."*

## An unpinned binary does not perform the second check

`migrate.Verify` returns before it ever reads the live schema when
`ExpectedFingerprint` is empty. The check exists, is tested, and does nothing.

Nothing about that is visible from outside — the engine starts normally, no
endpoint reports it, and the only symptom is that a drifted database is accepted,
which is exactly the situation the fingerprint exists to catch and the one where
nobody is watching.

So `signari doctor` now says which of the two checks a binary performs:

```
[warning ] schema   this binary has no pinned schema fingerprint, so it accepts
                    any database at the right version, including one that has
                    been hand-patched
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
