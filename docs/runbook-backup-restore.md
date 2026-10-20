# Backup and restore

## The thing that makes this different from every other database backup

**The root key is not in the database, and a backup without it is worthless.**

Every signing key in `core.signing_keys`, every TOTP secret, and every migration
source's client secret is encrypted with `SIGNARI_ROOT_KEY`. The engine reads that
key from its environment and nowhere else — deliberately never from the database
it protects, because a backup containing the key that decrypts it is not
encryption, it is filing. Keep the value in a secret store you can reach when the
database is gone. (This said the key could live in a file or a KMS; the engine
reads neither.)

The corollary is the part people discover too late:

> Restoring the database without the matching root key gives you a running
> identity provider that cannot decrypt a single signing key. Every token you
> have ever issued becomes unverifiable, every enrolled authenticator stops
> working, and there is no recovery — the plaintext does not exist anywhere else.

So the root key and the database are **one backup artefact**, and they must be
restore-tested **together**. Backing them up separately, to systems with different
retention, is the most common way this goes wrong.

## What to back up

| Artefact | Where it lives | Lose it and… |
|---|---|---|
| `SIGNARI_ROOT_KEY` | the engine's environment | every signing key, TOTP secret and migration secret is permanently unreadable |
| PostgreSQL database | your database host | everything else |
| `SIGNARI_ADMIN_TOKEN` | env | the console cannot write; regenerate and update both sides |
| TLS certificate + key | disk / cert manager | reissue; no data loss |

Only the first two are irreplaceable.

## Backup

```sh
# Database, as a superuser or a role with BYPASSRLS -- NOT as signari_engine.
# Every core table forces row-level security on its own owner, so pg_dump run
# as the engine role stops at the first one ("query would be affected by
# row-level security policy") and leaves a partial file. This runbook used
# $SIGNARI_DSN here; checked on a copy, that dump was missing most of the data.
# --clean --if-exists makes the dump restorable over an existing database.
pg_dump --format=custom --clean --if-exists \
        --dbname="postgres://superuser@host/signari" \
        --file="signari-$(date -u +%Y%m%dT%H%M%SZ).dump"

# Root key. Stored ALONGSIDE the dump, with the same retention, or the pair
# drifts apart and the older half becomes useless without anyone noticing.
printf '%s' "$SIGNARI_ROOT_KEY" > "signari-rootkey-$(date -u +%Y%m%dT%H%M%SZ).b64"
chmod 0400 signari-rootkey-*.b64
```

Keep a **second copy of the root key somewhere a database compromise cannot
reach** — a password manager is fine, and it is the copy that saves you when the
backup host is what failed.

## Restore

```sh
# Roles FIRST. They are cluster-wide and not in the dump, and the restore
# assigns every object to them. Migration 0001 creates them; run it against a
# scratch database, since the restore brings its own record of 0001 and a
# bootstrap after it would find nothing to apply.
createdb signari_roles
SIGNARI_DSN="postgres://superuser@host/signari_roles" signari migrate bootstrap
dropdb signari_roles            # the roles stay: they belong to the cluster

createdb signari_restore
pg_restore --dbname="postgres://superuser@host/signari_restore" \
           --clean --if-exists signari-TIMESTAMP.dump
```

This page used to restore first and bootstrap after. Followed on a fresh cluster
that gave 296 errors and no `signari_engine` role, which the bootstrap did not
create because the restored ledger already recorded 0001. The order above restored
with none, and the checks below passed.

## Finalize, before the engine serves it

```sh
SIGNARI_DSN="postgres://signari_engine@host/signari_restore" \
  signari restore finalize -confirm signari_restore
```

The dump holds every session as it was when it was taken. A session ended after
that, by logout, by an administrator or by deactivating somebody, is live again
in the restored database, and nothing in it can tell that session from one
that was never ended. Finalize ends every one of them and every refresh family,
queues a back-channel logout and a CAEP session-revoked event for each
application that wants one, and records `restore.finalized`. Everybody signs in
again; that is the price of not bringing back a session somebody ended. Run it
before the engine serves the restored database, so no session created afterwards
is ended with them. `-confirm` must repeat the database's name: run against the
wrong database, it signs everybody out of production.

Until October 2026 this runbook stopped at the checks below, and the restored
sessions stayed live.

## Verifying a restore actually worked

A restore that "completed" proves nothing. These three commands prove it:

```sh
export SIGNARI_DSN="postgres://…/signari_restore"
export SIGNARI_ROOT_KEY="$(cat signari-rootkey-TIMESTAMP.b64)"

# 1. Schema is intact and at a version this binary may serve, and matches what
#    its ledger recorded. A restore renders the schema the way the original
#    did, which a test holds to (see upgrading.md); "schema drift" here means
#    the restore changed it.
signari verify

# 2. THE REAL TEST: the root key still decrypts the signing keys. This is the
#    check that catches a mismatched pair, and nothing else does.
signari keys list

# 3. The audit chain survived the round trip. A restore that silently corrupted
#    it would leave you unable to prove anything about the period it covers.
#    It exits non-zero and names the entry when it does not verify.
signari audit verify
```

Step 3 used to be `go test ./internal/audit/ -run TestLiveChainVerifies`, which
needs the source tree and the Go toolchain on the host doing the restore.
`signari audit verify` judges the chain as an export does: the whole of it, or
everything since a declared checkpoint, said so. `signari doctor` reports the same.

If step 2 fails with *"unwrapping subject key (is the root key correct?)"*, the
dump and the key file are from different eras. **Do not proceed** — find the
matching key. There is no way to recover the data without it.

## Restore-testing on a schedule

An untested backup is a hypothesis. Run the three checks above against the most
recent dump **monthly**, and record when it last succeeded:

```sh
signari verify && signari keys list >/dev/null && signari audit verify \
  && signari restore finalize -confirm signari_restore \
  && date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/signari/last-restore-test
```

The drill that proves finalize, run on a copy: sign in and keep the browser's
cookie, take the dump, sign out everywhere, restore the dump. The old cookie is
signed in again. Finalize, and it is not:

| Step | `/account` with the cookie |
|---|---|
| signed in | 200 |
| signed out everywhere, after the dump | 303 to `/login` |
| the dump restored | **200**: the ended session is back |
| `restore finalize` (10 sessions of 2 people ended) | 303 to `/login` |

Surfacing that timestamp where operators see it is the point. A backup system
whose last successful restore was fourteen months ago is not a backup system,
and the only way anyone finds out is by being told the date.

## What a restore does NOT bring back

- **Nothing is lost from sessions, which is the danger.** They are rows, so they
  come back as they were at the dump, and a browser holding one is signed in
  again; a session ended after the dump is live again. This said everyone signs
  in again, which is not what happens (a restore of a copy brought back its nine
  live sessions). `signari restore finalize`, above, ends them all.
- **Undelivered logout notices** past their retry budget. Check the console's
  logout-delivery screen after a restore.
- **Anything erased.** A crypto-shredded subject stays unreadable in every
  backup, including ones taken before the erasure. That is the feature working,
  not a restore failure — see `internal/keys/subject.go`.
