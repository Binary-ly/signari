# Backup and restore

## Introduction

Most database backups are one file. A Signari backup is two: the PostgreSQL
database, and the "root key", the secret that encrypts the sensitive values inside
it. Neither is any use without the other, so you back them up together and test
them together.

This page shows how to take that backup, by hand or with the Helm chart, and how
to restore it. It also shows how to recover the database as it was at a chosen
moment. After a restore, `signari restore finalize` ends the sessions the backup
brought back, and three commands prove that the restore worked.

## The thing that makes this different from every other database backup

**The root key is not in the database, and a backup without it is worthless.**

The root key, `SIGNARI_ROOT_KEY`, encrypts every signing key in
`core.signing_keys`, every time-based one-time password ([TOTP](glossary.md#totp))
secret, and every migration source's client secret. The engine reads that key
from its environment, or from the file `SIGNARI_ROOT_KEY_FILE` names, which only
its owner may read. It reads the key from nowhere else.

It deliberately never reads the key from the database it protects. A backup that
contains the key that decrypts it is not encryption; it is filing. Keep the value
in a secret store you can reach when the database is gone.

A root key held in a key management service (KMS) is not built yet. This page
once said that the engine reads neither a file nor a KMS. It reads a file.

What follows from this is the part people discover too late:

> [!WARNING]
> Restoring the database without the matching root key gives you a running
> Signari that cannot decrypt a single signing key. Every token you have ever
> issued becomes unverifiable, every enrolled authenticator stops working, and
> there is no recovery: the plaintext does not exist anywhere else.

So the root key and the database are **one backup artefact**, and they must be
restore-tested **together**. The most common way this goes wrong is to back them
up separately, to systems with different retention.

## What to back up

A deployment has five things to back up, from the root key down to its Transport
Layer Security ([TLS](glossary.md#tls)) certificate:

| Artefact | Where it lives | Lose it and… |
|---|---|---|
| `SIGNARI_ROOT_KEY` | the engine's environment | every signing key, TOTP secret and migration secret is permanently unreadable |
| `SIGNARI_ROOT_KEY_REF`, where set | the engine's environment | the engine refuses every sealed value until it is given the same label again: each one names the label it was sealed under |
| PostgreSQL database | your database host | everything else |
| `SIGNARI_ADMIN_TOKEN` | env | the console cannot write; regenerate and update both sides |
| TLS certificate + key | disk / cert manager | reissue; no data loss |

Only the first two are irreplaceable.

## Backup

Take the dump as a PostgreSQL superuser or a role with `BYPASSRLS`, not as
`signari_engine`. Every core table applies [row-level
security](how-signari-works.md#how-the-database-keeps-organisations-apart) even to
its own owner. A dump taken as the engine's role stops at the first table, and
leaves a partial file. Then save the root key, and its label if the deployment
sets one, beside the dump:

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
# And the key's label, if the deployment sets one: a restore given the key under
# another label (or none) refuses every signing key it sealed.
[ -n "${SIGNARI_ROOT_KEY_REF:-}" ] &&
  printf '%s' "$SIGNARI_ROOT_KEY_REF" > "signari-rootkey-$(date -u +%Y%m%dT%H%M%SZ).ref"
```

Keep a **second copy of the root key somewhere a database compromise cannot
reach**. A password manager is fine. It is the copy that saves you when the
backup host is what failed.

### On Kubernetes, with the chart

The chart runs the two commands above on a schedule:

```sh
helm upgrade "$RELEASE" deploy/helm/signari --reuse-values \
  --set backup.enabled=true \
  --set backup.dsnSecretKey=BOOTSTRAP_DSN \
  --set backup.persistence.existingClaim=signari-backups \
  --set backup.schedule="0 2 * * *" --set backup.retentionDays=14
```

`dsnSecretKey` names a key in the chart's Secret that holds a superuser or
`BYPASSRLS` data source name ([DSN](glossary.md#dsn)), the database's connection
string. The chart refuses to render without one, because a dump as
`signari_engine` stops at the first table.

Each run writes `signari-<UTC time>.dump`, which is written as `.partial` and
renamed once whole. Beside it, the run writes `signari-rootkey-<the same time>.b64`.
Both are owner-only. When the Secret sets `SIGNARI_ROOT_KEY_REF`, the run also
writes `signari-rootkey-<the same time>.ref`, holding the key's label. Files older
than `retentionDays` are deleted, the set together.

The volume is a PersistentVolumeClaim you make, named by
`backup.persistence.existingClaim`, and the chart refuses to render without one. A
claim the chart made would hold `helm install --wait` until it bound. A storage
class that binds on first use, as kind's and most clouds' do, binds it only when
the first backup runs. The first continuous integration (CI) run of this recipe
hung for exactly that reason.

After that, three things are yours to decide. They are where the claim is copied
to, how often the CronJob runs, and how long you keep what it writes. The defaults are a
nightly run and two weeks, not a recommendation.

To restore from it, take the newest pair off the volume and follow the next
section. Give the key file mode `0400` before the engine reads it. A volume with
`fsGroup` can add group bits to the file, and the engine refuses a root key file
anybody else can read.

CI runs this on kind for every change to the chart or the engine
(`.github/workflows/helm.yml`). The CronJob runs once, and its newest dump is
restored into a fresh database. The engine is given the key and the label that
were written beside the dump. It then passes `verify`, `keys list` and
`audit verify`, then `restore finalize`. Its first run restored the key without
its label, and the engine refused every signing key: *"key … was wrapped with
root key "k8s" but "" is configured"*.

## Restore

Create Signari's database roles first, then restore the dump into a new
database. The roles belong to the PostgreSQL cluster, so they are not in the dump:

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

This page used to restore first and bootstrap after. Followed on a fresh cluster,
that order gave 296 errors and no `signari_engine` role. The bootstrap did not
create the role, because the restored ledger already recorded 0001. The order
above restored with none, and the checks below passed.

## Point-in-time recovery

A dump restores the database as it was when the dump ran. "Point-in-time
recovery" restores it as it was at a moment you choose, for instance the moment
before a bad change. For that, keep a base backup and every write-ahead log (WAL)
segment written since. PostgreSQL then replays the WAL up to that moment.

Turn on WAL archiving once, take base backups on a schedule, and recover from them
like this:

```sh
# Once, on the primary (postgresql.conf), then restart it:
#   wal_level = replica
#   archive_mode = on
#   archive_command = 'test ! -f /archive/%f && cp %p /archive/%f'

# A base backup, as a superuser, on a schedule:
pg_basebackup --dbname="postgres://superuser@host/postgres" -D /backups/base-TIMESTAMP -Fp -X none -c fast

# To recover: stop PostgreSQL, put the base backup in place of the data
# directory, and add to its postgresql.conf:
#   restore_command = 'cp /archive/%f %p'
#   recovery_target_time = '2026-10-20 18:37:54+02'
#   recovery_target_action = 'promote'
touch "$PGDATA/recovery.signal"
pg_ctl -D "$PGDATA" start      # replays the WAL to the target, then promotes
```

Then run `migrate up` if the backup is older than the binary, followed by the
checks and `restore finalize` below. Recovery leaves every session as it was at
the target, including the ones ended since, exactly as a dump does.

The archive must hold a commit at or after the target. PostgreSQL stops when it
reaches the first commit past the target. If the WAL runs out first, it shuts down
with `FATAL: recovery ended before configured recovery target was reached`.

On a quiet database, the segment that holds the last commits may not be archived
yet. Run `SELECT pg_switch_wal()` before relying on a recent target.

The root key is unaffected. It is not in the database, and the recovered rows are
sealed under whichever key was in use at the target.

This was drilled on a throwaway PostgreSQL 17 cluster holding a copy of a working
deployment. The copy was restored by the steps above with no errors, and a base
backup was taken. One person was created, the target noted, and a second person
created. Recovery stopped "before commit of transaction 2134" and brought back the
first person only. `verify` said `schema ok`, `audit verify` verified 2,971
entries, and `restore finalize` ended 9 sessions of 1 person.

## Finalize, before the engine serves it

Run `signari restore finalize` against the restored database, as `signari_engine`,
and give `-confirm` the database's name:

```sh
SIGNARI_DSN="postgres://signari_engine@host/signari_restore" \
  signari restore finalize -confirm signari_restore
```

The dump holds every session as it was when it was taken. A session ended after
that, by signing out, by an administrator or by deactivating somebody, is live again in
the restored database. Nothing in it can tell that session from one that was never
ended.

`restore finalize` ends every one of those sessions, and every "refresh family":
the line of refresh tokens that one application holds for one session. It queues
a Back-Channel Logout notice and a Continuous Access Evaluation Profile
([CAEP](glossary.md#caep)) session-revoked event for each application that wants
one, and records `restore.finalized`.

Everybody signs in again. That is the price of not bringing back a session
somebody ended.

Run it before the engine serves the restored database, so that no session created
afterwards is ended with them. `-confirm` must repeat the database's name: run
against the wrong database, it signs everybody out of production.

Until October 2026 this runbook stopped at the checks below, and the restored
sessions stayed live.

## Verifying a restore actually worked

A restore that "completed" proves nothing. These three commands prove it, run
with the restored database and the root key from the same backup:

```sh
export SIGNARI_DSN="postgres://…/signari_restore"
export SIGNARI_ROOT_KEY="$(cat signari-rootkey-TIMESTAMP.b64)"
# Only if the backup has one: the label the key sealed everything under.
[ -f signari-rootkey-TIMESTAMP.ref ] && export SIGNARI_ROOT_KEY_REF="$(cat signari-rootkey-TIMESTAMP.ref)"

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

> [!WARNING]
> If step 2 fails with *"unwrapping subject key (is the root key correct?)"*, the
> dump and the key file are from different eras. **Do not proceed**: find the
> matching key. There is no way to recover the data without it.

`signari audit verify` judges the chain as an export does: the whole of it, or
everything since a declared checkpoint, and it says which. Step 3 used to be
`go test ./internal/audit/ -run TestLiveChainVerifies`, which needs the source
tree and the Go toolchain on the host doing the restore.

`signari doctor` reports the same, with every other check, and a script can read
it:

```sh
signari doctor -json | jq -e '.critical == 0'   # exits 1 if anything is critical
signari doctor -json | jq -r '.findings[] | "\(.severity) \(.area): \(.summary)"'
```

## Restore-testing on a schedule

An untested backup is a hypothesis. Run the three checks above against the most
recent dump **monthly**, and record when it last succeeded:

```sh
signari verify && signari keys list >/dev/null && signari audit verify \
  && signari restore finalize -confirm signari_restore \
  && date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/signari/last-restore-test
```

Surfacing that timestamp where administrators see it is the point. A backup
system whose last successful restore was fourteen months ago is not a backup
system. The only way anyone finds out is by being told the date.

A drill on a copy proves what `restore finalize` does. Sign in and keep the
browser's cookie, take the dump, sign out everywhere, then restore the dump. The
old cookie is signed in again. Run `restore finalize`, and it is not:

| Step | `/account` with the cookie |
|---|---|
| signed in | 200 |
| signed out everywhere, after the dump | 303 to `/login` |
| the dump restored | **200**: the ended session is back |
| `restore finalize` (10 sessions of 2 people ended) | 303 to `/login` |

## What a restore does not bring back

**Sessions are not on this list, and that is the danger.** Sessions are rows, so
they come back as they were at the dump. A browser holding one is signed in again.
A session ended after the dump is live again. `signari restore finalize`, above,
ends them all. This page once said that everyone signs in again, which is not what
happens: a restore of a copy brought back its nine live sessions.

A restore does not bring back these:

- **Undelivered sign-out notices** past their retry budget. Check the console's
  screen of sign-out deliveries after a restore.
- **A person erased before the backup was taken.** The [erasure](erasure.md)
  destroyed their key and removed their account first, so the backup holds
  neither. That is the feature working, not a restore failure.

A backup taken *before* an erasure is different. It still holds the person's
account, and their key, wrapped under the root key that opens it. Restoring it
brings them back, so erase them again with `signari erase subject` after the
restore.
