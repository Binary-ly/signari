# Backup and restore

## The thing that makes this different from every other database backup

**The root key is not in the database, and a backup without it is worthless.**

Every signing key in `core.signing_keys`, every TOTP secret, and every migration
source's client secret is encrypted with `SIGNARI_ROOT_KEY`. That key lives in the
environment, a file, or a KMS — deliberately never in the database it protects,
because a backup containing the key that decrypts it is not encryption, it is
filing.

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
| `SIGNARI_ROOT_KEY` | env / file / KMS | every signing key, TOTP secret and migration secret is permanently unreadable |
| PostgreSQL database | your database host | everything else |
| `SIGNARI_ADMIN_TOKEN` | env | the console cannot write; regenerate and update both sides |
| TLS certificate + key | disk / cert manager | reissue; no data loss |

Only the first two are irreplaceable.

## Backup

```sh
# Database. --clean --if-exists makes the dump restorable over an existing
# database; without it a restore into a non-empty target fails halfway.
pg_dump --format=custom --clean --if-exists \
        --dbname="$SIGNARI_DSN" --file="signari-$(date -u +%Y%m%dT%H%M%SZ).dump"

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
createdb signari_restore
pg_restore --dbname=signari_restore --clean --if-exists signari-TIMESTAMP.dump

# Roles are CLUSTER-wide and are NOT in the dump. On a fresh cluster, recreate
# them first -- migration 0001 does exactly this and is idempotent.
SIGNARI_DSN="postgres://superuser@host/signari_restore" signari migrate bootstrap
```

## Verifying a restore actually worked

A restore that "completed" proves nothing. These three commands prove it:

```sh
export SIGNARI_DSN="postgres://…/signari_restore"
export SIGNARI_ROOT_KEY="$(cat signari-rootkey-TIMESTAMP.b64)"

# 1. Schema is intact and at the version this binary expects.
signari verify

# 2. THE REAL TEST: the root key still decrypts the signing keys. This is the
#    check that catches a mismatched pair, and nothing else does.
signari keys list

# 3. The audit chain survived the round trip. A restore that silently corrupted
#    it would leave you unable to prove anything about the period it covers.
SIGNARI_TEST_DSN="$SIGNARI_DSN" go test ./internal/audit/ -run TestLiveChainVerifies -v
```

If step 2 fails with *"unwrapping subject key (is the root key correct?)"*, the
dump and the key file are from different eras. **Do not proceed** — find the
matching key. There is no way to recover the data without it.

## Restore-testing on a schedule

An untested backup is a hypothesis. Run the three checks above against the most
recent dump **monthly**, and record when it last succeeded:

```sh
signari verify && signari keys list >/dev/null \
  && date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/signari/last-restore-test
```

Surfacing that timestamp where operators see it is the point. A backup system
whose last successful restore was fourteen months ago is not a backup system,
and the only way anyone finds out is by being told the date.

## What a restore does NOT bring back

- **Sessions.** Everyone signs in again. Correct: a restored session is a session
  whose termination may have been rolled back with it.
- **Undelivered logout notices** past their retry budget. Check the console's
  logout-delivery screen after a restore.
- **Anything erased.** A crypto-shredded subject stays unreadable in every
  backup, including ones taken before the erasure. That is the feature working,
  not a restore failure — see `internal/keys/subject.go`.
