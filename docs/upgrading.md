# Upgrading and rolling back

```sh
signari migrate status        # where the database is, and the oldest binary that may serve it
signari migrate up            # the upgrade: as signari_engine, before the new binary serves
signari verify                # whether this binary may serve this database
```

There are no down migrations. A migration that dropped a column cannot give the
data back, and a down script that pretends to would be untested on the one day
it runs. Two things take their place: a release before a migration can be
allowed to keep running against it, and everything else is rolled back by
restoring the backup taken before the upgrade.

What each schema version changed, and whether the release before may keep
serving it, is in [schema-versions.md](schema-versions.md). Read the versions
between the one `migrate status` reports and the one the new binary expects.

## The order

1. Back up: [runbook-backup-restore.md](runbook-backup-restore.md). That backup
   is the rollback for any migration that is not compatible.
2. Run `signari migrate up` with the **new** binary, once. Two at once take
   turns.
3. Replace the engine nodes with the new binary.

Nodes of the previous release keep serving during step 3: the schema is
checked when a node starts, not while it runs. A previous-release node that
restarts during the roll, because it crashed or was rescheduled, checks again.

## What the previous release does against the new schema

A binary serves a database **ahead** of it when every migration since its own
version was declared compatible with the version before. It refuses every other
database that is not at its own version:

```
$ signari-161 migrate status
database version : 162
binary expects   : 161
ledger           : matches what migration 162 recorded
oldest binary    : 161 -- the migrations since are compatible with it, so it may serve this database

$ signari-161 verify
schema ok
```

```
$ signari-161 verify
signari: the database is at 163, ahead of this binary (161), and migration
         0163_drill_probe_dropped is not compatible with an earlier binary --
         deploy a binary built for 163, or restore the backup taken before the
         upgrade (docs/upgrading.md)
```

Until October 2026 every binary refused every database but its own version, so a
previous-release node that restarted during a rolling upgrade crash-looped, and
the only way back from any upgrade was a restore.

The declaration is the line `-- signari:compatible-with-previous` in a
migration's leading comment. The ledger records it when the migration is
applied, because the previous binary has never seen the file. `migrate status`
prints the oldest binary that may serve the database.

## Rolling back

- **`migrate status` names a binary as old as the one you are going back to:**
  deploy it. Its `migrate up` finds nothing to apply and says the database is
  ahead, and it serves.
- **It does not:** restore the backup from step 1, by the
  [runbook](runbook-backup-restore.md), then deploy the previous binary.

A restored database is checked like any other. It matches its own ledger: a
test dumps and restores a database migrated from empty and fails on any line of
the fingerprint the round trip changes. The first run of this drill found one,
a CHECK written with `BETWEEN`, which PostgreSQL renders differently once it has
parsed its own rendering again. A database restored by the runbook was refused
at startup as hand-patched, until migration 0161 rewrote it.

## The drill

Run against a copy of a real database. Each step's result is what it printed.

| Step | Result |
|---|---|
| The previous release (159) restarts against 161 | refused: `database is at 161, this binary expects 159`. That release predates the declaration |
| 161 migrates its database and serves | discovery 200 |
| 162 applies a compatible migration; 161 restarts against it | `schema ok`, `oldest binary : 161`, discovery 200 |
| Roll back to 161: its migrate job, then serve | `nothing to apply`, `the database is at 162, ahead of this binary (161)`, exit 0; discovery 200 |
| Back up at 162; 163 applies a migration that is not compatible | 161 and 162 both refused, naming `0163_drill_probe_dropped` |
| Restore the 162 backup by the runbook; 161 against it | 0 restore errors, `schema ok`, `keys list` opens the signing keys, discovery 200 |

## Writing a compatible migration

Declare it only when the previous release keeps working against the result.
The file is checked when it is loaded, and the binary refuses to start with a
declaration on a migration that does anything but add:

| Allowed | Refused, because the previous release relies on it |
|---|---|
| `CREATE TABLE`, and on that table any `ALTER`, policy, trigger, unique index or row | a constraint, policy, trigger or unique index on a table it already has |
| `ALTER TABLE … ADD COLUMN`, nullable or with a default, one per statement | `DROP`, `RENAME`, `ALTER COLUMN`, a `NOT NULL` column with no default |
| `CREATE INDEX` that is not unique | `DROP INDEX` |
| `CREATE FUNCTION`, `CREATE VIEW` | `CREATE OR REPLACE` either: the previous release calls or reads the old one |
| `COMMENT ON`, `GRANT`, `SET` | `REVOKE`, `INSERT`, `UPDATE` or `DELETE` on a table it reads, `DO` blocks |

The check reads the SQL and does not run it, so it is a floor. A new column the
previous release would read wrongly, or a new row it would misread, is the
author's to rule out.

## Which PostgreSQL

| | |
|---|---|
| Runs on | 17 and later. 17 is the version this release's suites ran against, and an older major is refused rather than assumed to work: `signari verify`, `serve` and `migrate` refuse it before applying anything |
| Tested on | 17. A later major runs, and `signari doctor` warns that it was not tested here |
| Bootstrap | needs a role that may create roles, one of them with `BYPASSRLS` (`signari_maintenance`), and grant schemas to them: a superuser on your own server. Whether a managed service's administrator role may do this is the service's to say, and has not been tried here |

Until October 2026 nothing declared a range, and nothing checked one.

## Upgrading PostgreSQL

The fingerprint a migration recorded is compared only under the PostgreSQL
major version that computed it, because a catalogue may render the same schema
differently in another. After a major upgrade, `migrate status` says the ledger
is not compared, and the comparison resumes with the next migration. See
[schema-pinning.md](schema-pinning.md).
