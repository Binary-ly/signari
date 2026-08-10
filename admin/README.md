# Laravel admin

The Laravel skeleton and `app/Console/Commands/VerifyBoundary.php` are committed.
## Status: boundary verified, UI not built

Laravel 13.24 installed. `php artisan idp:verify-boundary` passes 6/6 against a
migrated database.

**Network note for this machine:** `composer install` fails here because
`github.com` and `codeload.github.com` (where every dist archive is served) time
out, while `api.github.com` -- an adjacent IP in the same /24 -- answers in 1.5s.
That is per-destination filtering upstream, not DNS and not composer. Install
through a VPN, or on a host without the filtering, then copy `vendor/` across.

## Configuration

Point it at the engine's database AS THE ADMIN ROLE -- never as the superuser, or
the checks pass vacuously:

    DB_CONNECTION=pgsql
    DB_HOST=127.0.0.1
    DB_DATABASE=idp
    DB_USERNAME=idp_admin
    DB_PASSWORD=...        # set on the role out-of-band

    php artisan idp:verify-boundary --org=<uuid>

## What that command proves

It asserts the boundary from the side that would benefit from cheating:

- **ADR-004** direct read AND write of `core.*` are denied by GRANT, not by convention
- **ADR-006** `core_v1.*` returns zero rows without `SET LOCAL app.org_id`, because the
  view owner is subject to FORCE row-level security -- the admin is under the same
  tenant isolation as the engine
- **pooling safety** the org context does not survive the transaction, so a pooled
  connection cannot hand the next request the previous tenant's scope

It also checks `current_user = idp_admin` first, because connecting as a superuser
would make every other assertion pass for the wrong reason.

## One thing this found

`SET LOCAL app.org_id = ?` does not work: PostgreSQL accepts no bind parameters in
SET. The tempting fix is to interpolate the value into the string, which would turn
the org id into an injection vector on the single call whose entire purpose is
tenant isolation. The correct form is:

    SELECT set_config('app.org_id', ?, true)

parameterisable, with `is_local = true` giving exactly SET LOCAL semantics.
