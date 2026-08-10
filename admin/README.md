# Laravel admin

The Laravel skeleton and `app/Console/Commands/VerifyBoundary.php` are committed.
## Status: boundary verified, read model and users table built

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


## Read model

Filament v4.12.6 installed. `App\Models\EngineUser` points Eloquent at
`core_v1.users` -- the versioned read-only view -- because ADR-004 leaves the admin
no access to `core` at all. The view is a contract the engine holds stable while
the physical tables move underneath it, which is the same mechanism that makes its
zero-downtime migrations possible.

`php artisan idp:read-model-smoke --org=<uuid>` asserts 7 properties, including
that every write path throws rather than reaching the database. Postgres would
refuse them regardless, but a raw PDO permission error surfacing from inside
Filament is a poor way to learn an architectural rule -- the exception names
ADR-004 and says writes go through the engine Admin API.

`App\Http\Middleware\ScopeToOrganisation` sets the org context per request:

- `set_config('app.org_id', ?, true)` -- NOT `SET LOCAL app.org_id = ?`, which
  PostgreSQL rejects (no bind parameters in SET) and whose obvious workaround,
  string interpolation, would make the org id an injection vector on the one call
  whose entire purpose is tenant isolation.
- The whole request is wrapped in a transaction, because `is_local = true` reverts
  at commit -- with no transaction there is nothing for it to be local to, and it
  leaks to the next request on that pooled connection.
- The org comes from the authenticated admin's own record, never a query string or
  header. A tenant selector an attacker can set is not a tenant boundary.
- No organisation means no context, which means zero rows. A missing scope must
  never widen access.


## Users resource

`App\Filament\Resources\EngineUsers` -- read-only, deliberately. There is no
create, edit or delete page, and `canCreate`/`canEdit`/`canDelete` all return
false, so Filament generates no routes, row actions or bulk actions for operations
the database would refuse. A write form here would be a button that cannot work.

The columns are chosen for what an operator actually needs to see:


Filters: status, "imported hash not yet upgraded", and "ready for passwordless".

The empty state says *"an empty table means no organisation context, not an empty
database"* -- because under ADR-006 that is by far the more likely cause, and an
operator who does not know that will go looking in the wrong place.
