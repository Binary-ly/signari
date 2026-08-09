# Laravel admin (scaffolded, dependencies not installed)

The Laravel skeleton and `app/Console/Commands/VerifyBoundary.php` are committed.
`composer install` cannot complete in the agent's sandbox. Diagnosed:

    repo.packagist.org  (metadata)        200 in ~1s
    api.github.com                        200 in ~1s
    codeload.github.com (dist archives)   HANGS to timeout

Composer resolves all 109 packages and writes the lock file, then stalls on the
first download, because dist archives are served from codeload.github.com. The
same hang occurs from the host, from a container, and with the vendor tree on a
container-local filesystem -- so it is neither a bind-mount speed problem nor a
composer configuration issue.

For contrast, everything else worked from the same environment today: `go get`
(proxy.golang.org), `npm install`, `git clone` from GitLab, and Docker registry
pulls. The restriction is specific to codeload.github.com.

Run it yourself:

    cd admin && composer install

Then point it at the engine's database AS THE ADMIN ROLE -- never as the superuser,
or `idp:verify-boundary` passes vacuously:

    DB_CONNECTION=pgsql
    DB_HOST=127.0.0.1
    DB_PORT=5432
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
