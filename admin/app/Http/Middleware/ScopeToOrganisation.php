<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sets the PostgreSQL org context for the duration of one request.
 *
 * This is ADR-006 made operational. `core_v1.*` views run with the owner's
 * privileges, and that owner (idp_engine) is subject to FORCE ROW LEVEL SECURITY,
 * so without this middleware every admin query returns zero rows. That is the
 * design: the admin is under the same database-enforced tenant isolation as the
 * engine, rather than being trusted to remember a WHERE clause.
 *
 * Three things here are load-bearing.
 *
 * 1. set_config(), NOT "SET LOCAL app.org_id = ?".
 *    PostgreSQL accepts no bind parameters in SET. The obvious workaround --
 *    interpolating the value into the statement -- would make the org id an SQL
 *    injection vector on the single call whose entire purpose is tenant
 *    isolation. set_config(name, value, is_local) is the parameterisable form.
 *
 * 2. is_local = true, and therefore a TRANSACTION.
 *    A local setting reverts at commit. Without the surrounding transaction there
 *    is nothing for it to be local TO, so it would behave like a session-level
 *    SET and leak to whichever request next picks up that pooled connection.
 *    That is the most common row-level-security bug in pooled applications.
 *
 * 3. Fail closed.
 *    An authenticated admin with no organisation selected gets NO context, which
 *    means zero rows -- not "all rows". A missing scope must never widen access.
 */
class ScopeToOrganisation
{
    public function handle(Request $request, Closure $next): Response
    {
        $orgId = $this->resolveOrganisation($request);

        if ($orgId === null) {
            // No context set. The RLS policies then match nothing, so the admin
            // sees an empty console rather than another tenant's data.
            return $next($request);
        }

        // The transaction is not incidental -- see (2) above. Everything the
        // request does against core_v1 must happen inside it, which is why the
        // whole pipeline is wrapped rather than just the SET.
        return DB::transaction(function () use ($orgId, $request, $next) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $orgId]);

            return $next($request);
        });
    }

    /**
     * The organisation this request is scoped to.
     *
     * Deliberately NOT taken from a query string or header: a tenant selector an
     * attacker can set is not a tenant boundary. It comes from the authenticated
     * admin's own record, and Filament's panel tenancy narrows within that.
     */
    private function resolveOrganisation(Request $request): ?string
    {
        $user = $request->user();

        if ($user === null) {
            return null;
        }

        $orgId = $user->org_id ?? null;

        // A UUID or nothing. Anything else is a bug or an attack, and either way
        // must not reach set_config.
        if (! is_string($orgId) || ! preg_match('/^[0-9a-f-]{36}$/i', $orgId)) {
            return null;
        }

        return $orgId;
    }
}
