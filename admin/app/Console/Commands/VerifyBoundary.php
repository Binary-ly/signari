<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Proves the engine/admin boundary from the ADMIN side.
 *
 * The Go tests assert that signari_admin is denied on core. That is the same codebase
 * asserting its own design. This asserts it from the consumer -- the runtime that
 * would actually benefit from cheating -- which is the side that matters.
 *
 * Three properties of that boundary:
 *
 *   ADR-004  the admin has NO privilege on schema core; the boundary is a GRANT,
 *            not a code-review rule, so "just this one direct read" is impossible
 *            rather than merely discouraged.
 *
 *   ADR-006  core_v1 views run with the OWNER's privileges, and that owner is
 *            subject to FORCE ROW LEVEL SECURITY. So the admin sees ZERO rows
 *            unless it sets the org context in-transaction. That is a feature:
 *            the admin is under the same database-enforced tenant isolation as
 *            the engine.
 *
 *   SET LOCAL, never SET. On a pooled connection SET persists and leaks the
 *            previous tenant's context into the next request. This is the most
 *            common RLS bug in pooled applications, so it is asserted here.
 */
class VerifyBoundary extends Command
{
    protected $signature = 'signari:verify-boundary {--org= : organisation UUID to scope to}';

    protected $description = 'Assert the engine/admin database boundary holds';

    public function handle(): int
    {
        $failures = 0;
        $check = function (string $label, bool $ok, string $detail = '') use (&$failures) {
            $this->line(sprintf('  %s  %s%s',
                $ok ? '<fg=green>PASS</>' : '<fg=red>FAIL</>',
                $label,
                $detail !== '' ? " <fg=gray>-- {$detail}</>" : ''));
            if (! $ok) {
                $failures++;
            }
        };

        $this->line('');
        $this->line(' <options=bold>Engine/admin boundary</>');

        // Confirm which role we actually connected as. A misconfigured .env that
        // connects as the superuser would make every check below pass vacuously,
        // which is the failure mode this whole file exists to prevent.
        $role = DB::selectOne('SELECT current_user AS r')->r;
        $check('connected as signari_admin, not a superuser', $role === 'signari_admin', "current_user={$role}");

        // ADR-004: no reach into core at all.
        $denied = false;
        $why = '';
        try {
            DB::select('SELECT count(*) FROM core.users');
        } catch (Throwable $e) {
            $denied = str_contains($e->getMessage(), 'permission denied');
            $why = $denied ? 'permission denied for schema core' : substr($e->getMessage(), 0, 60);
        }
        $check('ADR-004: direct read of core.users is DENIED', $denied, $why);

        // The same must hold for writes, and for a table the admin might plausibly
        // believe it owns. A read-only leak would be bad; a write leak is worse.
        $writeDenied = false;
        try {
            DB::statement("UPDATE core.clients SET enabled = false WHERE client_id = '__nonexistent__'");
        } catch (Throwable $e) {
            $writeDenied = str_contains($e->getMessage(), 'permission denied');
        }
        $check('ADR-004: direct WRITE to core.clients is DENIED', $writeDenied);

        // ADR-006: views are reachable, but yield nothing without org context.
        $rowsNoContext = null;
        try {
            $rowsNoContext = (int) DB::selectOne('SELECT count(*) AS c FROM core_v1.users')->c;
        } catch (Throwable $e) {
            $this->line('  <fg=red>FAIL</>  core_v1.users is not readable at all: '.substr($e->getMessage(), 0, 80));
            $failures++;
        }
        if ($rowsNoContext !== null) {
            $check('ADR-006: core_v1.users returns 0 rows with no org context (fails closed)',
                $rowsNoContext === 0, "rows={$rowsNoContext}");
        }

        $org = $this->option('org');
        if (! $org) {
            $this->line('');
            $this->line('  <fg=yellow>skipped</>  org-scoped read (pass --org=<uuid> to check it)');
        } else {
            // SET LOCAL inside a transaction. The context must evaporate at commit.
            $scoped = DB::transaction(function () use ($org) {
                // NOT "SET LOCAL app.org_id = ?" -- PostgreSQL does not accept bind
                // parameters in SET, and interpolating the value into the string
                // would make the org id an injection vector on the one call whose
                // whole job is tenant isolation.
                //
                // set_config(name, value, is_local) is the parameterisable form, and
                // is_local = true gives exactly SET LOCAL semantics: it reverts at
                // commit and cannot leak to the next transaction on a pooled
                // connection.
                DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

                return (int) DB::selectOne('SELECT count(*) AS c FROM core_v1.users')->c;
            });
            $check('ADR-006: core_v1.users returns rows WITH org context', $scoped > 0, "rows={$scoped}");

            // And the critical one: the context must NOT survive the transaction,
            // or a pooled connection hands the next request the previous tenant.
            $after = (int) DB::selectOne('SELECT count(*) AS c FROM core_v1.users')->c;
            $check('SET LOCAL does not leak past the transaction (pooling safety)',
                $after === 0, "rows_after_commit={$after}");
        }

        $this->line('');
        if ($failures > 0) {
            $this->line("  <fg=red;options=bold>{$failures} boundary check(s) FAILED</>");
            return self::FAILURE;
        }
        $this->line('  <fg=green;options=bold>boundary holds</>');
        return self::SUCCESS;
    }
}
