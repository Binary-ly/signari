<?php

namespace App\Console\Commands;

use App\Models\EngineUser;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Throwable;

/**
 * Exercises the read model the way the admin UI will, and asserts the write
 * guards actually fire. Cheap to run, and it catches the case where someone
 * "fixes" the model by removing a guard.
 */
class ReadModelSmoke extends Command
{
    protected $signature = 'idp:read-model-smoke {--org=}';
    protected $description = 'Read core_v1 through Eloquent and assert writes are refused';

    public function handle(): int
    {
        $fail = 0;
        $check = function (string $label, bool $ok, string $detail = '') use (&$fail) {
            $this->line(sprintf('  %s  %s%s', $ok ? '<fg=green>PASS</>' : '<fg=red>FAIL</>',
                $label, $detail ? " <fg=gray>-- {$detail}</>" : ''));
            $ok || $fail++;
        };

        $org = $this->option('org');
        $this->line('');
        $this->line(' <options=bold>Read model over core_v1</>');

        // No context: must be empty, never "everything".
        $check('no org context yields 0 users (fails closed)',
            EngineUser::count() === 0, 'count='.EngineUser::count());

        if ($org) {
            $rows = DB::transaction(function () use ($org) {
                DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);
                return EngineUser::query()->get();
            });
            $check('org context yields users through Eloquent', $rows->count() > 0, 'count='.$rows->count());

            if ($u = $rows->first()) {
                $check('view columns hydrate onto the model',
                    $u->email !== null && $u->status !== null, "email={$u->email} status={$u->status}");
                $check('derived accessors work',
                    is_bool($u->needsRehash()) && is_bool($u->canGoPasswordless()),
                    'passkeys='.$u->passkey_count);
            }
        }

        // The guards. Each must throw, not silently no-op.
        foreach (['save', 'delete', 'create'] as $op) {
            $threw = false;
            try {
                $op === 'create' ? EngineUser::create(['email' => 'x@y.z'])
                                 : (new EngineUser())->{$op}();
            } catch (RuntimeException $e) {
                $threw = str_contains($e->getMessage(), 'ADR-004');
            } catch (Throwable $e) {
                $threw = false;
            }
            $check("EngineUser::{$op}() is refused at the model", $threw);
        }

        $this->line('');
        $this->line($fail ? "  <fg=red;options=bold>{$fail} check(s) FAILED</>" : '  <fg=green;options=bold>read model ok</>');
        return $fail ? self::FAILURE : self::SUCCESS;
    }
}
