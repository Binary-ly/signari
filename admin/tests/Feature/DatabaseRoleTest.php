<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * The suite must run as the role the console runs as in production.
 *
 * Every boundary assertion in this suite -- tenant scoping, the console's
 * inability to write schema core, secrets absent from the read model -- passes
 * vacuously under a superuser, because a superuser bypasses row-level security
 * and every GRANT. The suite ran that way on the machine that wrote it for long
 * enough that eighteen tests had quietly come to depend on it: they found their
 * fixtures only because RLS was not being applied.
 */
class DatabaseRoleTest extends TestCase
{
    public function test_the_suite_does_not_run_as_a_superuser(): void
    {
        $row = DB::selectOne(
            'SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user'
        );

        $this->assertFalse((bool) $row->rolsuper,
            "the console suite is connected as superuser {$row->role}; point DB_USERNAME at signari_admin");
        $this->assertFalse((bool) $row->rolbypassrls,
            "the console suite is connected as {$row->role}, which bypasses row-level security");
    }

    /** ADR-004: the console reads core only through core_v1 and writes it only via the Admin API. */
    public function test_the_console_role_has_no_privilege_on_schema_core(): void
    {
        $usage = DB::selectOne("SELECT has_schema_privilege(current_user, 'core', 'USAGE') AS ok")->ok;

        $this->assertFalse((bool) $usage, 'the console role can reach schema core directly');
    }

    /**
     * The console's own tables belong to the console's own role.
     *
     * Running `php artisan migrate` as a superuser leaves admin.* owned by that
     * superuser, and the console then cannot write its own users or sessions --
     * which looks like a console bug rather than a deployment one.
     */
    public function test_the_console_owns_its_own_tables(): void
    {
        $foreign = DB::select(
            "SELECT tablename, tableowner FROM pg_tables
             WHERE schemaname = 'admin' AND tableowner <> current_user"
        );

        $this->assertSame([], array_map(fn ($t) => "{$t->tablename} ({$t->tableowner})", $foreign),
            'admin.* tables owned by another role: run the console migrations as signari_admin');
    }
}
