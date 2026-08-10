<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Binds each console operator to one organisation.
 *
 * ScopeToOrganisation reads this column and feeds it to set_config('app.org_id'),
 * which is what the FORCE ROW LEVEL SECURITY policies on `core` match against.
 * Without the column the middleware finds null, fails closed, and every screen in
 * the console renders zero rows -- correct behaviour, useless product.
 *
 * Deliberately NOT a foreign key to core.organizations. It could not be one: the
 * admin role has no privilege on schema core (ADR-004), and a FK requires
 * REFERENCES on the target. Granting it to satisfy an integrity constraint would
 * punch through the boundary the constraint is decorating -- so the guarantee is
 * left where it belongs, in the RLS policy. A stale org_id yields no rows, not
 * another tenant's rows, which is the safe direction to fail.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Nullable: an operator can exist before being assigned. They simply
            // see nothing until they are.
            $table->uuid('org_id')->nullable()->after('id');
            $table->index('org_id');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex(['org_id']);
            $table->dropColumn('org_id');
        });
    }
};
