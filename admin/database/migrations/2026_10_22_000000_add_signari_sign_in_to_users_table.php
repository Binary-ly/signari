<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Operators who sign in through Signari, and the break-glass account (6.06).
 *
 * signari_user_id is the person in core.users an operator signs in as. Their
 * console row is made at their first sign-in and found by this id afterwards,
 * never by address: an address in two systems is not proof it is one person.
 *
 * break_glass marks a local account that signs in with a password and a second
 * factor here, for when Signari itself is what is broken. Once Signari sign-in
 * is configured, it is the only kind a password admits, and it writes with the
 * deployment's environment token, which the engine records as break-glass on
 * every change.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->uuid('signari_user_id')->nullable()->unique();
            $table->boolean('break_glass')->default(false);
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['signari_user_id', 'break_glass']);
        });
    }
};
