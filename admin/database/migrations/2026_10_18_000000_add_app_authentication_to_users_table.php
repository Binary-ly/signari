<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A second factor for console operators.
 *
 * The console signed in with a password alone, and whoever holds that password
 * can disable clients, end sessions and read every user in the organisation.
 * Filament's app authentication stores the TOTP secret and the recovery codes
 * here, both encrypted under APP_KEY by the model's casts.
 *
 * Text, not string: an encrypted payload, and the recovery codes' in particular,
 * outgrows a varchar(255).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->text('app_authentication_secret')->nullable();
            $table->text('app_authentication_recovery_codes')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['app_authentication_secret', 'app_authentication_recovery_codes']);
        });
    }
};
