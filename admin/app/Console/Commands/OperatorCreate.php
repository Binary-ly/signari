<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

/**
 * Makes the console's break-glass account (6.06).
 *
 * Everyone else signs in through Signari, and their console account is made at
 * their first sign-in, so there is nothing to create for them here. This is the
 * one account that does not depend on Signari: a password shown once and a
 * second factor enrolled at its first sign-in, writing with the deployment's
 * environment token, which the engine records as break-glass on every change.
 * Keep it for when Signari is what is broken.
 */
class OperatorCreate extends Command
{
    protected $signature = 'signari:operator-create {email} {--break-glass} {--name=} {--org=}';

    protected $description = 'Create the console\'s break-glass account; other operators sign in through Signari';

    public function handle(): int
    {
        if (! $this->option('break-glass')) {
            $this->error('Operators sign in through Signari, and their console account is made at their first '.
                'sign-in: give them a role with `signari role grant`. Pass --break-glass to make the account '.
                'that works when Signari is down.');

            return self::FAILURE;
        }
        $email = (string) $this->argument('email');
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $this->error("{$email} is not an address.");

            return self::FAILURE;
        }
        $org = $this->option('org');
        if ($org !== null && ! preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $org)) {
            $this->error('--org is the organisation\'s uuid, lower case.');

            return self::FAILURE;
        }
        if (User::query()->where('email', $email)->exists()) {
            $this->error("An operator with the address {$email} exists already.");

            return self::FAILURE;
        }

        $password = Str::password(24);
        $user = new User;
        $user->forceFill([
            'name' => $this->option('name') ?: 'Break-glass',
            'email' => $email,
            'password' => $password,
            'org_id' => $org,
            'break_glass' => true,
        ])->save();

        $this->info("Break-glass account {$email} made.");
        $this->line('Its password, shown this once:');
        $this->line("  {$password}");
        $this->line('Its first sign-in enrols a second factor. It writes with SIGNARI_ADMIN_TOKEN, and every change '.
            'it makes is recorded as break-glass.');

        return self::SUCCESS;
    }
}
