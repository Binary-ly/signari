<?php

namespace Tests;

use App\Models\User;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    /**
     * Marks an operator as having set up the second factor the panel requires,
     * so a test about a screen reaches the screen rather than the set-up page.
     * ConsoleHardeningTest covers an operator who has not.
     */
    protected function enrol(User $user): User
    {
        $user->app_authentication_secret = 'JBSWY3DPEHPK3PXP';

        return $user;
    }
}
