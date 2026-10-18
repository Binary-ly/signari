<?php

namespace Tests\Feature;

use App\Models\User;
use Filament\Facades\Filament;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * The console signed in with a password alone, sent no framing or content
 * policy, and left its session cookie insecure by default. Each of these is a
 * way to reach an identity provider's administration without the operator.
 */
class ConsoleHardeningTest extends TestCase
{
    private ?User $operator = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->operator = new User;
        $this->operator->name = 'Operator';
        $this->operator->email = 'mfa-'.Str::random(8).'@example.test';
        $this->operator->password = bcrypt('irrelevant');
        $this->operator->save();
    }

    protected function tearDown(): void
    {
        $this->operator?->delete();
        parent::tearDown();
    }

    public function test_an_operator_without_a_second_factor_reaches_no_screen(): void
    {
        $setUp = Filament::getPanel('admin')->getSetUpRequiredMultiFactorAuthenticationUrl();
        $this->assertNotEmpty($setUp, 'the panel does not require a second factor');

        foreach (['/admin', '/admin/engine-clients', '/admin/engine-users'] as $screen) {
            $this->actingAs($this->operator)->get($screen)->assertRedirect($setUp);
        }
    }

    public function test_an_enrolled_operator_reaches_the_panel(): void
    {
        $this->enrol($this->operator)->save();

        $this->actingAs($this->operator)->get('/admin')->assertOk();
    }

    public function test_the_second_factor_is_stored_encrypted_and_never_serialised(): void
    {
        $this->enrol($this->operator)->save();

        $raw = $this->operator->getConnection()->table('users')
            ->where('id', $this->operator->id)->value('app_authentication_secret');
        $this->assertNotSame('JBSWY3DPEHPK3PXP', $raw, 'the TOTP secret is stored in plaintext');
        $this->assertArrayNotHasKey('app_authentication_secret', $this->operator->toArray());
    }

    public function test_every_response_carries_the_security_headers(): void
    {
        $response = $this->get('/admin/login')->assertOk();

        $csp = (string) $response->headers->get('Content-Security-Policy');
        foreach (["frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"] as $directive) {
            $this->assertStringContainsString($directive, $csp);
        }
        $response->assertHeader('X-Frame-Options', 'DENY');
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('Referrer-Policy', 'same-origin');
        // Over plain HTTP there is nothing to pin.
        $response->assertHeaderMissing('Strict-Transport-Security');

        $this->get('https://localhost/admin/login')
            ->assertHeader('Strict-Transport-Security', 'max-age=31536000');
    }
}
