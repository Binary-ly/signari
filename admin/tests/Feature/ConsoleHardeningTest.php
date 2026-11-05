<?php

namespace Tests\Feature;

use App\Models\User;
use App\Providers\AppServiceProvider;
use Filament\Facades\Filament;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PragmaRX\Google2FA\Google2FA;
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
        foreach (["default-src 'self'", "img-src 'self' data:", "connect-src 'self'",
            "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"] as $directive) {
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

    /*
     * An inline script runs only when it carries the nonce of the response it came
     * in (6.24). script-src had 'unsafe-inline', so a script injected into any
     * screen ran with the operator's session. Every inline script a panel screen
     * writes, Filament's, Livewire's and the console's own, carries this
     * response's nonce, and no two responses share one.
     */
    public function test_an_inline_script_runs_only_with_the_responses_nonce(): void
    {
        $this->enrol($this->operator)->save();
        $nonces = [];
        foreach (['/admin', '/admin/engine-clients'] as $screen) {
            $response = $this->actingAs($this->operator)->get($screen)->assertOk();
            $csp = (string) $response->headers->get('Content-Security-Policy');
            $this->assertStringNotContainsString("'unsafe-inline' 'unsafe-eval'", $csp);
            $this->assertMatchesRegularExpression("/script-src 'self' 'nonce-([A-Za-z0-9]{40})' 'unsafe-eval'/", $csp);
            preg_match("/'nonce-([A-Za-z0-9]{40})'/", $csp, $m);
            $nonces[] = $m[1];

            preg_match_all('/<script\b([^>]*)>/i', $response->getContent(), $tags);
            $inline = array_filter($tags[1], fn (string $attributes): bool => ! str_contains($attributes, 'src='));
            $this->assertNotEmpty($inline, "{$screen} wrote no inline script to check");
            foreach ($inline as $attributes) {
                $this->assertStringContainsString('nonce="'.$m[1].'"', $attributes,
                    "{$screen} wrote an inline script without this response's nonce: <script{$attributes}>");
            }
        }
        $this->assertNotSame($nonces[0], $nonces[1], 'two responses were given the same nonce');
    }

    /*
     * Filament's views that write inline scripts are copied here to give them the
     * nonce. A copy that drifts from the view it replaces would keep an old
     * Filament's markup on every screen, so each must be its original with the
     * nonce added to every script and nothing else: when a Filament upgrade changes
     * an original, this fails until the copy is made again from it.
     */
    public function test_the_copied_filament_views_are_their_originals_with_the_nonce(): void
    {
        $nonce = ' nonce="{{ \Illuminate\Support\Facades\Vite::cspNonce() }}"';
        foreach ([
            'filament-panels/components/layout/base.blade.php' => 'filament/filament/resources/views/components/layout/base.blade.php',
            'filament-panels/livewire/sidebar.blade.php' => 'filament/filament/resources/views/livewire/sidebar.blade.php',
            'filament/assets.blade.php' => 'filament/support/resources/views/assets.blade.php',
        ] as $copy => $original) {
            $ours = file_get_contents(resource_path('views/vendor/'.$copy));
            $theirs = file_get_contents(base_path('vendor/'.$original));
            $this->assertSame($theirs, str_replace($nonce, '', $ours), "{$copy} is no longer {$original} with the nonce added");
            $this->assertSame(substr_count($theirs, '<script'), substr_count($ours, '<script'.$nonce),
                "{$copy} has a script without the nonce");
        }
    }

    /*
     * Behind a proxy that terminates TLS every request reached PHP as plain
     * HTTP, so HSTS was never sent. A proxy named in TRUSTED_PROXIES is
     * believed about the scheme; any other is not.
     */
    public function test_hsts_is_sent_behind_a_trusted_proxy_and_only_a_trusted_one(): void
    {
        try {
            $forwarded = ['X-Forwarded-Proto' => 'https', 'X-Forwarded-Host' => 'console.example.test'];

            $this->assertFalse($this->withHeaders($forwarded)->get('/admin/login')
                ->headers->has('Strict-Transport-Security'),
                'a forwarded https was believed with no proxy trusted');

            config(['app.trusted_proxies' => '127.0.0.1, 10.0.0.0/8']);
            $this->app->getProvider(AppServiceProvider::class)->boot();
            $this->withHeaders($forwarded)->get('/admin/login')
                ->assertHeader('Strict-Transport-Security', 'max-age=31536000');

            // An absolute http URL: a relative one is built from the previous
            // request, which the trusted proxy just made https.
            $this->assertFalse($this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
                ->withHeaders($forwarded)->get('http://localhost/admin/login')
                ->headers->has('Strict-Transport-Security'),
                'a forwarded https from an untrusted address was believed');
        } finally {
            TrustProxies::flushState();
        }
    }

    /*
     * Sessions and remember-me cookies from before enrolment ended with it. They
     * survived: whoever had the password before the second factor was set up
     * kept a console session it was meant to have made impossible.
     */
    public function test_setting_up_the_second_factor_ends_other_sessions_and_remember_cookies(): void
    {
        // The console's own driver; phpunit.xml runs the array driver.
        config(['session.driver' => 'database']);
        $this->operator->setRememberToken('minted-before-the-second-factor');
        $this->operator->saveQuietly();
        $other = 'other-'.Str::random(32);
        DB::table('sessions')->insert([
            'id' => $other, 'user_id' => $this->operator->getKey(), 'ip_address' => '198.51.100.7',
            'user_agent' => 'test', 'payload' => base64_encode('a:0:{}'), 'last_activity' => time(),
        ]);
        $current = session()->getId();
        DB::table('sessions')->insert([
            'id' => $current, 'user_id' => $this->operator->getKey(), 'ip_address' => '127.0.0.1',
            'user_agent' => 'test', 'payload' => base64_encode('a:0:{}'), 'last_activity' => time(),
        ]);

        try {
            $this->operator->saveAppAuthenticationSecret((new Google2FA)->generateSecretKey());

            $this->assertFalse(DB::table('sessions')->where('id', $other)->exists(),
                'a session from before the second factor survived its enrolment');
            $this->assertTrue(DB::table('sessions')->where('id', $current)->exists(),
                'the session that set the factor up was ended with the others');
            $this->assertNotSame('minted-before-the-second-factor', $this->operator->fresh()->getRememberToken(),
                'remember-me cookies from before the second factor still sign in');
        } finally {
            DB::table('sessions')->whereIn('id', [$other, $current])->delete();
        }
    }
}
