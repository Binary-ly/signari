<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\EngineAdminApi;
use App\Services\SignariSignIn;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Signing in to the console through Signari (6.06).
 *
 * The console asks Signari for a second factor and the Admin API's audience,
 * then asks the engine who the token is for, and asks again on every request:
 * a session revoked in Signari ends console access on the next one. A password
 * admits only the break-glass account.
 */
class SignariSignInTest extends TestCase
{
    private const ISSUER = 'https://idp.example.test';

    private const ADMIN = 'http://127.0.0.1:8090';

    private string $person = '';

    private string $org = '';

    /** @var list<User> */
    private array $made = [];

    protected function setUp(): void
    {
        parent::setUp();
        config()->set('services.signari', [
            'issuer' => self::ISSUER, 'client_id' => 'console', 'client_secret' => 'console-secret',
            'redirect' => 'https://console.example.test/signari/callback',
        ]);
        $this->person = (string) Str::uuid();
        $this->org = (string) Str::uuid();
    }

    protected function tearDown(): void
    {
        User::query()->where('signari_user_id', $this->person)->delete();
        foreach ($this->made as $u) {
            $u->delete();
        }
        parent::tearDown();
    }

    /** What the engine's /admin/me answers, changeable mid-test: null is a 401. */
    private ?array $answer = null;

    private bool $faked = false;

    /** The engine: discovery, the token endpoint and /admin/me answering with $me. */
    private function engine(?array $me): void
    {
        $this->answer = $me;
        if ($this->faked) {
            return;
        }
        $this->faked = true;
        Http::fake([
            self::ISSUER.'/.well-known/openid-configuration' => Http::response([
                'issuer' => self::ISSUER,
                'authorization_endpoint' => self::ISSUER.'/authorize',
                'token_endpoint' => self::ISSUER.'/oauth2/token',
                'revocation_endpoint' => self::ISSUER.'/oauth2/revoke',
            ]),
            self::ISSUER.'/oauth2/token' => Http::response([
                'access_token' => 'issued-access', 'refresh_token' => 'issued-refresh',
                'token_type' => 'Bearer', 'expires_in' => 300,
            ]),
            self::ISSUER.'/oauth2/revoke' => Http::response('', 200),
            self::ADMIN.'/admin/me' => fn () => $this->answer === null
                ? Http::response(['error' => 'unauthorized'], 401)
                : Http::response($this->answer),
            self::ADMIN.'/admin/*' => Http::response(['config_version' => 7]),
        ]);
    }

    private function me(): array
    {
        return ['kind' => 'person', 'name' => 'user:'.$this->person, 'org_id' => $this->org,
            'scopes' => ['users:write'], 'expires_at' => null,
            'user' => ['id' => $this->person, 'email' => 'ada@example.test', 'display_name' => 'Ada L']];
    }

    private function signedIn(): User
    {
        $user = new User;
        $user->forceFill(['name' => 'Ada L', 'email' => $this->person.'@signari.invalid', 'password' => Str::random(40),
            'signari_user_id' => $this->person, 'org_id' => $this->org])->save();

        return $user;
    }

    private function kept(int $expiresIn = 300): array
    {
        return [SignariSignIn::SESSION => ['access_token' => encrypt('kept-access'),
            'refresh_token' => encrypt('kept-refresh'), 'expires_at' => time() + $expiresIn]];
    }

    public function test_unconfigured_the_console_signs_in_as_before(): void
    {
        config()->set('services.signari', ['issuer' => null, 'client_id' => null]);
        $this->get('/signari/login')->assertNotFound();
        $this->get('/admin/login')->assertOk()->assertDontSee('Sign in with Signari');
        $local = $this->enrol(new User);
        $local->forceFill(['name' => 'Local', 'email' => 'local-'.Str::random(8).'@example.test',
            'password' => 'irrelevant'])->save();
        $this->made[] = $local;
        $this->actingAs($local)->get('/admin')->assertOk();
    }

    public function test_the_sign_in_asks_for_a_second_factor_and_the_admin_api(): void
    {
        $this->engine($this->me());
        $this->get('/admin/login')->assertOk()->assertSee('Sign in with Signari');

        $location = $this->get('/signari/login')->assertRedirect()->headers->get('Location');
        $this->assertStringStartsWith(self::ISSUER.'/authorize?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $q);
        $this->assertSame('code', $q['response_type']);
        $this->assertSame('console', $q['client_id']);
        $this->assertSame('S256', $q['code_challenge_method']);
        $this->assertSame('2', $q['acr_values']);
        $this->assertSame(self::ISSUER.'/admin', $q['resource']);
        $this->assertSame(session('signari.sign_in_pending.state'), $q['state']);
        $verifier = session('signari.sign_in_pending.verifier');
        $this->assertSame(rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            $q['code_challenge']);
    }

    public function test_a_callback_this_console_did_not_start_is_refused(): void
    {
        $this->engine($this->me());
        $this->get('/signari/login');
        $this->get('/signari/callback?code=c&state=forged')->assertRedirect('/admin/login');
        $this->assertGuest();
        Http::assertNotSent(fn (Request $r) => str_ends_with($r->url(), '/oauth2/token'));
    }

    public function test_a_completed_sign_in_makes_the_person_an_operator_of_their_organisation(): void
    {
        $this->engine($this->me());
        $this->get('/signari/login');
        $state = session('signari.sign_in_pending.state');
        $verifier = session('signari.sign_in_pending.verifier');

        $this->get('/signari/callback?code=the-code&state='.$state)->assertRedirect('/admin');

        $user = User::query()->where('signari_user_id', $this->person)->firstOrFail();
        $this->assertAuthenticatedAs($user);
        $this->assertSame($this->org, $user->org_id);
        $this->assertFalse($user->break_glass);
        $this->assertStringEndsWith('@signari.invalid', $user->email);
        Http::assertSent(fn (Request $r) => str_ends_with($r->url(), '/oauth2/token')
            && $r['grant_type'] === 'authorization_code' && $r['code'] === 'the-code'
            && $r['code_verifier'] === $verifier);
        Http::assertSent(fn (Request $r) => str_ends_with($r->url(), '/admin/me')
            && $r->header('Authorization') === ['Bearer issued-access']);
    }

    public function test_an_ended_signari_session_ends_console_access_on_the_next_request(): void
    {
        $user = $this->signedIn();
        $this->engine($this->me());
        $this->actingAs($user)->withSession($this->kept())->get('/admin')->assertOk();

        // The engine no longer answers for the token: revoked in Signari.
        $this->engine(null);
        $this->actingAs($user)->withSession($this->kept())->get('/admin')->assertRedirect('/admin/login');
        $this->assertGuest();
    }

    public function test_the_organisation_is_the_one_the_engine_names(): void
    {
        $user = $this->signedIn();
        $moved = (string) Str::uuid();
        $this->engine(['org_id' => $moved] + $this->me());
        $this->actingAs($user)->withSession($this->kept())->get('/admin')->assertOk();
        $this->assertSame($moved, $user->fresh()->org_id);
    }

    public function test_a_password_admits_only_the_break_glass_account(): void
    {
        $this->engine(null);
        // A local account from before Signari sign-in: refused the panel by
        // canAccessPanel, which Authenticate asks before any other check.
        $local = $this->enrol(new User);
        $local->forceFill(['name' => 'Local', 'email' => 'local-'.Str::random(8).'@example.test',
            'password' => 'irrelevant'])->save();
        $this->made[] = $local;
        $this->actingAs($local)->get('/admin')->assertForbidden();

        $glass = $this->enrol(new User);
        $glass->forceFill(['name' => 'Glass', 'email' => 'glass-'.Str::random(8).'@example.test',
            'password' => 'irrelevant', 'break_glass' => true])->save();
        $this->made[] = $glass;
        $this->actingAs($glass)->get('/admin')->assertOk();
    }

    public function test_an_operator_writes_with_their_own_token_and_break_glass_with_the_environments(): void
    {
        $this->engine($this->me());
        $user = $this->signedIn();
        $this->actingAs($user)->withSession($this->kept());
        session()->put($this->kept());
        EngineAdminApi::fromConfig()->asOf(3)->setClientEnabled('app', false);
        Http::assertSent(fn (Request $r) => str_contains($r->url(), '/admin/clients/app')
            && $r->header('Authorization') === ['Bearer kept-access']);

        $glass = new User;
        $glass->forceFill(['name' => 'Glass', 'email' => 'glass-'.Str::random(8).'@example.test',
            'password' => 'irrelevant', 'break_glass' => true])->save();
        $this->made[] = $glass;
        Auth::login($glass);
        EngineAdminApi::fromConfig()->asOf(3)->setClientEnabled('other', false);
        Http::assertSent(fn (Request $r) => str_contains($r->url(), '/admin/clients/other')
            && $r->header('Authorization') === ['Bearer test-suite-token']);

        // An operator whose sign-in is gone writes nothing, rather than with the environment token.
        Auth::login($user);
        session()->forget(SignariSignIn::SESSION);
        $this->expectExceptionMessage('Your Signari sign-in has ended');
        EngineAdminApi::fromConfig();
    }

    public function test_a_screen_is_offered_only_to_the_roles_that_read_it(): void
    {
        $user = $this->signedIn();
        // An app manager: clients and configuration, nobody's people.
        $this->engine(['scopes' => ['clients:read', 'clients:write', 'config:read']] + $this->me());
        $this->actingAs($user)->withSession($this->kept())->get('/admin/engine-clients')->assertOk();
        $this->actingAs($user)->withSession($this->kept())->get('/admin/engine-users')->assertForbidden();

        // A user manager delegated over a group: the people screen reads
        // every person, so it is not theirs.
        $this->engine(['scopes' => ['users:read', 'users:write'],
            'delegated' => ['users:read' => [(string) Str::uuid()]]] + $this->me());
        $this->actingAs($user)->withSession($this->kept())->get('/admin/engine-users')->assertForbidden();
        $this->engine($this->me() + ['delegated' => []]);
        $this->answer['scopes'] = ['users:read', 'users:write'];
        $this->actingAs($user)->withSession($this->kept())->get('/admin/engine-users')->assertOk();
    }

    public function test_a_person_with_no_role_is_not_an_operator(): void
    {
        $this->engine(['scopes' => []] + $this->me());
        $this->get('/signari/login');
        $this->get('/signari/callback?code=c&state='.session('signari.sign_in_pending.state'))
            ->assertRedirect('/admin/login');
        $this->assertGuest();

        // And one whose last role is taken away is signed out.
        $user = $this->signedIn();
        $this->actingAs($user)->withSession($this->kept())->get('/admin')->assertRedirect('/admin/login');
        $this->assertGuest();
    }

    public function test_a_token_about_to_expire_is_refreshed(): void
    {
        $this->engine($this->me());
        session()->put($this->kept(10));
        $this->assertSame('issued-access', app(SignariSignIn::class)->accessToken());
        Http::assertSent(fn (Request $r) => str_ends_with($r->url(), '/oauth2/token')
            && $r['grant_type'] === 'refresh_token' && $r['refresh_token'] === 'kept-refresh');
    }

    public function test_signing_out_gives_up_the_refresh_token(): void
    {
        $this->engine($this->me());
        $user = $this->signedIn();
        $this->actingAs($user);
        session()->put($this->kept());
        Auth::logout();
        Http::assertSent(fn (Request $r) => str_ends_with($r->url(), '/oauth2/revoke')
            && $r['token'] === 'kept-refresh' && $r['token_type_hint'] === 'refresh_token');
        $this->assertNull(session(SignariSignIn::SESSION));
    }

    public function test_operator_create_makes_only_the_break_glass_account(): void
    {
        $email = 'glass-'.Str::random(8).'@example.test';
        $this->artisan('signari:operator-create', ['email' => $email])->assertFailed();
        $this->assertFalse(User::query()->where('email', $email)->exists());

        $this->artisan('signari:operator-create', ['email' => $email, '--break-glass' => true])->assertSuccessful();
        $glass = User::query()->where('email', $email)->firstOrFail();
        $this->made[] = $glass;
        $this->assertTrue($glass->break_glass);
        $this->assertNull($glass->signari_user_id);
    }
}
