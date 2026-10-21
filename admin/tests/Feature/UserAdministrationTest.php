<?php

namespace Tests\Feature;

use App\Filament\Resources\EngineUsers\Pages\ListEngineUsers;
use App\Models\EngineUser;
use App\Models\User;
use Filament\Actions\Testing\TestAction;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Livewire\Livewire;
use Tests\Concerns\SeedsEngineState;
use Tests\TestCase;

/**
 * The console's user-administration actions.
 *
 * These exist because until now an operator could not create a user at all --
 * three read-only screens and one toggle. Every write still goes through the
 * engine's Admin API, because the console has no privilege on schema core and
 * because password hashing must use the engine's Argon2 parameters.
 */
class UserAdministrationTest extends TestCase
{
    use SeedsEngineState;

    private ?User $operator = null;

    private string $orgId = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->orgId = $this->plantOrganisation();

        $this->operator = new User;
        $this->operator->name = 'Operator';
        $this->operator->email = 'op-'.Str::random(8).'@example.test';
        $this->operator->password = bcrypt('irrelevant');
        $this->operator->org_id = $this->orgId;
        $this->operator->save();
    }

    protected function tearDown(): void
    {
        $this->operator?->delete();
        $this->removePlantedEngineState();
        parent::tearDown();
    }

    /**
     * The organisation must come from the OPERATOR's record, never the form.
     * A tenant selector the caller can set is not a tenant boundary.
     */
    public function test_creating_a_user_sends_the_operators_own_org(): void
    {
        Http::fake(['*/admin/users' => Http::response(['id' => 'new-uuid', 'config_version' => 9], 201)]);
        $this->actingAs($this->operator);

        Livewire::test(ListEngineUsers::class)
            ->callAction(TestAction::make('createUser')->table(), data: [
                'email' => 'created@example.test', 'username' => null, 'password' => null,
            ])
            ->assertHasNoActionErrors();

        Http::assertSent(function (Request $r) {
            return $r->method() === 'POST'
                && str_ends_with($r->url(), '/admin/users')
                && $r->data()['org_id'] === $this->orgId
                // A blank password must be OMITTED, not sent as "" -- an empty
                // string would be a password nobody chose.
                && ! array_key_exists('password', $r->data());
        });
    }

    /**
     * Deactivation must report how many sessions were ended. Saying only
     * "deactivated" leaves an operator unsure whether the person is still signed
     * in somewhere -- which, in most identity systems, they are.
     */
    public function test_deactivation_reports_sessions_ended(): void
    {
        $user = $this->plantedUser();
        // The version read comes first: deactivating a user is a conditional
        // write, so the console asks the engine where the configuration is
        // before saying where it should stay. See EngineAdminApi.
        Http::fake([
            '*/admin/config-version' => Http::response(['config_version' => 9], 200),
            '*/admin/users/*' => Http::response(
                ['id' => $user->id, 'sessions_ended' => 3, 'config_version' => 10], 200
            ),
        ]);
        $this->actingAs($this->operator);

        DB::transaction(function () use ($user) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            // The success title, not any toast: the refusal path notifies too.
            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('toggleActive')->table($user))
                ->assertNotified(__('User deactivated'));
        });

        // The planted user is active, so the action must ask for inactive.
        Http::assertSent(fn (Request $r) => $r->method() === 'PATCH'
            && ($r->data()['active'] ?? null) === false);
    }

    /** A refused write must say so, not show a success toast over a failure. */
    public function test_a_refused_creation_is_reported(): void
    {
        Http::fake(['*/admin/users' => Http::response(
            ['error' => 'already_exists', 'detail' => 'that email is taken'], 409
        )]);
        $this->actingAs($this->operator);

        Livewire::test(ListEngineUsers::class)
            ->callAction(TestAction::make('createUser')->table(), data: ['email' => 'dupe@example.test'])
            // The refusal's own title: any toast would also match the success
            // path, and a misconfigured client fails with a toast too.
            ->assertNotified(__('User not created'));
    }

    /**
     * Removing a sign-in method offers what the engine lists, sends the one
     * chosen -- a passkey by its id -- and sends it conditionally, as every
     * other write here is. The engine ends the sessions and tells the holder.
     */
    public function test_removing_a_sign_in_method_is_conditional_and_names_it(): void
    {
        $user = $this->plantedUser();
        Http::fake(function (Request $r) {
            if (str_ends_with($r->url(), '/admin/config-version')) {
                return Http::response(['config_version' => 9], 200);
            }
            if ($r->method() === 'GET') {
                return Http::response(['factors' => [
                    ['type' => 'totp', 'confirmed' => true],
                    ['type' => 'webauthn', 'id' => 'pk-1', 'label' => 'Laptop', 'confirmed' => true],
                ], 'recovery_codes_unused' => 4], 200);
            }

            return Http::response(['removed' => 1, 'sessions_ended' => 2, 'config_version' => 10], 200);
        });
        $this->actingAs($this->operator);

        DB::transaction(function () use ($user) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('removeFactor')->table($user), data: ['factor' => 'webauthn:pk-1'])
                ->assertHasNoActionErrors()
                ->assertNotified(__('Sign-in method removed'));
        });

        Http::assertSent(fn (Request $r) => $r->method() === 'DELETE'
            && str_ends_with($r->url(), "/admin/users/{$user->id}/factors/webauthn/pk-1")
            && $r->header('If-Match') === ['"9"']);
    }

    /** A removal the engine refuses says so, not a success over a failure. */
    public function test_a_refused_removal_is_reported(): void
    {
        $user = $this->plantedUser();
        Http::fake(function (Request $r) {
            if (str_ends_with($r->url(), '/admin/config-version')) {
                return Http::response(['config_version' => 9], 200);
            }
            if ($r->method() === 'GET') {
                return Http::response(['factors' => [['type' => 'totp', 'confirmed' => true]]], 200);
            }

            return Http::response(['error' => 'factor_not_found'], 404);
        });
        $this->actingAs($this->operator);

        DB::transaction(function () use ($user) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('removeFactor')->table($user), data: ['factor' => 'totp'])
                ->assertNotified(__('Nothing was removed'));
        });
    }

    /**
     * A passkey link is sent conditionally, as every other write here is, and
     * the console is told when it ends and nothing more: the token is in the
     * person's email alone.
     */
    public function test_a_passkey_link_is_sent_conditionally(): void
    {
        $user = $this->plantedUser();
        Http::fake(function (Request $r) {
            if (str_ends_with($r->url(), '/admin/config-version')) {
                return Http::response(['config_version' => 9], 200);
            }

            return Http::response(['user_id' => 'u', 'link_id' => 'l-1',
                'expires_at' => '2026-10-22T18:00:00Z', 'config_version' => 10], 200);
        });
        $this->actingAs($this->operator);

        DB::transaction(function () use ($user) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('sendPasskeyLink')->table($user))
                ->assertHasNoActionErrors()
                ->assertNotified(__('Passkey link on its way'));
        });

        Http::assertSent(fn (Request $r) => $r->method() === 'POST'
            && str_ends_with($r->url(), "/admin/users/{$user->id}/passkey-link")
            && $r->header('If-Match') === ['"9"']
            && $r->data() === ['ttl_seconds' => 0]);
    }

    /** One the engine refuses, an account with no address, says why. */
    public function test_a_refused_passkey_link_is_reported(): void
    {
        $user = $this->plantedUser();
        Http::fake(function (Request $r) {
            if (str_ends_with($r->url(), '/admin/config-version')) {
                return Http::response(['config_version' => 9], 200);
            }

            return Http::response(['error' => 'cannot_send_link',
                'detail' => 'the account has no email address to send the link to'], 409);
        });
        $this->actingAs($this->operator);

        DB::transaction(function () use ($user) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('sendPasskeyLink')->table($user))
                ->assertNotified(__('No link was sent'));
        });
    }

    private function plantedUser(): EngineUser
    {
        $userId = $this->plantUser($this->orgId);

        return DB::transaction(function () use ($userId) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);

            return EngineUser::query()->findOrFail($userId);
        });
    }
}
