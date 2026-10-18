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

    private function plantedUser(): EngineUser
    {
        $userId = $this->plantUser($this->orgId);

        return DB::transaction(function () use ($userId) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);

            return EngineUser::query()->findOrFail($userId);
        });
    }
}
